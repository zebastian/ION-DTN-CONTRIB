/*
	tcpv4session.c:	TCPCLv4 (RFC 9174) session engine.

			The engine proper: the listening socket that accepts
			inbound TCP connections, the on-demand outbound ones
			and their reconnection backoff, the list of live
			sessions, and the two engine threads.

			Each session gets a receiver thread that runs the
			negotiation (tcpv4negotiate.c) and then the message
			loop (tcpv4rx.c); the clock thread drives keepalives,
			timeouts and idle session termination.  Bundle
			transmission (tcpv4tx.c) is done by the caller's
			sender threads.
								*/

#include "tcpv4sessint.h"
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "ion_network.h"

/*	*	*	Session lifecycle	*	*	*	*/

static void freeConn(Tcpv4Conn *conn)
{
	/*	Every bundle still queued or outstanding is reported as a
	 *	failed transmission, so that BP requeues it.  By now the
	 *	session's own threads have been joined and no sender still
	 *	holds it, so nothing else can touch the lists.		*/

	tcpv4TxDrain(conn);

	if (conn->tls != NULL)
	{
		tcpv4TlsClose(conn->tls, conn->cleanClose);
	}

	if (conn->sock != -1)
	{
		closesocket(conn->sock);
	}

	if (conn->rxBuf != NULL)
	{
		MRELEASE(conn->rxBuf);
	}

	if (conn->rxBundle != NULL)
	{
		MRELEASE(conn->rxBundle);
	}

	if (conn->dlvBundle != NULL)
	{
		MRELEASE(conn->dlvBundle);
	}

	if (conn->hasSendMutex)
	{
		pthread_mutex_destroy(&conn->sendMutex);
	}

	if (conn->hasTxMutex)
	{
		pthread_mutex_destroy(&conn->txMutex);
	}

	if (conn->hasTxCond)
	{
		pthread_cond_destroy(&conn->txCond);
	}

	if (conn->hasDlvMutex)
	{
		pthread_mutex_destroy(&conn->dlvMutex);
	}

	if (conn->hasDlvCond)
	{
		pthread_cond_destroy(&conn->dlvCond);
	}

	MRELEASE(conn);
}

/*	Say so when a second established session to the same node appears.
 *	Two nodes that dial each other at the same time get two sessions,
 *	which RFC 9174 neither forbids nor resolves; sender selection
 *	settles on one of them (see findConn) and the other falls idle, but
 *	an operator who is paying for the second connection should be able
 *	to see that it is there.					*/

static void noteDuplicateSession(Tcpv4Conn *conn)
{
	Tcpv4Engine *e = conn->owner;
	Tcpv4Conn   *other;
	int	     duplicate = 0;

	if (!tcpv4NodeIdIsSet(conn->routeNodeId))
	{
		return;
	}

	pthread_mutex_lock(&e->mutex);
	for (other = e->conns; other != NULL; other = other->next)
	{
		if (other == conn || other->failed || other->receiverDone
				|| other->state != TCS_ESTABLISHED)
		{
			continue;
		}

		if (tcpv4NodeIdMatches(other->routeNodeId, conn->routeNodeId))
		{
			duplicate = 1;
			break;
		}
	}

	pthread_mutex_unlock(&e->mutex);

	if (duplicate)
	{
		writeMemoNote("[i] tcpv4cla has more than one session to node",
				conn->routeNodeId);
	}
}

static void *receiverThread(void *parm)
{
	Tcpv4Conn   *conn = parm;
	Tcpv4Engine *e = conn->owner;
	int	     established = (tcpv4Establish(conn) == 0);

	/*	RFC 9174 4.1: the reconnection backoff advances on anything
	 *	that kept a session from being established, and resets only
	 *	on one that was.					*/

	tcpv4DialOutcome(conn, established);

	if (established)
	{
		noteDuplicateSession(conn);
		conn->rx = e->rx.open(e->rx.user);
		if (conn->rx == NULL)
		{
			putErrmsg("tcpv4cla can't open reception context.",
					conn->peerName);
			ionKillMainThread("tcpv4cla");
		}
		else
		{
			/*	The transmit and delivery threads live
			 *	exactly as long as the message loop, and are
			 *	started and joined here so that both are gone
			 *	before the session is declared finished.	*/

			if (pthread_begin(&conn->xmit, NULL, tcpv4XmitThread,
					    conn)
					== 0)
			{
				conn->hasXmit = 1;
			}
			else
			{
				putSysErrmsg("tcpv4cla can't start transmit"
					     " thread",
						conn->peerName);
			}

			if (pthread_begin(&conn->dlv, NULL,
					    tcpv4DeliveryThread, conn)
					== 0)
			{
				conn->hasDlv = 1;
			}
			else
			{
				putSysErrmsg("tcpv4cla can't start delivery"
					     " thread",
						conn->peerName);
			}

			if (conn->hasXmit && conn->hasDlv)
			{
				conn->cleanClose
						= (tcpv4MessageLoop(conn) == 0);
			}

			/*	Shut the socket down before joining, so that
			 *	a transmit thread blocked in a write to a
			 *	peer that has stopped reading comes back.	*/

			tcpv4ConnFail(conn);
			tcpv4TxStop(conn);
			if (conn->hasXmit)
			{
				pthread_join(conn->xmit, NULL);
				conn->hasXmit = 0;
			}

			tcpv4DeliveryStop(conn);
			if (conn->hasDlv)
			{
				pthread_join(conn->dlv, NULL);
				conn->hasDlv = 0;
			}

			e->rx.close(conn->rx);
			conn->rx = NULL;
		}
	}

	/*	The TLS session is torn down in freeConn, once this thread
	 *	has been joined: until then another thread may still be
	 *	writing a SESS_TERM through it.				*/

	tcpv4ConnFail(conn);
	writeMemoNote("[i] tcpv4cla session ended with", conn->peerName);

	pthread_mutex_lock(&e->mutex);
	conn->receiverDone = 1;
	pthread_cond_broadcast(&e->cond);
	pthread_mutex_unlock(&e->mutex);
	writeErrmsgMemos();
	return NULL;
}

/*	Create a session around an already-connected socket and start its
 *	receiver thread.  On success the engine owns the socket.  Called
 *	with e->mutex NOT held.						*/

static Tcpv4Conn *startConn(Tcpv4Engine *e, int sock, int activeRole,
		const char *nodeId, const char *peerName, const char *peerAddr,
		int busy)
{
	Tcpv4Conn *conn;

	conn = MTAKE(sizeof(Tcpv4Conn));
	if (conn == NULL)
	{
		putErrmsg("tcpv4cla: no memory for session.", NULL);
		return NULL;
	}

	memset(conn, 0, sizeof(*conn));
	conn->owner = e;
	conn->sock = sock;
	conn->activeRole = activeRole;
	conn->state = TCS_NEGOTIATING;
	conn->busy = busy;
	conn->segmentMtu = TCPV4_DEFAULT_SEGMENT_MRU;
	conn->transferMtu = TCPV4CLA_BUFSZ;
	istrcpy(conn->peerName, peerName, sizeof(conn->peerName));
	if (peerAddr != NULL)
	{
		istrcpy(conn->peerAddr, peerAddr, sizeof(conn->peerAddr));
	}

	if (nodeId != NULL)
	{
		/*	We dialled this one, so the node it is meant to
		 *	reach comes from the egress plan rather than from
		 *	the wire; until SESS_INIT says otherwise, that is
		 *	also the node it may carry bundles to.		*/

		istrcpy(conn->dialNodeId, nodeId, sizeof(conn->dialNodeId));
		istrcpy(conn->routeNodeId, nodeId, sizeof(conn->routeNodeId));
	}

	pthread_mutex_init(&conn->sendMutex, NULL);
	conn->hasSendMutex = 1;
	pthread_mutex_init(&conn->txMutex, NULL);
	conn->hasTxMutex = 1;
	pthread_cond_init(&conn->txCond, NULL);
	conn->hasTxCond = 1;
	pthread_mutex_init(&conn->dlvMutex, NULL);
	conn->hasDlvMutex = 1;
	pthread_cond_init(&conn->dlvCond, NULL);
	conn->hasDlvCond = 1;

	pthread_mutex_lock(&e->mutex);
	conn->next = e->conns;
	e->conns = conn;
	e->connCount++;
	pthread_mutex_unlock(&e->mutex);

	if (pthread_begin(&conn->receiver, NULL, receiverThread, conn))
	{
		putSysErrmsg("tcpv4cla can't start receiver thread", peerName);
		pthread_mutex_lock(&e->mutex);
		conn->sock = -1; /* Caller closes the socket.		*/
		conn->failed = 1;
		conn->receiverDone = 1;
		pthread_mutex_unlock(&e->mutex);
		return NULL;
	}

	pthread_mutex_lock(&e->mutex);
	conn->hasReceiver = 1;
	pthread_mutex_unlock(&e->mutex);
	return conn;
}

/*	Join and free every session whose receiver thread has exited and
 *	that no sender still holds.  Only the clock thread calls this, so
 *	no other thread ever removes a session from the list.		*/

static void reapConns(Tcpv4Engine *e)
{
	Tcpv4Conn  *dead = NULL;
	Tcpv4Conn  *conn;
	Tcpv4Conn **pp;

	pthread_mutex_lock(&e->mutex);
	pp = &e->conns;
	while (*pp != NULL)
	{
		conn = *pp;
		if (conn->receiverDone && conn->txSenders == 0)
		{
			*pp = conn->next;
			conn->next = dead;
			dead = conn;
			e->connCount--;
			continue;
		}

		pp = &conn->next;
	}

	pthread_mutex_unlock(&e->mutex);

	while (dead != NULL)
	{
		conn = dead;
		dead = conn->next;
		if (conn->hasReceiver)
		{
			pthread_join(conn->receiver, NULL);
		}

		freeConn(conn);
	}
}

/*	*	*	Accept thread	*	*	*	*	*/

/*	How many sessions with this peer address are part way through
 *	negotiation.  Called with e->mutex held.			*/

static int countNegotiating(Tcpv4Engine *e, const char *peerHost)
{
	Tcpv4Conn *conn;
	int	   count = 0;

	if (peerHost == NULL || peerHost[0] == '\0')
	{
		return 0;
	}

	for (conn = e->conns; conn != NULL; conn = conn->next)
	{
		if (conn->failed || conn->receiverDone
				|| conn->state != TCS_NEGOTIATING)
		{
			continue;
		}

		if (strcmp(conn->peerAddr, peerHost) == 0)
		{
			count++;
		}
	}

	return count;
}

static void *acceptThread(void *parm)
{
	Tcpv4Engine	       *e = parm;
	struct pollfd		pfd;
	struct sockaddr_storage peerAddr;
	socklen_t		peerLen;
	char			peerName[TCPV4_MAX_HOST_LEN];
	char			peerHost[TCPV4_MAX_HOST_LEN];
	int			negotiating;
	int			connCount;
	int			busy;
	int			newSock;

	while (e->running)
	{
		pfd.fd = e->listenSock;
		pfd.events = POLLIN;
		pfd.revents = 0;
		if (poll(&pfd, 1, TCPV4_ACCEPT_POLL_MS) <= 0)
		{
			continue; /* Timeout, or interrupted; re-check.	*/
		}

		peerLen = sizeof peerAddr;
		newSock = accept(e->listenSock, (struct sockaddr *) &peerAddr,
				&peerLen);
		if (newSock < 0)
		{
			if (errno == EINTR || errno == ECONNABORTED)
			{
				continue;
			}

			if (e->running)
			{
				putSysErrmsg("tcpv4cla accept() failed", NULL);
				ionKillMainThread("tcpv4cla");
			}

			break;
		}

		if (!e->running)
		{
			closesocket(newSock);
			break;
		}

		{
			char host[NI_MAXHOST];
			char serv[NI_MAXSERV];

			if (getnameinfo((struct sockaddr *) &peerAddr, peerLen,
					    host, sizeof host, serv,
					    sizeof serv,
					    NI_NUMERICHOST | NI_NUMERICSERV)
					== 0)
			{
				isprintf(peerName, sizeof(peerName), "%s:%s",
						host, serv);
				istrcpy(peerHost, host, sizeof(peerHost));
			}
			else
			{
				istrcpy(peerName, "(unknown peer)",
						sizeof(peerName));
				peerHost[0] = '\0';
			}
		}

		/*	RFC 9174 7.10 (denial of service): negotiation is the
		 *	phase an unauthenticated peer can drive, and it can
		 *	be made to last the whole contact timeout, so it is
		 *	rationed per peer address rather than only globally -
		 *	otherwise one address holds every session slot on the
		 *	node and no other peer can get in.  Established
		 *	sessions are not rationed this way, so a legitimate
		 *	peer reconnecting is unaffected.		*/

		pthread_mutex_lock(&e->mutex);
		negotiating = countNegotiating(e, peerHost);
		connCount = e->connCount;
		pthread_mutex_unlock(&e->mutex);

		if (peerHost[0] != '\0'
				&& negotiating >= TCPV4_MAX_PEER_NEGOTIATING)
		{
			writeMemoNote("[?] tcpv4cla refusing a connection,"
				      " too many sessions being negotiated"
				      " with", peerName);
			closesocket(newSock);
			continue;
		}

		/*	Past the session limit the connection is still worth
		 *	a SESS_TERM "Busy" (RFC 9174 6.1), which tells the
		 *	peer to come back rather than leaving it to read a
		 *	bare close as a network fault.  That courtesy costs a
		 *	handshake, so only a bounded few get it.	*/

		busy = (connCount >= e->maxSessions);
		if (connCount >= e->maxSessions + TCPV4_BUSY_SLACK)
		{
			writeMemoNote("[?] tcpv4cla refusing a connection,"
				      " session limit reached:", peerName);
			closesocket(newSock);
			continue;
		}

		if (watchSocket(newSock) < 0)
		{
			closesocket(newSock);
			putErrmsg("tcpv4cla can't watch socket.", NULL);
			continue;
		}

		tcpv4TuneSocket(&e->cfg, newSock);

		if (startConn(e, newSock, 0, NULL, peerName, peerHost, busy)
				== NULL)
		{
			closesocket(newSock);
		}

		sm_TaskYield();
	}

	writeErrmsgMemos();
	writeMemo("[i] tcpv4cla accept thread has ended.");
	return NULL;
}

/*	*	*	Clock thread	*	*	*	*	*/

/*	One second of session upkeep: keepalives (RFC 9174 5.1.1),
 *	reception timeout, negotiation timeout (RFC 9174 4.1) and idle
 *	session termination (RFC 9174 6.2).				*/

static void clockTick(Tcpv4Engine *e)
{
	Tcpv4Tick *tick = e->ticks;
	Tcpv4Conn *conn;
	Tcpv4Dial *dial;
	int	   room = e->maxSessions + TCPV4_BUSY_SLACK;
	int	   count = 0;
	int	   i;

	pthread_mutex_lock(&e->mutex);
	for (dial = e->dials; dial != NULL; dial = dial->next)
	{
		if (dial->secUntilRetry > 0)
		{
			dial->secUntilRetry--;
		}
	}

	for (conn = e->conns; conn != NULL && count < room; conn = conn->next)
	{
		if (conn->failed || conn->receiverDone)
		{
			continue;
		}

		tick[count].conn = conn;
		tick[count].sendKa = 0;
		tick[count].sendTerm = 0;
		tick[count].timedOut = 0;
		conn->secSinceTx++;
		conn->secSinceRx++;
		conn->secSinceData++;

		if (conn->state == TCS_NEGOTIATING)
		{
			conn->secNegotiating++;
			if (conn->secNegotiating > TCPV4_CONTACT_TIMEOUT)
			{
				tick[count].timedOut = 1;
			}

			count++;
			continue;
		}

		if (conn->keepalive > 0)
		{
			if (conn->secSinceTx >= conn->keepalive)
			{
				tick[count].sendKa = 1;
			}

			/*	RFC 9174 5.1.1: silence for longer than the
			 *	negotiated interval ends the session; two
			 *	intervals allows for one lost KEEPALIVE.	*/

			if (conn->secSinceRx > 2 * conn->keepalive)
			{
				tick[count].timedOut = 1;
			}
		}

		if (e->cfg.idleSec > 0 && conn->state == TCS_ESTABLISHED
				&& !conn->termSent && !conn->txActive
				&& !conn->rxActive
				&& conn->secSinceData >= e->cfg.idleSec)
		{
			conn->termSent = 1;
			conn->state = TCS_ENDING;
			tick[count].sendTerm = 1;
		}

		count++;
	}

	pthread_mutex_unlock(&e->mutex);

	/*	Socket writes happen outside the engine lock.  Sessions are
	 *	only ever freed by this thread, so the snapshot stays valid.	*/

	for (i = 0; i < count; i++)
	{
		conn = tick[i].conn;
		if (tick[i].timedOut)
		{
			writeMemoNote("[?] tcpv4cla session timed out with",
					conn->peerName);
			tcpv4ConnFail(conn);
			continue;
		}

		if (tick[i].sendTerm)
		{
			writeMemoNote("[i] tcpv4cla terminating idle session"
				      " with",
					conn->peerName);

			/*	RFC 9174 6.1: no new transfer may begin once
			 *	a SESS_TERM has gone out.		*/

			tcpv4TxStop(conn);
			if (tcpv4SendSessTerm(conn, TMSG_TERM_IDLE_TIMEOUT, 0) < 0)
			{
				tcpv4ConnFail(conn);
			}

			continue;
		}

		if (tick[i].sendKa && tcpv4SendKeepalive(conn) < 0)
		{
			tcpv4ConnFail(conn);
		}
	}

	reapConns(e);
}

static void *clockThread(void *parm)
{
	Tcpv4Engine *e = parm;

	while (e->running)
	{
		snooze(1);
		clockTick(e);
	}

	writeErrmsgMemos();
	writeMemo("[i] tcpv4cla clock thread has ended.");
	return NULL;
}

/*	*	*	Reconnection backoff	*	*	*	*/

static Tcpv4Dial *findDial(Tcpv4Engine *e, const char *nodeId)
{
	Tcpv4Dial *dial;

	for (dial = e->dials; dial != NULL; dial = dial->next)
	{
		if (tcpv4NodeIdMatches(dial->nodeId, nodeId))
		{
			return dial;
		}
	}

	dial = MTAKE(sizeof(Tcpv4Dial));
	if (dial == NULL)
	{
		return NULL;
	}

	memset(dial, 0, sizeof(*dial));
	istrcpy(dial->nodeId, nodeId, sizeof(dial->nodeId));
	dial->interval = 1;
	dial->next = e->dials;
	e->dials = dial;
	return dial;
}

/*	Set the wait before the next attempt on this neighbour and double
 *	the interval for the attempt after that, to the cap of RFC 9174
 *	4.1.  The wait is drawn from the upper half of the interval rather
 *	than being the interval itself: 4.1 asks for randomization, so
 *	that a set of nodes knocked off the air together does not come
 *	back in lockstep and collide again.  Called with e->mutex held.	*/

static void backOff(Tcpv4Engine *e, Tcpv4Dial *dial)
{
	int half = dial->interval / 2;

	dial->secUntilRetry = dial->interval - half
			+ (int) (rand_r(&e->randState) % (unsigned) (half + 1));
	dial->interval <<= 1;
	if (dial->interval > TCPV4_MAX_RECONNECT)
	{
		dial->interval = TCPV4_MAX_RECONNECT;
	}
}

void tcpv4DialOutcome(Tcpv4Conn *conn, int established)
{
	Tcpv4Engine *e = conn->owner;
	Tcpv4Dial   *dial;

	if (!conn->activeRole || !tcpv4NodeIdIsSet(conn->dialNodeId))
	{
		return; /* Not a session this node dialled.		*/
	}

	pthread_mutex_lock(&e->mutex);
	dial = findDial(e, conn->dialNodeId);
	if (dial != NULL)
	{
		if (established)
		{
			/*	RFC 9174 4.1: the delay is reset once a
			 *	session has been established - which is not
			 *	the same as the TCP connection having been
			 *	accepted.  A peer that accepts the connection
			 *	and then rejects the session (a certificate
			 *	it will not trust, a NODE-ID it cannot
			 *	authenticate, a TLS policy it cannot meet) is
			 *	the ordinary misconfiguration, and resetting
			 *	on connect would have this node retry it at
			 *	full speed for as long as it lasted.	*/

			dial->interval = 1;
			dial->secUntilRetry = 0;
		}
		else
		{
			backOff(e, dial);
		}
	}

	pthread_mutex_unlock(&e->mutex);
}

int tcpv4ConnIsBusy(Tcpv4Conn *conn)
{
	return conn->busy;
}

/*	*	*	Engine	*	*	*	*	*	*/

Tcpv4Engine *tcpv4EngineStart(const Tcpv4ClaConfig *cfg,
		const Tcpv4Receiver *rx, const Tcpv4Transmitter *tx)
{
	Tcpv4Engine	 *e;
	IonEndpointSpec	  spec;
	IonNetworkAddress addr;
	char		  ductName[TCPV4_MAX_HOST_LEN + 16];
	char		  addrStr[INET6_ADDR_WITH_PORT_STRLEN];
	int		  on = 1;

	e = MTAKE(sizeof(Tcpv4Engine));
	if (e == NULL)
	{
		putErrmsg("tcpv4cla: no memory for engine.", NULL);
		return NULL;
	}

	memset(e, 0, sizeof(*e));
	e->listenSock = -1;
	e->cfg = *cfg;
	e->rx = *rx;
	e->tx = *tx;
	e->maxSessions = (cfg->maxSessions > 0 ? cfg->maxSessions
					       : TCPV4_DEFAULT_MAX_SESSIONS);
	e->randState = (unsigned int) (getpid() ^ (int) time(NULL));
	pthread_mutex_init(&e->mutex, NULL);
	pthread_cond_init(&e->cond, NULL);

	/*	The clock thread collects what it has to do under the engine
	 *	lock and does it outside, so it needs somewhere to put a
	 *	session's worth of decisions.  It is allocated once here
	 *	rather than taken off that thread's stack, since -L makes
	 *	the session limit an operator's choice.			*/

	e->ticks = MTAKE(sizeof(Tcpv4Tick)
			* (e->maxSessions + TCPV4_BUSY_SLACK));
	if (e->ticks == NULL)
	{
		putErrmsg("tcpv4cla: no memory for session upkeep.", NULL);
		tcpv4EngineStop(e);
		return NULL;
	}

	memset(e->ticks, 0, sizeof(Tcpv4Tick)
			* (e->maxSessions + TCPV4_BUSY_SLACK));

	{
		char nbrBuf[FQN_MAX_LENGTH];

		putFqn(nbrBuf, getOwnFqnn());
		isprintf(e->nodeId, sizeof(e->nodeId), "ipn:%s.0", nbrBuf);
	}

	isprintf(ductName, sizeof(ductName), "%s:%d", cfg->host, cfg->port);
	if (parseNetworkEndpoint(ductName, &spec) < 0
			|| resolveNetworkAddressTCP(&spec, &addr) < 0)
	{
		putErrmsg("tcpv4cla can't resolve its induct address.",
				ductName);
		tcpv4EngineStop(e);
		return NULL;
	}

	if (createNetworkSocket(SOCK_STREAM, &addr, &e->listenSock) < 0)
	{
		putSysErrmsg("tcpv4cla can't create server socket", ductName);
		tcpv4EngineStop(e);
		return NULL;
	}

	oK(setsockopt(e->listenSock, SOL_SOCKET, SO_REUSEADDR, (char *) &on,
			sizeof on));
	if (listen(e->listenSock, 5) < 0)
	{
		putSysErrmsg("tcpv4cla can't listen on server socket",
				ductName);
		tcpv4EngineStop(e);
		return NULL;
	}

	if (cfg->tlsPolicy != TCPV4_TLS_DISABLE)
	{
		e->serverCreds = tcpv4TlsCredsNew(cfg, 1);
		e->clientCreds = tcpv4TlsCredsNew(cfg, 0);
		if (e->serverCreds == NULL || e->clientCreds == NULL)
		{
			tcpv4EngineStop(e);
			return NULL;
		}
	}

	e->running = 1;
	if (pthread_begin(&e->acceptThread, NULL, acceptThread, e))
	{
		putSysErrmsg("tcpv4cla can't start accept thread", NULL);
		e->running = 0;
		tcpv4EngineStop(e);
		return NULL;
	}

	e->hasAcceptThread = 1;
	if (pthread_begin(&e->clockThread, NULL, clockThread, e))
	{
		putSysErrmsg("tcpv4cla can't start clock thread", NULL);
		tcpv4EngineStop(e);
		return NULL;
	}

	e->hasClockThread = 1;
	writeMemoNote("[i] tcpv4cla listening on",
			(char *) formatNetworkAddress(&addr, addrStr,
					sizeof addrStr));
	return e;
}

/*	Open a session to a peer, honouring the reconnection backoff of
 *	RFC 9174 4.1.  Returns 0 when a session attempt was started, -1
 *	otherwise.							*/

int tcpv4OpenSession(Tcpv4Engine *e, const char *nodeId, const char *ductName)
{
	Tcpv4Dial *dial;
	Tcpv4Conn *conn;
	char	   spec[TCPV4_MAX_HOST_LEN + 16];
	char	   host[TCPV4_MAX_HOST_LEN];
	int	   port = e->cfg.port;
	int	   sock = -1;
	int	   result;

	pthread_mutex_lock(&e->mutex);

	/*	A session to this node may have appeared since the caller
	 *	looked - one this node accepted, or one another sender
	 *	dialled.  Two nodes that dial each other at the same time
	 *	will still end up with two sessions, which is legal but
	 *	wasteful; this at least keeps one node from doing it to
	 *	itself.							*/

	for (conn = e->conns; conn != NULL; conn = conn->next)
	{
		if (conn->failed || conn->receiverDone
				|| conn->state == TCS_ENDING)
		{
			continue;
		}

		if (tcpv4NodeIdMatches(conn->dialNodeId, nodeId)
				|| tcpv4NodeIdMatches(conn->routeNodeId,
						  nodeId))
		{
			pthread_mutex_unlock(&e->mutex);
			return 0; /* One is already open or opening.	*/
		}
	}

	dial = findDial(e, nodeId);
	if (dial == NULL)
	{
		pthread_mutex_unlock(&e->mutex);
		return -1;
	}

	if (dial->secUntilRetry > 0)
	{
		pthread_mutex_unlock(&e->mutex);
		return -1; /* Must not retry yet.			*/
	}

	if (e->connCount >= e->maxSessions)
	{
		pthread_mutex_unlock(&e->mutex);
		writeMemo("[?] tcpv4cla not dialling: session limit reached.");
		return -1;
	}

	pthread_mutex_unlock(&e->mutex);

	if (parseTcpv4DuctName(ductName, host, &port) < 0)
	{
		writeMemoNote("[?] tcpv4cla: bad tcpv4 outduct name",
				(char *) ductName);
		return -1;
	}

	istrcpy(spec, ductName, sizeof(spec));
	result = itcp_connect_dualstack(spec, (unsigned short) e->cfg.port,
			&sock, NULL);
	if (result < 1)
	{
		pthread_mutex_lock(&e->mutex);
		backOff(e, dial);
		pthread_mutex_unlock(&e->mutex);
		if (result == 0)
		{
			writeMemoNote("[i] tcpv4cla can't reach peer",
					(char *) ductName);
		}

		return -1;
	}

	if (watchSocket(sock) < 0)
	{
		closesocket(sock);
		putErrmsg("tcpv4cla can't watch socket.", (char *) ductName);
		return -1;
	}

	tcpv4TuneSocket(&e->cfg, sock);

	/*	The backoff is not reset here.  A connection that is
	 *	accepted and then goes no further has not reached a session,
	 *	and it is the receiver thread - which knows how the
	 *	negotiation ended - that reports the outcome.		*/

	/*	The peer name doubles as the TLS server_name, so it is the
	 *	host part of the duct name, not the whole spec.		*/

	if (startConn(e, sock, 1, nodeId, host, NULL, 0) == NULL)
	{
		closesocket(sock);
		return -1;
	}

	return 0;
}

void tcpv4EngineStop(Tcpv4Engine *e)
{
	Tcpv4Conn *conn;
	Tcpv4Conn *next;
	Tcpv4Dial *dial;
	Tcpv4Dial *nextDial;

	if (e == NULL)
	{
		return;
	}

	e->running = 0;
	if (e->hasClockThread)
	{
		pthread_join(e->clockThread, NULL);
		e->hasClockThread = 0;
	}

	if (e->listenSock != -1)
	{
		oK(shutdown(e->listenSock, SHUT_RDWR));
	}

	if (e->hasAcceptThread)
	{
		pthread_join(e->acceptThread, NULL);
		e->hasAcceptThread = 0;
	}

	/*	RFC 9174 6.1: terminate cleanly where we can, then drop the
	 *	connection.  The receiver threads unblock on the shutdown.	*/

	pthread_mutex_lock(&e->mutex);
	for (conn = e->conns; conn != NULL; conn = conn->next)
	{
		conn->termSent = 1;
	}

	pthread_mutex_unlock(&e->mutex);

	/*	Release any sender still waiting for window room, so that
	 *	the sessions can be taken down.				*/

	for (conn = e->conns; conn != NULL; conn = conn->next)
	{
		tcpv4TxStop(conn);
		tcpv4DeliveryStop(conn);
	}

	for (conn = e->conns; conn != NULL; conn = conn->next)
	{
		if (conn->state == TCS_ESTABLISHED && !conn->failed)
		{
			oK(tcpv4SendSessTerm(conn, TMSG_TERM_UNKNOWN, 0));
		}
	}

	for (conn = e->conns; conn != NULL; conn = conn->next)
	{
		tcpv4ConnFail(conn);
	}

	for (conn = e->conns; conn != NULL; conn = next)
	{
		next = conn->next;
		if (conn->hasReceiver)
		{
			pthread_join(conn->receiver, NULL);
		}

		freeConn(conn);
	}

	e->conns = NULL;

	for (dial = e->dials; dial != NULL; dial = nextDial)
	{
		nextDial = dial->next;
		MRELEASE(dial);
	}

	if (e->listenSock != -1)
	{
		closesocket(e->listenSock);
	}

	if (e->ticks != NULL)
	{
		MRELEASE(e->ticks);
	}

	tcpv4TlsCredsFree(e->serverCreds);
	tcpv4TlsCredsFree(e->clientCreds);
	pthread_mutex_destroy(&e->mutex);
	pthread_cond_destroy(&e->cond);
	MRELEASE(e);
}
