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
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "ion_network.h"

/*	*	*	Session lifecycle	*	*	*	*/

static void freeConn(Tcpv4Conn *conn)
{
	if (conn->tls != NULL)
	{
		tcpv4TlsClose(conn->tls, conn->cleanClose);
	}

	if (conn->sock != -1)
	{
		closesocket(conn->sock);
	}

	if (conn->rxBundle != NULL)
	{
		MRELEASE(conn->rxBundle);
	}

	if (conn->hasSendMutex)
	{
		pthread_mutex_destroy(&conn->sendMutex);
	}

	MRELEASE(conn);
}

static void *receiverThread(void *parm)
{
	Tcpv4Conn   *conn = parm;
	Tcpv4Engine *e = conn->owner;

	if (tcpv4Establish(conn) == 0)
	{
		conn->rx = e->rx.open(e->rx.user);
		if (conn->rx == NULL)
		{
			putErrmsg("tcpv4cla can't open reception context.",
					conn->peerName);
			ionKillMainThread("tcpv4cla");
		}
		else
		{
			conn->cleanClose = (tcpv4MessageLoop(conn) == 0);
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
		uvast nodeNbr, const char *peerName)
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
	conn->peerNode = nodeNbr;
	conn->segmentMtu = TCPV4_DEFAULT_SEGMENT_MRU;
	conn->transferMtu = TCPV4CLA_BUFSZ;
	istrcpy(conn->peerName, peerName, sizeof(conn->peerName));
	pthread_mutex_init(&conn->sendMutex, NULL);
	conn->hasSendMutex = 1;

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
		if (conn->receiverDone && !conn->sendBusy)
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

static void *acceptThread(void *parm)
{
	Tcpv4Engine	       *e = parm;
	struct pollfd		pfd;
	struct sockaddr_storage peerAddr;
	socklen_t		peerLen;
	char			peerName[TCPV4_MAX_HOST_LEN];
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

		if (e->connCount >= TCPV4_MAX_SESSIONS)
		{
			writeMemo("[?] tcpv4cla refusing a connection: session"
				  " limit reached.");
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
			}
			else
			{
				istrcpy(peerName, "(unknown peer)",
						sizeof(peerName));
			}
		}

		if (startConn(e, newSock, 0, 0, peerName) == NULL)
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
	Tcpv4Conn *snapshot[TCPV4_MAX_SESSIONS];
	Tcpv4Conn *conn;
	Tcpv4Dial *dial;
	int	   sendKa[TCPV4_MAX_SESSIONS];
	int	   sendTerm[TCPV4_MAX_SESSIONS];
	int	   timedOut[TCPV4_MAX_SESSIONS];
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

	for (conn = e->conns; conn != NULL && count < TCPV4_MAX_SESSIONS;
			conn = conn->next)
	{
		if (conn->failed || conn->receiverDone)
		{
			continue;
		}

		sendKa[count] = 0;
		sendTerm[count] = 0;
		timedOut[count] = 0;
		conn->secSinceTx++;
		conn->secSinceRx++;
		conn->secSinceData++;

		if (conn->state == TCS_NEGOTIATING)
		{
			conn->secNegotiating++;
			if (conn->secNegotiating > TCPV4_CONTACT_TIMEOUT)
			{
				timedOut[count] = 1;
			}

			snapshot[count++] = conn;
			continue;
		}

		if (conn->keepalive > 0)
		{
			if (conn->secSinceTx >= conn->keepalive)
			{
				sendKa[count] = 1;
			}

			/*	RFC 9174 5.1.1: silence for longer than the
			 *	negotiated interval ends the session; two
			 *	intervals allows for one lost KEEPALIVE.	*/

			if (conn->secSinceRx > 2 * conn->keepalive)
			{
				timedOut[count] = 1;
			}
		}

		if (e->cfg.idleSec > 0 && conn->state == TCS_ESTABLISHED
				&& !conn->termSent && !conn->txActive
				&& !conn->rxActive
				&& conn->secSinceData >= e->cfg.idleSec)
		{
			conn->termSent = 1;
			conn->state = TCS_ENDING;
			sendTerm[count] = 1;
		}

		snapshot[count++] = conn;
	}

	pthread_mutex_unlock(&e->mutex);

	/*	Socket writes happen outside the engine lock.  Sessions are
	 *	only ever freed by this thread, so the snapshot stays valid.	*/

	for (i = 0; i < count; i++)
	{
		conn = snapshot[i];
		if (timedOut[i])
		{
			writeMemoNote("[?] tcpv4cla session timed out with",
					conn->peerName);
			tcpv4ConnFail(conn);
			continue;
		}

		if (sendTerm[i])
		{
			writeMemoNote("[i] tcpv4cla terminating idle session"
				      " with",
					conn->peerName);
			if (tcpv4SendSessTerm(conn, TMSG_TERM_IDLE_TIMEOUT, 0) < 0)
			{
				tcpv4ConnFail(conn);
			}

			continue;
		}

		if (sendKa[i] && tcpv4SendKeepalive(conn) < 0)
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

static Tcpv4Dial *findDial(Tcpv4Engine *e, uvast nodeNbr)
{
	Tcpv4Dial *dial;

	for (dial = e->dials; dial != NULL; dial = dial->next)
	{
		if (dial->nodeNbr == nodeNbr)
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
	dial->nodeNbr = nodeNbr;
	dial->interval = 1;
	dial->next = e->dials;
	e->dials = dial;
	return dial;
}

/*	*	*	Engine	*	*	*	*	*	*/

Tcpv4Engine *tcpv4EngineStart(const Tcpv4ClaConfig *cfg,
		const Tcpv4Receiver *rx)
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
	pthread_mutex_init(&e->mutex, NULL);
	pthread_cond_init(&e->cond, NULL);

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

int tcpv4OpenSession(Tcpv4Engine *e, uvast nodeNbr, const char *ductName)
{
	Tcpv4Dial *dial;
	char	   spec[TCPV4_MAX_HOST_LEN + 16];
	char	   host[TCPV4_MAX_HOST_LEN];
	int	   port = e->cfg.port;
	int	   sock = -1;
	int	   result;

	pthread_mutex_lock(&e->mutex);
	dial = findDial(e, nodeNbr);
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

	if (e->connCount >= TCPV4_MAX_SESSIONS)
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
		dial->secUntilRetry = dial->interval;
		dial->interval <<= 1;
		if (dial->interval > TCPV4_MAX_RECONNECT)
		{
			dial->interval = TCPV4_MAX_RECONNECT;
		}

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

	pthread_mutex_lock(&e->mutex);
	dial->interval = 1;
	dial->secUntilRetry = 0;
	pthread_mutex_unlock(&e->mutex);

	/*	The peer name doubles as the TLS server_name, so it is the
	 *	host part of the duct name, not the whole spec.		*/

	if (startConn(e, sock, 1, nodeNbr, host) == NULL)
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

	tcpv4TlsCredsFree(e->serverCreds);
	tcpv4TlsCredsFree(e->clientCreds);
	pthread_mutex_destroy(&e->mutex);
	pthread_cond_destroy(&e->cond);
	MRELEASE(e);
}
