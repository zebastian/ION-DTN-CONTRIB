/*
	tcpv4session.c:	TCPCLv4 (RFC 9174) session engine.

			One listening socket accepts inbound TCP connections;
			outbound ones are opened on demand for egress plans.
			Each session gets a receiver thread that runs the
			contact negotiation, the optional TLS handshake, the
			SESS_INIT exchange and then the message loop; a clock
			thread drives keepalives, timeouts and idle session
			termination.  Bundle transmission is done by the
			caller's sender threads, which serialise their writes
			with every other writer on the session.
								*/

#include "tcpv4session.h"
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include "ion_network.h"
#include "tcpv4msg.h"
#include "tcpv4tls.h"

/*	An extension item list has to be buffered before it can be walked;
 *	RFC 9174 4.8 asks extensions to avoid large data lengths, so a
 *	generous cap here is also a defence against a hostile peer.	*/
#define TCPV4_MAX_EXT_LEN	 1024

/*	Bound on concurrently open sessions (RFC 9174 7.10, denial of
 *	service): further inbound connections are closed immediately.	*/
#define TCPV4_MAX_SESSIONS	 64

/*	Accept-loop poll interval; bounds shutdown latency.		*/
#define TCPV4_ACCEPT_POLL_MS	 500

/*	Ceiling on how long a sender waits for a transfer to be fully
 *	acknowledged.  The clock thread normally detects a dead peer much
 *	sooner, but a session with KEEPALIVEs disabled has no such timer,
 *	so no sender is left blocked indefinitely.			*/
#define TCPV4_XFER_TIMEOUT	 300

/*	TCPCL session states (the subset the engine acts on; RFC 9174 3.3
 *	names more, but they collapse to these for our purposes).	*/
#define TCS_NEGOTIATING		 0 /* Contact/TLS/SESS_INIT in progress.	*/
#define TCS_ESTABLISHED		 1 /* SESS_INIT exchanged both ways.	*/
#define TCS_ENDING		 2 /* SESS_TERM sent or received.	*/

typedef struct Tcpv4Conn
{
	struct Tcpv4Conn *next;
	Tcpv4Engine	 *owner;
	int		  sock;
	int		  activeRole;  /* 1 = we opened the connection.	*/
	Tcpv4TlsConn	 *tls;	       /* NULL when TLS was not enabled.*/
	int		  state;       /* TCS_*.			*/
	int		  failed;
	int		  sendBusy;    /* A sender owns the transmit side.*/
	int		  receiverDone;
	int		  hasReceiver;
	int		  cleanClose; /* Session ended by SESS_TERM exchange.*/
	pthread_t	  receiver;

	char  peerName[TCPV4_MAX_HOST_LEN]; /* Duct name / peer address.	*/
	uvast peerNode;			    /* From the peer's node ID.	*/
	char  peerNodeId[TCPV4_MAX_NODEID_LEN];
	int   peerAuthenticated;

	/*	Negotiated session parameters (RFC 9174 4.7).		*/
	int	 keepalive;   /* min of the two proposals, seconds.	*/
	uint64_t segmentMtu;  /* = peer's Segment MRU.			*/
	uint64_t transferMtu; /* = peer's Transfer MRU.			*/

	/*	Transmission: one transfer in flight per session (RFC 9174
	 *	5.2.2 forbids interleaving within a session).		*/
	pthread_mutex_t sendMutex; /* Serialises every socket write.	*/
	int		hasSendMutex;
	uint64_t	nextTxId;
	uint64_t	txId;
	uint64_t	txAcked;   /* Cumulative XFER_ACK length.	*/
	int		txActive;
	int		txRefused; /* Refusal reason + 1; 0 = none.	*/

	/*	Reception, touched only by this session's receiver thread
	 *	(plus rxActive, which the clock thread reads).		*/
	void	      *rx;	 /* Caller's per-session context.	*/
	unsigned char *rxBundle;
	int	       rxCap;
	int	       rxLen;
	uint64_t       rxId;
	int	       rxActive;
	int	       rxRefused; /* Draining a refused transfer.	*/

	/*	Second counters maintained by the clock thread.		*/
	int secSinceTx;	  /* Since any message was sent.		*/
	int secSinceRx;	  /* Since any message was received.		*/
	int secSinceData; /* Since any non-KEEPALIVE message either way.	*/
	int secNegotiating;
	int termSent;
} Tcpv4Conn;

/*	Per-neighbour reconnection backoff (RFC 9174 4.1).		*/
typedef struct Tcpv4Dial
{
	struct Tcpv4Dial *next;
	uvast		  nodeNbr;
	int		  interval;	/* Current backoff, seconds.	*/
	int		  secUntilRetry;
} Tcpv4Dial;

struct Tcpv4Engine
{
	int	       listenSock;
	Tcpv4ClaConfig cfg;
	char	       nodeId[TCPV4_MAX_NODEID_LEN];
	Tcpv4Receiver  rx;

	Tcpv4TlsCreds *serverCreds; /* TLS server role (passive entity).	*/
	Tcpv4TlsCreds *clientCreds; /* TLS client role (active entity).	*/

	pthread_t	acceptThread;
	pthread_t	clockThread;
	int		hasAcceptThread;
	int		hasClockThread;
	pthread_mutex_t mutex;
	pthread_cond_t	cond;
	int		running;

	Tcpv4Conn *conns;
	int	   connCount;
	Tcpv4Dial *dials;
};

/*	*	*	Low-level session I/O	*	*	*	*/

/*	Receive exactly len octets.  Returns len, 0 if the peer closed the
 *	connection, or -1 on failure.  Only the receiver thread reads.	*/

static int connRecv(Tcpv4Conn *conn, void *into, int len)
{
	char *cursor = (char *) into;
	int   got = 0;

	if (conn->tls != NULL)
	{
		while (got < len)
		{
			int n = tcpv4TlsRecv(conn->tls, cursor + got, len - got);

			if (n <= 0)
			{
				return n;
			}

			got += n;
		}

		return got;
	}

	return itcp_recv(&conn->sock, cursor, len);
}

/*	Send len octets as one indivisible unit.  RFC 9174 5.2.4 notes that
 *	a TCPCL message cannot be cut short or preempted by another, so
 *	every writer takes sendMutex for the whole message.  Returns 0 on
 *	success, -1 on failure.						*/

static int connSendLocked(Tcpv4Conn *conn, const void *data, int len)
{
	if (conn->tls != NULL)
	{
		return tcpv4TlsSend(conn->tls, data, len) == len ? 0 : -1;
	}

	return itcp_send(&conn->sock, (char *) data, len) == len ? 0 : -1;
}

static int connSend(Tcpv4Conn *conn, const void *data, int len)
{
	int result;

	pthread_mutex_lock(&conn->sendMutex);
	result = connSendLocked(conn, data, len);
	pthread_mutex_unlock(&conn->sendMutex);
	if (result == 0)
	{
		conn->secSinceTx = 0;
	}

	return result;
}

/*	Send a message header and its payload as one unit.  Handing the two
 *	to the kernel (or to TLS) separately is what makes a TCPCL sender
 *	pay Nagle's small-write penalty on every segment: the header goes
 *	out alone and the payload then waits for its acknowledgment.  A
 *	single writev - or, under TLS, a single corked record - keeps the
 *	segment in one segment-sized write.  Caller holds sendMutex.	*/

static int connSendSegment(Tcpv4Conn *conn, const void *hdr, int hdrLen,
		const void *data, int dataLen)
{
	struct iovec  iov[2];
	int	      iovCount;
	const char   *cursor;
	size_t	      remaining;

	if (conn->tls != NULL)
	{
		int result;

		tcpv4TlsCork(conn->tls);
		result = (tcpv4TlsSend(conn->tls, hdr, hdrLen) == hdrLen
					&& (dataLen == 0
							|| tcpv4TlsSend(conn->tls,
									   data,
									   dataLen)
									== dataLen))
				? 0
				: -1;
		if (tcpv4TlsUncork(conn->tls) < 0)
		{
			result = -1;
		}

		return result;
	}

	iov[0].iov_base = (void *) hdr;
	iov[0].iov_len = hdrLen;
	iov[1].iov_base = (void *) data;
	iov[1].iov_len = dataLen;
	iovCount = (dataLen > 0 ? 2 : 1);
	remaining = (size_t) hdrLen + (size_t) dataLen;

	for (;;)
	{
		ssize_t sent = writev(conn->sock, iov, iovCount);

		if (sent < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}

			return -1;
		}

		remaining -= (size_t) sent;
		if (remaining == 0)
		{
			return 0;
		}

		/*	A partial write: drop the octets already sent and
		 *	go round again.					*/

		while (sent > 0 && (size_t) sent >= iov[0].iov_len)
		{
			sent -= iov[0].iov_len;
			iov[0] = iov[1];
			iovCount--;
			if (iovCount == 0)
			{
				return 0;
			}
		}

		cursor = (const char *) iov[0].iov_base;
		iov[0].iov_base = (void *) (cursor + sent);
		iov[0].iov_len -= (size_t) sent;
	}
}

/*	Settings every TCPCL socket wants: TCP_NODELAY, because a TCPCL
 *	sender alternates a small header with a large payload and Nagle
 *	would hold each header until the previous write was acknowledged,
 *	and the operator's socket buffer sizes when they asked for them.	*/

static void tuneSocket(const Tcpv4ClaConfig *cfg, int sock)
{
	int on = 1;

	oK(setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof on));

	if (cfg->rcvBufSize > 0)
	{
		int size = cfg->rcvBufSize;

		oK(setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *) &size,
				sizeof size));
	}

	if (cfg->sndBufSize > 0)
	{
		int size = cfg->sndBufSize;

		oK(setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *) &size,
				sizeof size));
	}
}

/*	Mark a session dead and wake everybody waiting on it.  The socket is
 *	shut down rather than closed so that a blocked reader returns while
 *	the descriptor stays valid until the session is reaped.		*/

static void failConn(Tcpv4Conn *conn)
{
	Tcpv4Engine *e = conn->owner;

	pthread_mutex_lock(&e->mutex);
	conn->failed = 1;
	pthread_cond_broadcast(&e->cond);
	pthread_mutex_unlock(&e->mutex);
	if (conn->sock != -1)
	{
		oK(shutdown(conn->sock, SHUT_RDWR));
	}
}

/*	*	*	Message transmission	*	*	*	*/

static int sendSessInit(Tcpv4Conn *conn)
{
	Tcpv4Engine  *e = conn->owner;
	Tcpv4SessInit init;
	uint8_t	      buf[64 + TCPV4_MAX_NODEID_LEN];
	int	      len;

	memset(&init, 0, sizeof(init));
	init.keepalive = (uint16_t) e->cfg.keepalive;
	init.segmentMru = (uint64_t) e->cfg.segmentMru;
	init.transferMru = (uint64_t) e->cfg.transferMru;
	init.nodeId = (const uint8_t *) e->nodeId;
	init.nodeIdLen = (uint16_t) strlen(e->nodeId);
	len = tcpv4MsgEncodeSessInit(buf, sizeof(buf), &init);
	if (len < 0)
	{
		return -1;
	}

	return connSend(conn, buf, len);
}

static int sendKeepalive(Tcpv4Conn *conn)
{
	uint8_t buf[1];
	int	len = tcpv4MsgEncodeKeepalive(buf, sizeof(buf));

	return len < 0 ? -1 : connSend(conn, buf, len);
}

static int sendSessTerm(Tcpv4Conn *conn, uint8_t reason, int reply)
{
	Tcpv4SessTerm term;
	uint8_t	      buf[3];
	int	      len;

	memset(&term, 0, sizeof(term));
	term.flags = reply ? TMSG_TERM_FLAG_REPLY : 0;
	term.reason = reason;
	len = tcpv4MsgEncodeSessTerm(buf, sizeof(buf), &term);
	if (len < 0)
	{
		return -1;
	}

	writeMemoNote("[i] tcpv4cla sending SESS_TERM to", conn->peerName);
	return connSend(conn, buf, len);
}

static int sendMsgReject(Tcpv4Conn *conn, uint8_t reason, uint8_t rejectedType)
{
	Tcpv4MsgReject rej;
	uint8_t	       buf[3];
	int	       len;

	memset(&rej, 0, sizeof(rej));
	rej.reason = reason;
	rej.rejectedType = rejectedType;
	len = tcpv4MsgEncodeMsgReject(buf, sizeof(buf), &rej);
	if (len < 0)
	{
		return -1;
	}

	writeMemoNote("[?] tcpv4cla sending MSG_REJECT to", conn->peerName);
	return connSend(conn, buf, len);
}

static int sendXferAck(Tcpv4Conn *conn, uint8_t flags, uint64_t transferId,
		uint64_t ackLength)
{
	Tcpv4XferAck ack;
	uint8_t	     buf[18];
	int	     len;

	memset(&ack, 0, sizeof(ack));
	ack.flags = flags; /* RFC 9174 5.2.3: echo the segment's flags.	*/
	ack.transferId = transferId;
	ack.ackLength = ackLength;
	len = tcpv4MsgEncodeXferAck(buf, sizeof(buf), &ack);
	return len < 0 ? -1 : connSend(conn, buf, len);
}

static int sendXferRefuse(Tcpv4Conn *conn, uint8_t reason, uint64_t transferId)
{
	Tcpv4XferRefuse refuse;
	uint8_t		buf[10];
	int		len;

	memset(&refuse, 0, sizeof(refuse));
	refuse.reason = reason;
	refuse.transferId = transferId;
	len = tcpv4MsgEncodeXferRefuse(buf, sizeof(buf), &refuse);
	return len < 0 ? -1 : connSend(conn, buf, len);
}

/*	*	*	Contact and session negotiation	*	*	*/

/*	Exchange contact headers (RFC 9174 4.2, 4.3) and return the
 *	negotiated Enable TLS value in *enableTls.  Returns 0 on success,
 *	-1 when the connection is to be closed.				*/

static int exchangeContact(Tcpv4Conn *conn, int *enableTls)
{
	Tcpv4Engine *e = conn->owner;
	Tcpv4Contact ours;
	Tcpv4Contact peer;
	uint8_t	     buf[TMSG_CONTACT_LEN];
	int	     len;
	int	     canTls = (e->cfg.tlsPolicy != TCPV4_TLS_DISABLE);

	memset(&ours, 0, sizeof(ours));
	ours.version = TMSG_VERSION;
	ours.flags = canTls ? TMSG_CONTACT_CAN_TLS : 0;
	len = tcpv4MsgEncodeContact(buf, sizeof(buf), &ours);
	if (len < 0)
	{
		return -1;
	}

	/*	RFC 9174 4.1: the active entity sends first; the passive
	 *	entity replies only after a Contact Header arrives, so that
	 *	it commits no resources to an unknown peer.		*/

	if (conn->activeRole)
	{
		if (connSend(conn, buf, len) < 0)
		{
			return -1;
		}
	}

	if (connRecv(conn, buf, TMSG_CONTACT_LEN) != TMSG_CONTACT_LEN)
	{
		writeMemoNote("[i] tcpv4cla got no contact header from",
				conn->peerName);
		return -1;
	}

	if (tcpv4MsgDecodeContact(buf, TMSG_CONTACT_LEN, &peer) <= 0)
	{
		/*	RFC 9174 6.1: on a bad magic string, close the TCP
		 *	connection without sending SESS_TERM.		*/

		writeMemoNote("[?] tcpv4cla got a bad contact header from",
				conn->peerName);
		return -1;
	}

	if (!conn->activeRole)
	{
		len = tcpv4MsgEncodeContact(buf, sizeof(buf), &ours);
		if (len < 0 || connSend(conn, buf, len) < 0)
		{
			return -1;
		}
	}

	if (peer.version != TMSG_VERSION)
	{
		if (conn->activeRole)
		{
			/*	RFC 9174 4.3: a lower version from the
			 *	passive entity closes the connection.	*/

			writeMemoNote("[?] tcpv4cla peer speaks another TCPCL"
				      " version",
					conn->peerName);
		}
		else
		{
			oK(sendSessTerm(conn, TMSG_TERM_VERSION_MISMATCH, 0));
		}

		return -1;
	}

	/*	RFC 9174 4.3: Enable TLS is the logical AND of the two
	 *	CAN_TLS flags, then local policy is applied.		*/

	*enableTls = canTls && (peer.flags & TMSG_CONTACT_CAN_TLS);
	if (!*enableTls && e->cfg.tlsPolicy == TCPV4_TLS_REQUIRE)
	{
		writeMemoNote("[?] tcpv4cla requires TLS but peer cannot",
				conn->peerName);
		oK(sendSessTerm(conn, TMSG_TERM_CONTACT_FAILURE, 0));
		return -1;
	}

	return 0;
}

/*	Parse "ipn:<node>[.<service>]" into a node number, or 0.		*/

static uvast nodeNbrFromNodeId(const char *nodeId)
{
	uvast node = 0;

	if (nodeId != NULL && strncmp(nodeId, "ipn:", 4) == 0)
	{
		oK(sscanf(nodeId + 4, UVAST_FIELDSPEC, &node));
	}

	return node;
}

/*	Apply the peer's SESS_INIT: negotiate the session parameters
 *	(RFC 9174 4.7) and adopt the peer's node ID (RFC 9174 4.6).
 *	Returns 0 on success, -1 when the session is unacceptable.	*/

static int applySessInit(Tcpv4Conn *conn, const Tcpv4SessInit *peer)
{
	Tcpv4Engine *e = conn->owner;
	uvast	     peerNode;
	size_t	     off = 0;
	Tcpv4ExtItem item;
	int	     rc;

	if (peer->segmentMru == 0 || peer->transferMru == 0)
	{
		writeMemoNote("[?] tcpv4cla got an unusable MRU from",
				conn->peerName);
		return -1;
	}

	/*	RFC 9174 4.8: an unknown session extension item marked
	 *	CRITICAL terminates the session with "Contact Failure".	*/

	while ((rc = tcpv4MsgNextExtItem(peer->sessExt, peer->sessExtLen, &off,
				&item))
			== 1)
	{
		if (item.flags & TMSG_EXT_CRITICAL)
		{
			writeMemoNote("[?] tcpv4cla got a critical session"
				      " extension it cannot handle from",
					conn->peerName);
			return -1;
		}
	}

	if (rc < 0)
	{
		writeMemoNote("[?] tcpv4cla got a malformed session extension"
			      " list from",
				conn->peerName);
		return -1;
	}

	pthread_mutex_lock(&e->mutex);
	conn->segmentMtu = peer->segmentMru;
	conn->transferMtu = peer->transferMru;
	conn->keepalive = (peer->keepalive < e->cfg.keepalive
					? peer->keepalive
					: e->cfg.keepalive);
	if (peer->nodeIdLen > 0 && peer->nodeIdLen < TCPV4_MAX_NODEID_LEN)
	{
		memcpy(conn->peerNodeId, peer->nodeId, peer->nodeIdLen);
		conn->peerNodeId[peer->nodeIdLen] = '\0';
		peerNode = nodeNbrFromNodeId(conn->peerNodeId);
		if (peerNode != 0)
		{
			/*	RFC 9174 4.6: a session is associated with
			 *	the node ID the peer actually gave, even if
			 *	that is not the one we dialled.		*/

			conn->peerNode = peerNode;
		}
	}

	pthread_mutex_unlock(&e->mutex);
	return 0;
}

/*	Read the peer's SESS_INIT, which RFC 9174 4.6 makes the first
 *	message of the session.  Returns 0 on success, -1 otherwise.	*/

static int recvSessInit(Tcpv4Conn *conn)
{
	Tcpv4SessInit peer;
	uint8_t	     *buf;
	uint8_t	      fixed[21]; /* type, keepalive, 2 MRUs, node ID len.	*/
	uint16_t      nodeIdLen;
	uint32_t      extLen;
	int	      result = -1;
	int	      off;

	if (connRecv(conn, fixed, 1) != 1)
	{
		return -1;
	}

	if (fixed[0] == TMSG_SESS_TERM)
	{
		writeMemoNote("[i] tcpv4cla peer refused the session",
				conn->peerName);
		return -1;
	}

	if (fixed[0] != TMSG_SESS_INIT)
	{
		oK(sendMsgReject(conn, TMSG_REJECT_UNEXPECTED, fixed[0]));
		return -1;
	}

	if (connRecv(conn, fixed + 1, 20) != 20)
	{
		return -1;
	}

	nodeIdLen = (uint16_t) ((fixed[19] << 8) | fixed[20]);
	if (nodeIdLen >= TCPV4_MAX_NODEID_LEN)
	{
		writeMemoNote("[?] tcpv4cla got an oversized node ID from",
				conn->peerName);
		return -1;
	}

	/*	The whole message is buffered so that the codec, not this
	 *	function, does the field parsing.			*/

	buf = MTAKE(sizeof(fixed) + nodeIdLen + 4 + TCPV4_MAX_EXT_LEN);
	if (buf == NULL)
	{
		putErrmsg("tcpv4cla: no memory for SESS_INIT.", NULL);
		return -1;
	}

	memcpy(buf, fixed, sizeof(fixed));
	off = sizeof(fixed);
	if (nodeIdLen > 0)
	{
		if (connRecv(conn, buf + off, nodeIdLen) != nodeIdLen)
		{
			MRELEASE(buf);
			return -1;
		}

		off += nodeIdLen;
	}

	if (connRecv(conn, buf + off, 4) != 4)
	{
		MRELEASE(buf);
		return -1;
	}

	extLen = ((uint32_t) buf[off] << 24) | ((uint32_t) buf[off + 1] << 16)
			| ((uint32_t) buf[off + 2] << 8)
			| (uint32_t) buf[off + 3];
	off += 4;
	if (extLen > TCPV4_MAX_EXT_LEN)
	{
		writeMemoNote("[?] tcpv4cla got an oversized session extension"
			      " list from",
				conn->peerName);
		MRELEASE(buf);
		return -1;
	}

	if (extLen > 0)
	{
		if (connRecv(conn, buf + off, extLen) != (int) extLen)
		{
			MRELEASE(buf);
			return -1;
		}

		off += extLen;
	}

	if (tcpv4MsgDecodeSessInit(buf, off, &peer) == off)
	{
		result = applySessInit(conn, &peer);
	}
	else
	{
		writeMemoNote("[?] tcpv4cla got a malformed SESS_INIT from",
				conn->peerName);
	}

	MRELEASE(buf);
	return result;
}

/*	Run the whole session establishment sequence on a fresh socket.
 *	Returns 0 once the session is established, -1 otherwise.	*/

static int establishSession(Tcpv4Conn *conn)
{
	Tcpv4Engine *e = conn->owner;
	int	     enableTls = 0;

	if (exchangeContact(conn, &enableTls) < 0)
	{
		return -1;
	}

	if (enableTls)
	{
		/*	RFC 9174 4.4.3: the active entity is the TLS
		 *	client, the passive entity the TLS server.	*/

		conn->tls = tcpv4TlsHandshake(&e->cfg,
				conn->activeRole ? e->clientCreds
						 : e->serverCreds,
				conn->sock, conn->activeRole ? 0 : 1,
				conn->peerName);
		if (conn->tls == NULL)
		{
			/*	RFC 9174 4.4.3: on handshake failure both
			 *	entities close the TCP connection; there is
			 *	no session yet to terminate.		*/

			return -1;
		}

		conn->peerAuthenticated = tcpv4TlsPeerAuthenticated(conn->tls);
	}

	/*	RFC 9174 4.4.3 has the active entity send SESS_INIT first;
	 *	both directions are independent, so send ours right away and
	 *	then read the peer's.					*/

	if (sendSessInit(conn) < 0 || recvSessInit(conn) < 0)
	{
		return -1;
	}

	pthread_mutex_lock(&e->mutex);
	conn->state = TCS_ESTABLISHED;
	conn->secSinceRx = 0;
	conn->secSinceTx = 0;
	conn->secSinceData = 0;
	pthread_cond_broadcast(&e->cond);
	pthread_mutex_unlock(&e->mutex);

	{
		char txt[512];

		isprintf(txt, sizeof(txt),
				"[i] tcpv4cla session established with '%s'"
				" (node '%s'%s, keepalive %d s, segment MTU "
				UVAST_FIELDSPEC ").",
				conn->peerName,
				conn->peerNodeId[0] ? conn->peerNodeId
						   : "unknown",
				conn->tls == NULL ? ", no TLS"
						  : (conn->peerAuthenticated
										  ? ", authenticated"
										  : ", unauthenticated"),
				conn->keepalive, (uvast) conn->segmentMtu);
		writeMemo(txt);
	}

	return 0;
}

/*	*	*	Message reception	*	*	*	*/

/*	Grow the reassembly buffer to hold at least want octets.		*/

static int rxReserve(Tcpv4Conn *conn, int want)
{
	unsigned char *bigger;
	int	       cap;

	if (want <= conn->rxCap)
	{
		return 0;
	}

	cap = (conn->rxCap == 0 ? 8192 : conn->rxCap);
	while (cap < want)
	{
		cap <<= 1;
	}

	bigger = MTAKE(cap);
	if (bigger == NULL)
	{
		putErrmsg("tcpv4cla: no memory for transfer reassembly.", NULL);
		return -1;
	}

	if (conn->rxLen > 0)
	{
		memcpy(bigger, conn->rxBundle, conn->rxLen);
	}

	if (conn->rxBundle != NULL)
	{
		MRELEASE(conn->rxBundle);
	}

	conn->rxBundle = bigger;
	conn->rxCap = cap;
	return 0;
}

/*	Read and discard len octets, to stay in sync with the message
 *	stream while a transfer is being refused.			*/

static int drainOctets(Tcpv4Conn *conn, uint64_t len)
{
	unsigned char scratch[4096];

	while (len > 0)
	{
		int chunk = (len > sizeof scratch ? (int) sizeof scratch
						  : (int) len);

		if (connRecv(conn, scratch, chunk) != chunk)
		{
			return -1;
		}

		len -= chunk;
	}

	return 0;
}

/*	Read one XFER_SEGMENT header (whose length varies with the START
 *	flag) into buf and decode it.  Returns 0 on success, -1 on
 *	failure.							*/

static int recvXferSegmentHdr(Tcpv4Conn *conn, uint8_t *buf, size_t cap,
		Tcpv4XferSegment *seg)
{
	uint32_t extLen = 0;
	int	 off;

	buf[0] = TMSG_XFER_SEGMENT;
	if (connRecv(conn, buf + 1, 9) != 9) /* flags + Transfer ID.	*/
	{
		return -1;
	}

	off = 10;
	if (buf[1] & TMSG_FLAG_START)
	{
		if (connRecv(conn, buf + off, 4) != 4)
		{
			return -1;
		}

		extLen = ((uint32_t) buf[off] << 24)
				| ((uint32_t) buf[off + 1] << 16)
				| ((uint32_t) buf[off + 2] << 8)
				| (uint32_t) buf[off + 3];
		off += 4;
		if (extLen > TCPV4_MAX_EXT_LEN)
		{
			writeMemoNote("[?] tcpv4cla got an oversized transfer"
				      " extension list from",
					conn->peerName);
			return -1;
		}

		if (extLen > 0)
		{
			if (connRecv(conn, buf + off, extLen) != (int) extLen)
			{
				return -1;
			}

			off += extLen;
		}
	}

	if (connRecv(conn, buf + off, 8) != 8) /* Data length.		*/
	{
		return -1;
	}

	off += 8;
	if ((size_t) off > cap
			|| tcpv4MsgDecodeXferSegmentHdr(buf, off, seg) != off)
	{
		writeMemoNote("[?] tcpv4cla got a malformed XFER_SEGMENT from",
				conn->peerName);
		return -1;
	}

	return 0;
}

/*	Non-zero when the segment carries a transfer extension item that is
 *	both unknown to us (all of them are) and marked CRITICAL, which
 *	RFC 9174 5.2.5 answers with XFER_REFUSE "Extension Failure".	*/

static int segmentHasCriticalExt(const Tcpv4XferSegment *seg)
{
	Tcpv4ExtItem item;
	size_t	     off = 0;
	int	     rc;

	while ((rc = tcpv4MsgNextExtItem(seg->xferExt, seg->xferExtLen, &off,
				&item))
			== 1)
	{
		if (item.flags & TMSG_EXT_CRITICAL)
		{
			return 1;
		}
	}

	return rc < 0 ? 1 : 0;
}

static int handleXferSegment(Tcpv4Conn *conn)
{
	Tcpv4Engine	*e = conn->owner;
	Tcpv4XferSegment seg;
	uint8_t		 hdr[32 + TCPV4_MAX_EXT_LEN];
	int		 dataLen;

	if (recvXferSegmentHdr(conn, hdr, sizeof(hdr), &seg) < 0)
	{
		return -1;
	}

	/*	RFC 9174 4.6: the peer must honour the Segment MRU we
	 *	advertised.  An oversized segment cannot be drained safely
	 *	(its length is attacker-chosen), so end the session.	*/

	if (seg.dataLength > (uint64_t) e->cfg.segmentMru)
	{
		writeMemoNote("[?] tcpv4cla got a segment larger than the"
			      " advertised Segment MRU from",
				conn->peerName);
		oK(sendSessTerm(conn, TMSG_TERM_RESOURCE_EXHAUSTION, 0));
		return -1;
	}

	dataLen = (int) seg.dataLength;

	if (seg.flags & TMSG_FLAG_START)
	{
		if (conn->rxActive)
		{
			/*	RFC 9174 5.2.2 forbids interleaving
			 *	transfers within one session.		*/

			writeMemoNote("[?] tcpv4cla got interleaved transfers"
				      " from",
					conn->peerName);
			oK(sendMsgReject(conn, TMSG_REJECT_UNEXPECTED,
					TMSG_XFER_SEGMENT));
			return -1;
		}

		pthread_mutex_lock(&e->mutex);
		conn->rxActive = 1;
		pthread_mutex_unlock(&e->mutex);
		conn->rxId = seg.transferId;
		conn->rxLen = 0;
		conn->rxRefused = 0;

		if (conn->state == TCS_ENDING)
		{
			/*	RFC 9174 6.1: no new incoming transfer is
			 *	accepted while the session is Ending.	*/

			conn->rxRefused = 1;
			oK(sendXferRefuse(conn, TMSG_REFUSE_SESS_TERM,
					seg.transferId));
		}
		else if (segmentHasCriticalExt(&seg))
		{
			conn->rxRefused = 1;
			oK(sendXferRefuse(conn, TMSG_REFUSE_EXT_FAILURE,
					seg.transferId));
		}
	}
	else
	{
		if (!conn->rxActive || seg.transferId != conn->rxId)
		{
			writeMemoNote("[?] tcpv4cla got a segment outside any"
				      " transfer from",
					conn->peerName);
			oK(sendMsgReject(conn, TMSG_REJECT_UNEXPECTED,
					TMSG_XFER_SEGMENT));
			return -1;
		}
	}

	/*	RFC 9174 4.6: the whole transfer must fit the Transfer MRU
	 *	we advertised; refuse (and drain) the rest if it does not.	*/

	if (!conn->rxRefused
			&& (uint64_t) conn->rxLen + seg.dataLength
					> (uint64_t) e->cfg.transferMru)
	{
		conn->rxRefused = 1;
		oK(sendXferRefuse(conn, TMSG_REFUSE_NO_RESOURCES,
				seg.transferId));
	}

	if (conn->rxRefused)
	{
		if (drainOctets(conn, seg.dataLength) < 0)
		{
			return -1;
		}
	}
	else
	{
		if (rxReserve(conn, conn->rxLen + dataLen) < 0)
		{
			oK(sendSessTerm(conn, TMSG_TERM_RESOURCE_EXHAUSTION, 0));
			return -1;
		}

		if (dataLen > 0
				&& connRecv(conn, conn->rxBundle + conn->rxLen,
						   dataLen)
						!= dataLen)
		{
			return -1;
		}

		conn->rxLen += dataLen;
	}

	if (seg.flags & TMSG_FLAG_END)
	{
		pthread_mutex_lock(&e->mutex);
		conn->rxActive = 0;
		pthread_mutex_unlock(&e->mutex);

		if (!conn->rxRefused)
		{
			/*	RFC 9174 5.2.3: acknowledge only once the
			 *	segment has been fully processed, which for
			 *	the last segment means delivered to BP.	*/

			if (e->rx.deliver(conn->rx, conn->rxBundle,
					    conn->rxLen)
					< 0)
			{
				return -1;
			}
		}
	}

	if (!conn->rxRefused)
	{
		if (sendXferAck(conn, seg.flags, seg.transferId,
				    (uint64_t) conn->rxLen)
				< 0)
		{
			return -1;
		}
	}

	return 0;
}

static int handleXferAck(Tcpv4Conn *conn)
{
	Tcpv4Engine *e = conn->owner;
	Tcpv4XferAck ack;
	uint8_t	     buf[18];
	int	     known;

	buf[0] = TMSG_XFER_ACK;
	if (connRecv(conn, buf + 1, 17) != 17)
	{
		return -1;
	}

	if (tcpv4MsgDecodeXferAck(buf, 18, &ack) != 18)
	{
		return -1;
	}

	pthread_mutex_lock(&e->mutex);
	known = (conn->txActive && ack.transferId == conn->txId);
	if (known)
	{
		conn->txAcked = ack.ackLength;
		pthread_cond_broadcast(&e->cond);
	}

	pthread_mutex_unlock(&e->mutex);

	if (!known)
	{
		/*	RFC 9174 5.1.2 names an XFER_ACK with an unknown
		 *	Transfer ID as a "Message Unexpected" case; it does
		 *	not require closing the session.		*/

		oK(sendMsgReject(conn, TMSG_REJECT_UNEXPECTED, TMSG_XFER_ACK));
	}

	return 0;
}

static int handleXferRefuse(Tcpv4Conn *conn)
{
	Tcpv4Engine    *e = conn->owner;
	Tcpv4XferRefuse refuse;
	uint8_t		buf[10];
	int		known;

	buf[0] = TMSG_XFER_REFUSE;
	if (connRecv(conn, buf + 1, 9) != 9)
	{
		return -1;
	}

	if (tcpv4MsgDecodeXferRefuse(buf, 10, &refuse) != 10)
	{
		return -1;
	}

	pthread_mutex_lock(&e->mutex);
	known = (conn->txActive && refuse.transferId == conn->txId);
	if (known)
	{
		conn->txRefused = refuse.reason + 1;
		pthread_cond_broadcast(&e->cond);
	}

	pthread_mutex_unlock(&e->mutex);

	if (known)
	{
		writeMemoNote("[i] tcpv4cla transfer refused by",
				conn->peerName);
	}
	else
	{
		oK(sendMsgReject(conn, TMSG_REJECT_UNEXPECTED,
				TMSG_XFER_REFUSE));
	}

	return 0;
}

/*	Returns 1 when the session is to be closed cleanly, 0 to keep
 *	reading, -1 on failure.						*/

static int handleSessTerm(Tcpv4Conn *conn)
{
	Tcpv4Engine  *e = conn->owner;
	Tcpv4SessTerm term;
	uint8_t	      buf[3];
	int	      replyNeeded;

	buf[0] = TMSG_SESS_TERM;
	if (connRecv(conn, buf + 1, 2) != 2)
	{
		return -1;
	}

	if (tcpv4MsgDecodeSessTerm(buf, 3, &term) != 3)
	{
		return -1;
	}

	pthread_mutex_lock(&e->mutex);
	replyNeeded = !(term.flags & TMSG_TERM_FLAG_REPLY) && !conn->termSent;
	conn->state = TCS_ENDING;
	conn->termSent = 1;
	pthread_cond_broadcast(&e->cond);
	pthread_mutex_unlock(&e->mutex);

	if (replyNeeded)
	{
		/*	RFC 9174 6.1: the acknowledging SESS_TERM repeats
		 *	the content of the message being acknowledged, with
		 *	the REPLY flag set.				*/

		oK(sendSessTerm(conn, term.reason, 1));

		/*	Stay in the loop: the peer may still finish an
		 *	in-progress transfer before it closes.		*/

		return 0;
	}

	return 1; /* Our own termination was acknowledged.		*/
}

/*	The message loop of an established session.  Returns 0 on a clean
 *	end, -1 on failure.						*/

static int messageLoop(Tcpv4Conn *conn)
{
	Tcpv4Engine *e = conn->owner;
	uint8_t	     type;
	int	     result;

	for (;;)
	{
		result = connRecv(conn, &type, 1);
		if (result != 1)
		{
			/*	0 is the peer closing; RFC 9174 6.1 makes
			 *	a close during a transfer a failure of that
			 *	transfer, which the sender learns from the
			 *	session going away.			*/

			return result == 0 && conn->state == TCS_ENDING ? 0
									: -1;
		}

		pthread_mutex_lock(&e->mutex);
		conn->secSinceRx = 0;
		if (type != TMSG_KEEPALIVE)
		{
			conn->secSinceData = 0;
		}

		pthread_mutex_unlock(&e->mutex);

		switch (type)
		{
		case TMSG_XFER_SEGMENT:
			if (handleXferSegment(conn) < 0)
			{
				return -1;
			}

			break;

		case TMSG_XFER_ACK:
			if (handleXferAck(conn) < 0)
			{
				return -1;
			}

			break;

		case TMSG_XFER_REFUSE:
			if (handleXferRefuse(conn) < 0)
			{
				return -1;
			}

			break;

		case TMSG_KEEPALIVE:
			break;

		case TMSG_SESS_TERM:
			result = handleSessTerm(conn);
			if (result != 0)
			{
				return result < 0 ? -1 : 0;
			}

			break;

		case TMSG_SESS_INIT:
			/*	RFC 9174 5.1.2: a SESS_INIT after the
			 *	session is established is "Message
			 *	Unexpected".				*/

			oK(sendMsgReject(conn, TMSG_REJECT_UNEXPECTED, type));
			return -1;

		default:
			/*	RFC 9174 5.1.2: an unknown message type is
			 *	rejected and the connection closed.	*/

			oK(sendMsgReject(conn, TMSG_REJECT_TYPE_UNKNOWN, type));
			return -1;
		}
	}
}

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

	if (establishSession(conn) == 0)
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
			conn->cleanClose = (messageLoop(conn) == 0);
			e->rx.close(conn->rx);
			conn->rx = NULL;
		}
	}

	/*	The TLS session is torn down in freeConn, once this thread
	 *	has been joined: until then another thread may still be
	 *	writing a SESS_TERM through it.				*/

	failConn(conn);
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

		tuneSocket(&e->cfg, newSock);

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
			failConn(conn);
			continue;
		}

		if (sendTerm[i])
		{
			writeMemoNote("[i] tcpv4cla terminating idle session"
				      " with",
					conn->peerName);
			if (sendSessTerm(conn, TMSG_TERM_IDLE_TIMEOUT, 0) < 0)
			{
				failConn(conn);
			}

			continue;
		}

		if (sendKa[i] && sendKeepalive(conn) < 0)
		{
			failConn(conn);
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

static int engineConnect(Tcpv4Engine *e, uvast nodeNbr, const char *ductName)
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

	tuneSocket(&e->cfg, sock);

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

/*	Claim the transmit side of an established session to nodeNbr.
 *	*exists reports whether any session to that node is alive, so the
 *	caller can wait for one that is still negotiating instead of
 *	opening a second connection.  Called with e->mutex held.	*/

static Tcpv4Conn *claimConn(Tcpv4Engine *e, uvast nodeNbr, int *exists)
{
	Tcpv4Conn *conn;

	*exists = 0;
	for (conn = e->conns; conn != NULL; conn = conn->next)
	{
		if (conn->failed || conn->receiverDone
				|| conn->peerNode != nodeNbr)
		{
			continue;
		}

		if (conn->state == TCS_ENDING)
		{
			continue; /* RFC 9174 6.1: no new transfers.	*/
		}

		*exists = 1;
		if (conn->state != TCS_ESTABLISHED || conn->sendBusy)
		{
			continue;
		}

		conn->sendBusy = 1;
		return conn;
	}

	return NULL;
}

/*	Send one bundle as a single TCPCL transfer, segmented to the peer's
 *	Segment MTU, then wait for it to be acknowledged in full.	*/

static int doSend(Tcpv4Conn *conn, const unsigned char *bundle, int len)
{
	Tcpv4Engine	*e = conn->owner;
	Tcpv4XferSegment seg;
	uint8_t		 hdr[32];
	struct timespec	 deadline;
	int		 hdrLen;
	int		 off = 0;
	int		 result = 0;

	if ((uint64_t) len > conn->transferMtu)
	{
		writeMemoNote("[?] tcpv4cla: bundle exceeds the peer's"
			      " Transfer MRU;",
				conn->peerName);
		return -1;
	}

	pthread_mutex_lock(&e->mutex);
	conn->txId = conn->nextTxId++;
	conn->txAcked = 0;
	conn->txRefused = 0;
	conn->txActive = 1;
	conn->secSinceData = 0;
	pthread_mutex_unlock(&e->mutex);

	/*	RFC 9174 5.2.3 recommends sending segments without waiting
	 *	for each acknowledgment, so the whole transfer is written
	 *	before the cumulative acknowledgment is awaited.	*/

	do
	{
		int chunk = len - off;

		if ((uint64_t) chunk > conn->segmentMtu)
		{
			chunk = (int) conn->segmentMtu;
		}

		memset(&seg, 0, sizeof(seg));
		seg.flags = (off == 0 ? TMSG_FLAG_START : 0);
		if (off + chunk == len)
		{
			seg.flags |= TMSG_FLAG_END;
		}

		seg.transferId = conn->txId;
		seg.dataLength = (uint64_t) chunk;
		hdrLen = tcpv4MsgEncodeXferSegmentHdr(hdr, sizeof(hdr), &seg);
		if (hdrLen < 0)
		{
			result = -1;
			break;
		}

		/*	RFC 9174 5.2.4: a message cannot be preempted part
		 *	way through, so header and data go out under one
		 *	hold of the send mutex.				*/

		pthread_mutex_lock(&conn->sendMutex);
		if (connSendSegment(conn, hdr, hdrLen, bundle + off, chunk) < 0)
		{
			result = -1;
		}

		pthread_mutex_unlock(&conn->sendMutex);
		if (result < 0)
		{
			break;
		}

		conn->secSinceTx = 0;
		off += chunk;
	} while (off < len);

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += TCPV4_XFER_TIMEOUT;
	pthread_mutex_lock(&e->mutex);
	while (result == 0 && !conn->failed && conn->txRefused == 0
			&& conn->txAcked < (uint64_t) len)
	{
		if (pthread_cond_timedwait(&e->cond, &e->mutex, &deadline)
				== ETIMEDOUT)
		{
			writeMemoNote("[?] tcpv4cla timed out awaiting"
				      " XFER_ACK from",
					conn->peerName);
			break;
		}
	}

	if (conn->failed || conn->txRefused != 0
			|| conn->txAcked < (uint64_t) len)
	{
		result = -1;
	}

	conn->txActive = 0;
	conn->secSinceData = 0;
	pthread_mutex_unlock(&e->mutex);
	return result;
}

int tcpv4EngineSendTo(Tcpv4Engine *e, uvast nodeNbr, const char *ductName,
		const unsigned char *bundle, int len)
{
	Tcpv4Conn *conn;
	int	   exists;
	int	   dialed = 0;
	int	   waited = 0;
	int	   result;

	for (;;)
	{
		if (!e->running)
		{
			return -1;
		}

		pthread_mutex_lock(&e->mutex);
		conn = claimConn(e, nodeNbr, &exists);
		pthread_mutex_unlock(&e->mutex);
		if (conn != NULL)
		{
			break;
		}

		if (exists)
		{
			/*	A session to this node is coming up or is
			 *	busy with another bundle; wait for it rather
			 *	than opening a second one.		*/

			if (waited >= 100)
			{
				return -1;
			}

			microsnooze(100000);
			waited++;
			continue;
		}

		if (dialed || engineConnect(e, nodeNbr, ductName) < 0)
		{
			return -1;
		}

		dialed = 1;
	}

	result = doSend(conn, bundle, len);

	pthread_mutex_lock(&e->mutex);
	conn->sendBusy = 0;
	pthread_cond_broadcast(&e->cond);
	pthread_mutex_unlock(&e->mutex);
	return result;
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
			oK(sendSessTerm(conn, TMSG_TERM_UNKNOWN, 0));
		}
	}

	for (conn = e->conns; conn != NULL; conn = conn->next)
	{
		failConn(conn);
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
