/*
	tcpv4sessint.h: internal interface of the TCPCLv4 session engine.

			The engine is split across several translation units
			that share one session object, so the types that
			would otherwise be private to tcpv4session.c live
			here.  Nothing outside the engine includes this
			header; the engine's public interface is the much
			smaller tcpv4session.h.

			The units are layered: tcpv4io.c writes and reads
			whole messages on a session, tcpv4negotiate.c runs
			the contact and SESS_INIT exchange, tcpv4rx.c runs
			the message loop of an established session, tcpv4tx.c
			sends a bundle as a transfer, and tcpv4session.c owns
			the session list and the engine's threads.
								*/

#ifndef TCPV4SESSINT_H
#define TCPV4SESSINT_H

#include "tcpv4session.h"
#include "tcpv4msg.h"
#include "tcpv4tls.h"

#ifdef __cplusplus
extern "C" {
#endif

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
	int   peerAuthenticated;   /* Certificate chain validated.	*/
	int   nodeIdAuthenticated; /* NODE-ID matched (RFC 9174 4.4.4.3).*/

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

/*	*	*	tcpv4io.c: session I/O	*	*	*	*/

/*	Receive exactly len octets.  Returns len, 0 if the peer closed the
 *	connection, or -1 on failure.  Only the receiver thread reads.	*/
int tcpv4ConnRecv(Tcpv4Conn *conn, void *into, int len);

/*	Send len octets as one indivisible unit, taking sendMutex for the
 *	whole message.  Returns 0 on success, -1 on failure.		*/
int tcpv4ConnSend(Tcpv4Conn *conn, const void *data, int len);

/*	Send a message header and its payload as one unit, so that a
 *	transfer segment costs one write.  Caller holds sendMutex.	*/
int tcpv4ConnSendSegment(Tcpv4Conn *conn, const void *hdr, int hdrLen,
		const void *data, int dataLen);

/*	Apply the socket options every TCPCL socket wants.		*/
void tcpv4TuneSocket(const Tcpv4ClaConfig *cfg, int sock);

/*	Mark a session dead and wake everybody waiting on it.		*/
void tcpv4ConnFail(Tcpv4Conn *conn);

int tcpv4SendKeepalive(Tcpv4Conn *conn);
int tcpv4SendSessTerm(Tcpv4Conn *conn, uint8_t reason, int reply);
int tcpv4SendMsgReject(Tcpv4Conn *conn, uint8_t reason, uint8_t rejectedType);
int tcpv4SendXferAck(Tcpv4Conn *conn, uint8_t flags, uint64_t transferId,
		uint64_t ackLength);
int tcpv4SendXferRefuse(Tcpv4Conn *conn, uint8_t reason, uint64_t transferId);

/*	*	*	tcpv4negotiate.c: session establishment	*	*/

/*	Run the whole session establishment sequence on a fresh socket:
 *	contact header, optional TLS handshake, SESS_INIT exchange.
 *	Returns 0 with the session established, -1 otherwise.		*/
int tcpv4Establish(Tcpv4Conn *conn);

/*	*	*	tcpv4rx.c: reception	*	*	*	*/

/*	The message loop of an established session.  Returns 0 on a clean
 *	end of session, -1 when the session failed.			*/
int tcpv4MessageLoop(Tcpv4Conn *conn);

/*	*	*	tcpv4session.c: session lifecycle	*	*/

/*	Open a session to a peer, honouring the reconnection backoff of
 *	RFC 9174 4.1.  Returns 0 when a session is opening or open, -1 when
 *	no attempt was made.  Called with e->mutex held.		*/
int tcpv4OpenSession(Tcpv4Engine *e, uvast nodeNbr, const char *ductName);

#ifdef __cplusplus
}
#endif

#endif /* TCPV4SESSINT_H */
