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

#include <sys/uio.h>
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

/*	Accept-loop poll interval; bounds shutdown latency.		*/
#define TCPV4_ACCEPT_POLL_MS	 500

/*	Reception is buffered once a session is established: the message
 *	stream is then read in bufferfuls rather than a read per protocol
 *	field, which collapses the five reads an XFER_SEGMENT header costs
 *	- together with any acknowledgments that arrived behind it - into
 *	one.								*/
#define TCPV4_RXBUF_SIZE	 (64 * 1024)

/*	A read at least this large bypasses the buffer and lands directly
 *	in the caller's memory, so a bulk segment payload is not copied
 *	twice.								*/
#define TCPV4_RXBUF_DIRECT	 4096

/*	Ceiling on how long a sender waits for a session to this node to
 *	become usable - to finish negotiating, or to finish the transfer
 *	another sender is running.  Waiting longer than this serves the
 *	bundle less well than letting BP requeue it.			*/
#define TCPV4_CLAIM_TIMEOUT	 10

/*	Ceiling on how long a sender waits for room in a session's
 *	transmission window.  The clock thread normally detects a dead peer
 *	much sooner, but a session with KEEPALIVEs disabled has no such
 *	timer, so no sender is left blocked indefinitely.		*/
#define TCPV4_XFER_TIMEOUT	 300

/*	Octets read out of a bundle at a time.  A transfer is streamed
 *	rather than held in memory, which bounds both a session's transmit
 *	footprint and the length of the SDR transaction each read costs.	*/
#define TCPV4_TXBUF_SIZE	 (64 * 1024)

/*	Segments coalesced into a single write.  A peer that advertises a
 *	small Segment MRU would otherwise cost one write per segment.	*/
#define TCPV4_TX_SEGS_PER_WRITE	 16

/*	A session's second counters and its two activity flags are written
 *	by whichever of its own threads sent or received something, and
 *	read by the clock thread a second at a time.  The two never hold
 *	the same lock - a sender holds sendMutex or txMutex, the clock
 *	thread holds the engine lock - and taking the engine lock on every
 *	send to close that gap would serialise the sends against it.  So
 *	they are read and written atomically instead.  Relaxed ordering is
 *	all this needs: nothing is published through these fields, and the
 *	clock thread is entitled to a value one tick stale - it acts on
 *	whole seconds.							*/
#define TCPV4_GET(field)	__atomic_load_n(&(field), __ATOMIC_RELAXED)
#define TCPV4_SET(field, v)	__atomic_store_n(&(field), (v), __ATOMIC_RELAXED)
#define TCPV4_BUMP(field)	((void) __atomic_fetch_add(&(field), 1, \
					__ATOMIC_RELAXED))

/*	TCPCL session states (the subset the engine acts on; RFC 9174 3.3
 *	names more, but they collapse to these for our purposes).	*/
#define TCS_NEGOTIATING		 0 /* Contact/TLS/SESS_INIT in progress.	*/
#define TCS_ESTABLISHED		 1 /* SESS_INIT exchanged both ways.	*/
#define TCS_ENDING		 2 /* SESS_TERM sent or received.	*/

/*	One bundle being transmitted as one TCPCL transfer.  It is created
 *	when a sender hands the bundle over and destroyed when its outcome
 *	has been reported, and until then it sits on exactly one of the
 *	session's two transmission lists.				*/

typedef struct Tcpv4Xfer
{
	struct Tcpv4Xfer *next;
	Object		  bundle;     /* Opaque to the engine.		*/
	vast		  length;
	uint64_t	  transferId;
	int		  inFlight;   /* Transmit thread still holds it.	*/
	int		  acked;      /* Peer acknowledged all of it.	*/
	int		  refused;    /* Peer refused it, or it failed.	*/
	int		  completed;  /* Peer already had the bundle.	*/
} Tcpv4Xfer;

/*	How a finished transfer is reported to BP.  Acknowledgment of the
 *	whole length is the ordinary success; RFC 9174 5.2.4 gives one
 *	other, the "Completed" refusal, which says the receiver already
 *	has the bundle and lets the sender consider the transfer done
 *	rather than offering it again for as long as the bundle lives.	*/
#define TCPV4_XFER_SUCCEEDED(x) ((x)->completed || ((x)->acked && !(x)->refused))

typedef struct Tcpv4Conn
{
	struct Tcpv4Conn *next;
	Tcpv4Engine	 *owner;
	int		  sock;
	int		  activeRole;  /* 1 = we opened the connection.	*/
	Tcpv4TlsConn	 *tls;	       /* NULL when TLS was not enabled.*/
	int		  state;       /* TCS_*.			*/
	int		  failed;
	int		  receiverDone;
	int		  hasReceiver;
	int		  cleanClose; /* Session ended by SESS_TERM exchange.*/
	pthread_t	  receiver;

	char  peerName[TCPV4_MAX_HOST_LEN]; /* Duct name / peer address.	*/
	char  peerAddr[TCPV4_MAX_HOST_LEN]; /* Numeric address, accepted
					       sessions only.		*/
	char  peerNodeId[TCPV4_MAX_NODEID_LEN];	  /* What the peer claims.	*/
	char  dialNodeId[TCPV4_MAX_NODEID_LEN];	  /* From the egress plan;
					       empty when we accepted.	*/
	char  routeNodeId[TCPV4_MAX_NODEID_LEN];  /* Node this session may
					       carry bundles to; empty
					       means inbound only.	*/
	int   peerAuthenticated;   /* Certificate chain validated.	*/
	int   nodeIdAuthenticated; /* NODE-ID matched (RFC 9174 4.4.4.3).*/
	int   busy;		   /* Refuse: too many sessions open.	*/

	/*	Negotiated session parameters (RFC 9174 4.7).		*/
	int	 keepalive;   /* min of the two proposals, seconds.	*/
	uint64_t segmentMtu;  /* = peer's Segment MRU.			*/
	uint64_t transferMtu; /* = peer's Transfer MRU.			*/

	pthread_mutex_t sendMutex; /* Serialises every socket write.	*/
	int		hasSendMutex;

	/*	Transmission.  A sender thread appends to txQueue and
	 *	returns; this session's transmit thread moves each transfer
	 *	to txWindow before it writes the transfer's first octet and
	 *	leaves it there until an XFER_ACK retires it.  A bundle is
	 *	therefore on one of the two lists from before any of it is
	 *	sent until its outcome is reported, so a session that fails
	 *	loses none of them.  Only the transmit thread writes
	 *	XFER_SEGMENTs, which is what keeps transfers from
	 *	interleaving now that several may be outstanding.	*/
	pthread_mutex_t txMutex;
	int		hasTxMutex;
	pthread_cond_t	txCond;
	int		hasTxCond;
	pthread_t	xmit;
	int		hasXmit;
	Tcpv4Xfer      *txQueue;      /* Awaiting transmission.		*/
	Tcpv4Xfer      *txQueueTail;
	Tcpv4Xfer      *txWindow;     /* Awaiting acknowledgment.	*/
	Tcpv4Xfer      *txWindowTail;
	int		txCount;      /* On the two lists together.	*/
	vast		txBytes;      /* On the two lists together.	*/
	int		txSenders;    /* Senders holding this session.	*/
	uint64_t	nextTxId;
	uint64_t	txAckedLen;   /* Ack length for the window head.	*/
	int		txStopped;    /* No further transfers accepted.	*/
	int		txActive;     /* txCount != 0; read by the clock
					 thread, for the idle timer only.
					 TCPV4_GET/SET.			*/

	/*	Reception, touched only by this session's receiver thread
	 *	(plus rxActive, which the clock thread reads).		*/
	void	      *rx;	 /* Caller's per-session context.	*/
	unsigned char *rxBuf;	 /* Read-ahead; NULL = unbuffered.	*/
	int	       rxBufLen; /* Octets held.				*/
	int	       rxBufOff; /* Octets of those already consumed.	*/
	unsigned char *rxBundle;
	int	       rxCap;
	int	       rxLen;
	uint64_t       rxId;
	int	       rxActive;  /* TCPV4_GET/SET; see txActive.	*/
	int	       rxRefused; /* Draining a refused transfer.	*/

	/*	Reception hand-off.  A reassembled transfer is left here for
	 *	the delivery thread, so that BP's acquisition of one transfer
	 *	overlaps with reading the next off the wire.  Exactly one
	 *	transfer fits: a receiver that outruns BP has to block here,
	 *	because the ZCO attendant's backpressure is meant to reach
	 *	the peer rather than be absorbed by a growing queue.
	 *
	 *	The delivery thread sends the END segment's acknowledgment,
	 *	once BP has the bundle (RFC 9174 5.2.3).  Acknowledgments
	 *	must stay in order, so the receiver thread holds any of its
	 *	own until the hand-off is idle again.			*/
	pthread_mutex_t dlvMutex;
	int		hasDlvMutex;
	pthread_cond_t	dlvCond;
	int		hasDlvCond;
	pthread_t	dlv;
	int		hasDlv;
	unsigned char  *dlvBundle;    /* Swapped with rxBundle.		*/
	int		dlvCap;
	int		dlvLen;
	uint64_t	dlvId;
	uint8_t		dlvFlags;
	int		dlvPending;
	int		dlvStopped;
	int		dlvFailed;

	/*	Second counters advanced by the clock thread and reset by
	 *	the session's own threads; TCPV4_GET/SET/BUMP.		*/
	int secSinceTx;	  /* Since any message was sent.		*/
	int secSinceRx;	  /* Since any message was received.		*/
	int secSinceData; /* Since any non-KEEPALIVE message either way.	*/
	int secNegotiating;
	int termSent;
} Tcpv4Conn;

/*	Per-neighbour reconnection backoff (RFC 9174 4.1).  The backoff
 *	is advanced by anything that stops a session from being reached -
 *	a refused connection, but equally a contact header, TLS handshake
 *	or SESS_INIT that fails - and reset only once a session has
 *	actually been established.  A peer that accepts TCP and then
 *	rejects the session is the common misconfiguration, and it is
 *	exactly the case that a connect-only backoff never slows down.	*/
typedef struct Tcpv4Dial
{
	struct Tcpv4Dial *next;
	char		  nodeId[TCPV4_MAX_NODEID_LEN];
	int		  interval;	/* Current backoff, seconds.	*/
	int		  secUntilRetry;
} Tcpv4Dial;

/*	Per-session state the clock thread collects under the engine lock
 *	and acts on outside it.						*/
typedef struct
{
	Tcpv4Conn *conn;
	int	   sendKa;
	int	   sendTerm;
	int	   timedOut;
} Tcpv4Tick;

struct Tcpv4Engine
{
	int	       listenSock;
	Tcpv4ClaConfig cfg;
	char	       nodeId[TCPV4_MAX_NODEID_LEN];
	Tcpv4Receiver  rx;
	Tcpv4Transmitter tx;

	Tcpv4TlsCreds *serverCreds; /* TLS server role (passive entity).	*/
	Tcpv4TlsCreds *clientCreds; /* TLS client role (active entity).	*/

	pthread_t	acceptThread;
	pthread_t	clockThread;
	int		hasAcceptThread;
	int		hasClockThread;
	pthread_mutex_t mutex;
	pthread_cond_t	cond;
	int		running;  /* Cleared without the lock at shutdown
				     and polled by the accept and clock
				     threads; TCPV4_GET/SET.		*/

	Tcpv4Conn *conns;
	int	   connCount;
	int	   maxSessions;	 /* cfg.maxSessions, for brevity.	*/
	Tcpv4Dial *dials;
	Tcpv4Tick *ticks;	 /* Clock thread scratch, maxSessions
				    + TCPV4_BUSY_SLACK entries.		*/
	unsigned int randState;	 /* Backoff randomization (4.1).	*/
};

/*	*	*	tcpv4io.c: session I/O	*	*	*	*/

/*	Receive exactly len octets.  Returns len, 0 if the peer closed the
 *	connection, or -1 on failure.  Only the receiver thread reads.	*/
int tcpv4ConnRecv(Tcpv4Conn *conn, void *into, int len);

/*	Turn on read-ahead for this session, which is safe only once the
 *	session is established (see the definition).			*/
void tcpv4ConnStartBuffering(Tcpv4Conn *conn);

/*	Send len octets as one indivisible unit, taking sendMutex for the
 *	whole message.  Returns 0 on success, -1 on failure.		*/
int tcpv4ConnSend(Tcpv4Conn *conn, const void *data, int len);

/*	Apply the socket options every TCPCL socket wants.		*/
void tcpv4TuneSocket(const Tcpv4ClaConfig *cfg, int sock);

/*	Mark a session dead and wake everybody waiting on it.		*/
void tcpv4ConnFail(Tcpv4Conn *conn);

/*	Names for the log, so that a rejection or a refusal reads as what
 *	it is rather than as a number.					*/
const char *tcpv4MsgTypeName(uint8_t type);
const char *tcpv4RefuseReasonName(uint8_t reason);

/*	Read and report the rest of an inbound MSG_REJECT (RFC 9174 5.1.2),
 *	whose type octet the caller has already read.  Never answers with a
 *	MSG_REJECT of its own, which 5.1.2 forbids.  Returns 0 with
 *	*rejectedType set, -1 when the message could not be read.	*/
int tcpv4RecvMsgReject(Tcpv4Conn *conn, uint8_t *rejectedType);

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

/*	Send a sequence of buffers as one write, so that a run of segments
 *	costs one call rather than one per segment.  Caller holds
 *	sendMutex.							*/
int tcpv4ConnSendIov(Tcpv4Conn *conn, struct iovec *iov, int count);

/*	*	*	tcpv4tx.c: transmission	*	*	*	*/

/*	The transmit thread of an established session: writes the queued
 *	transfers, one at a time, streaming each out of its bundle.	*/
void *tcpv4XmitThread(void *parm);

/*	Stop accepting transfers and wake everyone waiting on the window,
 *	so the transmit thread and any blocked sender can leave.	*/
void tcpv4TxStop(Tcpv4Conn *conn);

/*	Report the outcome of every transfer still queued or outstanding,
 *	as a failure, and free them.  Called once the session's threads
 *	have been joined and no sender still holds the session.		*/
void tcpv4TxDrain(Tcpv4Conn *conn);

/*	A windowed transfer is finished once the transmit thread has let go
 *	of it and the peer has either acknowledged all of it or refused it.
 *	Unlinks and returns it, or NULL when it is not finished yet.
 *	Called with txMutex held; the caller reports the outcome after
 *	unlocking, because that call reaches into BP.			*/
Tcpv4Xfer *tcpv4TxFinished(Tcpv4Conn *conn, Tcpv4Xfer *x);

/*	*	*	tcpv4rx.c: reception	*	*	*	*/

/*	The delivery thread of an established session: hands reassembled
 *	transfers to BP and acknowledges them.				*/
void *tcpv4DeliveryThread(void *parm);

/*	Stop the delivery thread and wake it.				*/
void tcpv4DeliveryStop(Tcpv4Conn *conn);

/*	The message loop of an established session.  Returns 0 on a clean
 *	end of session, -1 when the session failed.			*/
int tcpv4MessageLoop(Tcpv4Conn *conn);

/*	*	*	tcpv4session.c: session lifecycle	*	*/

/*	Open a session to a peer, honouring the reconnection backoff of
 *	RFC 9174 4.1.  Returns 0 when a session is opening or open, -1 when
 *	no attempt was made.  Takes e->mutex itself, so the caller must
 *	not hold it.							*/
int tcpv4OpenSession(Tcpv4Engine *e, const char *nodeId, const char *ductName);

/*	Report the outcome of a session this node opened, so that the
 *	reconnection backoff of RFC 9174 4.1 advances on anything that
 *	kept the session from being established and resets only on a
 *	session that was.  A no-op for a session this node accepted.	*/
void tcpv4DialOutcome(Tcpv4Conn *conn, int established);

/*	Non-zero when this session is one more than the node is prepared
 *	to carry, so that negotiation ends it with SESS_TERM "Busy"
 *	(RFC 9174 6.1) rather than a bare close.			*/
int tcpv4ConnIsBusy(Tcpv4Conn *conn);

#ifdef __cplusplus
}
#endif

#endif /* TCPV4SESSINT_H */
