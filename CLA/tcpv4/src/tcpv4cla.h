/*
	tcpv4cla.h:	common definitions for the TCPCLv4 convergence
			layer adapter (RFC 9174, TLS via GnuTLS).

	Bundles are carried as XFER_SEGMENT messages over a TCP connection
	that is (by default) protected with TLS 1.3.
								*/

#ifndef TCPV4CLA_H
#define TCPV4CLA_H

#include <pthread.h>
#include "bpP.h"
#include "tcpv4nodeid.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TCPV4_DEFAULT_PORT	4556	    /* RFC 9174 8.1 (dtn-bundle).*/
#define TCPV4CLA_BUFSZ		(256 * 1024) /* Max bundle handled.	*/
#define TCPV4_DEFAULT_SEGMENT_MRU (64 * 1024)
#define TCPV4_DEFAULT_KEEPALIVE	30	/* RFC 9174 5.1.1: >= 30 s.	*/
#define TCPV4_MAX_KEEPALIVE	600	/* RFC 9174 5.1.1: <= 600 s.	*/
#define TCPV4_CONTACT_TIMEOUT	60	/* RFC 9174 4.1: <= 60 s.	*/
#define TCPV4_MAX_RECONNECT	60	/* RFC 9174 4.1: <= 60 s.	*/

#define TCPV4_MAX_HOST_LEN	256
#define TCPV4_MAX_PATH_LEN	1024
#define TCPV4_MAX_NODEID_LEN	256
#define TCPV4_MAX_PRIORITY_LEN	256

/*	Default bound on concurrently open sessions (RFC 9174 7.10,
 *	denial of service); -L overrides it.  A connection arriving past
 *	the bound is not simply dropped: RFC 9174 6.1 has a "Busy" reason
 *	for exactly this, so a few sessions beyond the bound are still
 *	negotiated far enough to say so.  Those slack slots are what
 *	stops the courtesy from being unbounded in its turn.		*/
#define TCPV4_DEFAULT_MAX_SESSIONS 64
#define TCPV4_MAX_SESSIONS_LIMIT   1024
#define TCPV4_BUSY_SLACK	   8

/*	Bound on connections from one peer address that may be part way
 *	through negotiation at the same time.  Negotiation is the phase
 *	an unauthenticated peer can drive - up to the contact timeout,
 *	and through a TLS handshake - so this is the phase that has to be
 *	rationed per peer rather than globally, lest one address hold
 *	every session slot on the node.  Established sessions are not
 *	capped per peer, so a legitimate peer reconnecting is unaffected.	*/
#define TCPV4_MAX_PEER_NEGOTIATING 4

/*	Transmission window: how many transfers, and how many octets of
 *	them, may be awaiting their XFER_ACK on one session at once; -W
 *	overrides both.  RFC 9174 5.2.2 forbids interleaving the segments
 *	of two transfers within a session, but not beginning a transfer
 *	before the previous one has been acknowledged - and it is that
 *	which keeps a link with any appreciable round-trip time busy,
 *	rather than idle for one round trip per bundle.  The window is
 *	therefore what bounds a delayed link's throughput: about one
 *	window per round trip, whichever of the two bounds binds first.
 *
 *	The window is bounded by octets as well as by count, because an
 *	outstanding transfer pins its bundle's outbound ZCO space until
 *	the acknowledgment retires it.  Either bound may be given as 0,
 *	which leaves that dimension unbounded and the other one to bound
 *	the window on its own; both at once is refused.			*/
#define TCPV4_DEFAULT_TX_WINDOW	       100
#define TCPV4_MAX_TX_WINDOW	       65536
#define TCPV4_DEFAULT_TX_WINDOW_BYTES  (4 * 1024 * 1024)

/*	Ceiling on the pause a sender takes after the engine declines a
 *	bundle.  BP offers a declined bundle again immediately, and the
 *	reasons the engine declines - a reconnection backoff with seconds
 *	to run, an unreachable peer, a bundle too large for the peer's
 *	Transfer MRU - do not clear in the time that takes, so without a
 *	pause the two spin against each other.				*/
#define TCPV4_RETRY_MAX_SEC	   5

/*	Local policy applied to the negotiated Enable TLS parameter
 *	(RFC 9174 4.3).  REQUIRE terminates the session with "Contact
 *	Failure" when the peer cannot do TLS; PREFER is the opportunistic
 *	security model of RFC 7435; DISABLE clears our CAN_TLS flag.	*/
#define TCPV4_TLS_REQUIRE	0
#define TCPV4_TLS_PREFER	1
#define TCPV4_TLS_DISABLE	2

/*	Local policy for NODE-ID authentication (RFC 9174 4.4.4.3): whether
 *	the peer's certificate must authenticate the node ID it claims in
 *	its SESS_INIT.  REQUIRE is the policy RFC 9174 4.4.5 recommends.
 *	A node ID that is not authenticated is never used to route bundles
 *	to the peer, whatever the policy (RFC 9174 4.6, 7.9).		*/
#define TCPV4_EIDPOL_REQUIRE	0
#define TCPV4_EIDPOL_PREFER	1
#define TCPV4_EIDPOL_NONE	2

/*	Local policy for the TCPCL certificate profile (RFC 9174 4.4.2).
 *	4.4.5 recommends that a certificate carrying an Extended Key Usage
 *	extension at all be required to name id-kp-bundleSecurity in it,
 *	which is REQUIRE; PREFER accepts one that does not and says so;
 *	NONE asks only what RFC 5280 4.2.1.12 asks, that the extension not
 *	exclude this use.  None of the three rejects a certificate with no
 *	such extension: 4.4.2 does not require one.			*/
#define TCPV4_EKUPOL_REQUIRE	0
#define TCPV4_EKUPOL_PREFER	1
#define TCPV4_EKUPOL_NONE	2

/*
 * Configuration parsed from command-line arguments.  A certificate and key
 * are required whenever TLS is not disabled: RFC 9174 4.4.3 has the passive
 * entity supply a certificate and request one from the active entity, so
 * both roles need their own end-entity credentials.
 */
typedef struct
{
	char host[TCPV4_MAX_HOST_LEN];
	int  port;
	char certFile[TCPV4_MAX_PATH_LEN]; /* end-entity cert (PEM).	*/
	char keyFile[TCPV4_MAX_PATH_LEN];  /* private key (PEM).	*/
	char caFile[TCPV4_MAX_PATH_LEN];   /* trust anchors (PEM).	*/
	char crlFile[TCPV4_MAX_PATH_LEN];  /* revocation lists (PEM).	*/
	int  noVerify;			   /* skip peer verification.	*/
	int  tlsPolicy;			   /* TCPV4_TLS_*.		*/
	int  eidPolicy;			   /* TCPV4_EIDPOL_*.		*/
	int  ekuPolicy;			   /* TCPV4_EKUPOL_*.		*/
	int  keepalive;	   /* Keepalive Interval we propose, seconds.	*/
	int  idleSec;	   /* Idle session termination; 0 disables.	*/
	int  segmentMru;   /* advertised Segment MRU.			*/
	int  transferMru;  /* advertised Transfer MRU.			*/
	int  rcvBufSize;   /* SO_RCVBUF, bytes; 0 = OS default.		*/
	int  sndBufSize;   /* SO_SNDBUF, bytes; 0 = OS default.		*/
	int  maxSessions;  /* Concurrently open sessions.		*/
	int  txWindow;	   /* Transfers awaiting acknowledgment; 0 =
			      bounded by txWindowBytes alone.		*/
	vast txWindowBytes; /* Octets of those; 0 = bounded by txWindow
			      alone.					*/
	char tlsPriority[TCPV4_MAX_PRIORITY_LEN]; /* GnuTLS priority
					string; empty = the default.	*/
} Tcpv4ClaConfig;

/*
 * Parse a duct name of the form "host[:port]" into components, where host
 * is a DNS name, an IPv4 address, or a bracketed IPv6 address ("[::1]").
 * The brackets are stripped, so host is what getaddrinfo() wants.
 * Returns 0 on success, -1 on error.  Leaves *port at the caller's
 * default when no ":port" is present.
 */
int parseTcpv4DuctName(const char *ductName, char *host, int *port);

/*
 * Parse optional command-line arguments.
 *
 *   -c <certfile>  end-entity certificate (PEM)  [required unless -T none]
 *   -k <keyfile>   private key (PEM)             [required unless -T none]
 *   -C <cafile>    CA trust anchors (PEM)
 *   -R <crlfile>   certificate revocation lists (PEM)
 *   -n             do not verify the peer certificate
 *   -T <policy>    TLS policy: require (default), prefer, none
 *   -E <policy>    NODE-ID authentication: require (default), prefer, none
 *   -B <policy>    id-kp-bundleSecurity: require, prefer (default), none
 *   -K <seconds>   Keepalive Interval to propose (default 30, 0 disables)
 *   -t <seconds>   idle session termination timeout (default 0 = never)
 *   -S <bytes>     advertised Segment MRU (default 65536)
 *   -M <bytes>     advertised Transfer MRU (default 262144)
 *   -r <bytes>     socket receive buffer (SO_RCVBUF; 0 = OS default)
 *   -w <bytes>     socket send buffer (SO_SNDBUF; 0 = OS default)
 *   -L <count>     concurrently open sessions (default 64)
 *   -W <count>[:<bytes>]  transfers, and octets of them, that may await
 *                  acknowledgment on one session at once (default
 *                  100:4194304); either bound may be 0 for "unbounded"
 *   -P <string>    TLS priority string (GnuTLS syntax); TLS 1.3 is
 *                  imposed on top of it, per RFC 9174 4.4.3
 *
 * Scans the options in argv[1..argc-2]; ION appends the duct name as
 * the final argument (the host), which the caller consumes.
 * Returns 0 on success, -1 on error.
 */
int parseTcpv4Args(int argc, char *argv[], Tcpv4ClaConfig *cfg);

#ifdef __cplusplus
}
#endif

#endif /* TCPV4CLA_H */
