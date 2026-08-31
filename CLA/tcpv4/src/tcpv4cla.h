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
	int  noVerify;			   /* skip peer verification.	*/
	int  tlsPolicy;			   /* TCPV4_TLS_*.		*/
	int  eidPolicy;			   /* TCPV4_EIDPOL_*.		*/
	int  keepalive;	   /* Keepalive Interval we propose, seconds.	*/
	int  idleSec;	   /* Idle session termination; 0 disables.	*/
	int  segmentMru;   /* advertised Segment MRU.			*/
	int  transferMru;  /* advertised Transfer MRU.			*/
	int  rcvBufSize;   /* SO_RCVBUF, bytes; 0 = OS default.		*/
	int  sndBufSize;   /* SO_SNDBUF, bytes; 0 = OS default.		*/
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
 *   -n             do not verify the peer certificate
 *   -T <policy>    TLS policy: require (default), prefer, none
 *   -E <policy>    NODE-ID authentication: require (default), prefer, none
 *   -K <seconds>   Keepalive Interval to propose (default 30, 0 disables)
 *   -t <seconds>   idle session termination timeout (default 0 = never)
 *   -S <bytes>     advertised Segment MRU (default 65536)
 *   -M <bytes>     advertised Transfer MRU (default 262144)
 *   -r <bytes>     socket receive buffer (SO_RCVBUF; 0 = OS default)
 *   -w <bytes>     socket send buffer (SO_SNDBUF; 0 = OS default)
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
