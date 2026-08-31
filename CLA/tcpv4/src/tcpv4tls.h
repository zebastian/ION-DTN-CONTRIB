/*
	tcpv4tls.h:	TLS backend interface for the TCPCLv4 convergence
			layer.

	The session engine is backend-neutral; all
	dependence on a specific TLS library is confined behind this
	interface and implemented in one tcpv4tls_<backend>.c file.

	RFC 9174 4.4.3 makes the active entity (the one that opened the TCP
	connection) the TLS client and the passive entity the TLS server;
	the passive entity supplies a certificate and requests one from the
	active entity, so both roles need their own credentials.
									*/

#ifndef TCPV4TLS_H
#define TCPV4TLS_H

#include "tcpv4cla.h"

#ifdef __cplusplus
extern "C" {
#endif

/*	Credentials (cert / key / trust anchors), shared by every
 *	connection of one engine.  Opaque; defined by the backend.	*/
typedef struct Tcpv4TlsCreds Tcpv4TlsCreds;

/*	Per-connection TLS session.  Opaque; defined by the backend.	*/
typedef struct Tcpv4TlsConn Tcpv4TlsConn;

/*	Allocate credentials from cfg for the TLS client (isServer == 0) or
 *	the TLS server (isServer != 0) role.  Both roles require cert + key
 *	per RFC 9174 4.4.3; peers are verified against cfg->caFile, or the
 *	system trust store when none is given.  Returns NULL on failure.	*/
Tcpv4TlsCreds *tcpv4TlsCredsNew(const Tcpv4ClaConfig *cfg, int isServer);
void tcpv4TlsCredsFree(Tcpv4TlsCreds *creds);

/*	Run the TLS handshake over the already-connected socket sock.
 *	hostName is the DNS name of the passive entity, used for the SNI
 *	server_name extension and certificate verification in the client
 *	role (RFC 9174 4.4.3); it is ignored in the server role.  Returns
 *	NULL on failure, in which case the caller closes the TCP
 *	connection (RFC 9174 4.4.3).					*/
Tcpv4TlsConn *tcpv4TlsHandshake(const Tcpv4ClaConfig *cfg,
		Tcpv4TlsCreds *creds, int sock, int isServer,
		const char *hostName);

/*	Send exactly len octets.  Returns len on success, -1 on failure.	*/
int tcpv4TlsSend(Tcpv4TlsConn *conn, const void *data, int len);

/*	Batch the next sends into as few TLS records as possible: cork,
 *	send the pieces, then uncork to flush them.  Used to keep a TCPCL
 *	segment's header and payload in one record rather than two.	*/
void tcpv4TlsCork(Tcpv4TlsConn *conn);
int tcpv4TlsUncork(Tcpv4TlsConn *conn);

/*	Receive up to len octets.  Returns the number received (> 0), 0 on
 *	orderly peer shutdown, or -1 on failure.			*/
int tcpv4TlsRecv(Tcpv4TlsConn *conn, void *into, int len);

/*	Non-zero if the peer supplied a certificate that validated against
 *	the configured trust anchors.  RFC 9174 4.6 warns that an
 *	unauthenticated peer node ID is not to be trusted for routing.	*/
int tcpv4TlsPeerAuthenticated(Tcpv4TlsConn *conn);

/*	Result of validating an identity against certificate claims, in the
 *	three-way form RFC 9174 4.4.4 defines.				*/
#define TCPV4_NODEID_SUCCESS 1	/* A NODE-ID is present and matches.	*/
#define TCPV4_NODEID_ABSENT  0	/* The certificate carries no NODE-ID.	*/
#define TCPV4_NODEID_FAILURE (-1) /* NODE-IDs present, none matches.	*/
#define TCPV4_NODEID_ERROR   (-2) /* No usable peer certificate.	*/

/*	Validate nodeId against the NODE-IDs of the peer's end-entity
 *	certificate (RFC 9174 4.4.4.3), a NODE-ID being a subjectAltName
 *	otherName of form id-on-bundleEID whose value is a node ID
 *	(RFC 9174 4.4.1).  Returns one of TCPV4_NODEID_*.		*/
int tcpv4TlsMatchNodeId(Tcpv4TlsConn *conn, const char *nodeId);

/*	Tear down the TLS session.  When graceful is non-zero a close_notify
 *	is sent first.  Does not close the underlying socket.		*/
void tcpv4TlsClose(Tcpv4TlsConn *conn, int graceful);

#ifdef __cplusplus
}
#endif

#endif /* TCPV4TLS_H */
