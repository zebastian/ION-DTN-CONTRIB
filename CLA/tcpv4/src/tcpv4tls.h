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

/*	Result of checking the peer's certificate against the TCPCL
 *	certificate profile of RFC 9174 4.4.2.				*/
#define TCPV4_EKU_PRESENT   1	/* Usable, and says so for TCPCL.	*/
#define TCPV4_EKU_ABSENT    0	/* Unrestricted (RFC 5280 4.2.1.12).	*/
#define TCPV4_EKU_NO_BUNDLE 2	/* Usable, but no id-kp-bundleSecurity.	*/
#define TCPV4_EKU_WRONG	    (-1) /* Restricted, and not to this use.	*/
#define TCPV4_EKU_ERROR	    (-2) /* No usable peer certificate.		*/

/*	Check the peer's end-entity certificate against the extended key
 *	usage profile of RFC 9174 4.4.2, which asks for rather less than
 *	one might assume: a TCPCL certificate SHOULD carry
 *	id-kp-bundleSecurity and MAY carry id-kp-clientAuth and
 *	id-kp-serverAuth, and is not obliged to carry an EKU extension at
 *	all.  So there are three usable shapes and one that is not:
 *
 *	  ABSENT	no extension, so no restriction (RFC 5280
 *			4.2.1.12) - usable, though not the profile 4.4.2
 *			asks an issuer for.
 *	  PRESENT	carries id-kp-bundleSecurity, or
 *			anyExtendedKeyUsage: the profile 4.4.5 recommends.
 *	  NO_BUNDLE	carries the TLS purpose this role needs
 *			(id-kp-serverAuth for the passive entity,
 *			id-kp-clientAuth for the active one) but does not
 *			say it is for TCPCL.
 *	  WRONG		carries an extension naming none of those, so it
 *			was issued for something else; using it here is
 *			what RFC 5280 forbids.
 *
 *	Returns one of TCPV4_EKU_*.					*/
int tcpv4TlsCheckKeyPurpose(Tcpv4TlsConn *conn);

/*	Result of checking the peer's certificate key usage (RFC 9174
 *	4.4.4.1, RFC 5280 4.2.1.3).					*/
#define TCPV4_KU_OK	1	/* Present and allows a signature.	*/
#define TCPV4_KU_ABSENT	0	/* No extension, so no restriction.	*/
#define TCPV4_KU_WRONG	(-1)	/* Present and forbids a signature.	*/
#define TCPV4_KU_ERROR	(-2)	/* No usable peer certificate.		*/

/*	RFC 9174 4.4.4.1 has the entity apply security policy to the key
 *	usage extension, if present, in accordance with RFC 5280 4.2.1.3
 *	and the profile of 4.4.2 - which asks for digitalSignature, the
 *	bit a TLS 1.3 handshake actually uses.  A certificate whose key
 *	usage withholds it cannot have authenticated this handshake, so
 *	accepting one would be accepting a signature its issuer said the
 *	key was not for.  Returns one of TCPV4_KU_*.			*/
int tcpv4TlsCheckKeyUsage(Tcpv4TlsConn *conn);

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
