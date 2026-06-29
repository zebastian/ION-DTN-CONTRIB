/*
	quictls.h:	TLS backend interface for the QUIC convergence layer.

	The QUIC transport engine (quicsession.c) is backend-neutral; all
	dependence on a specific TLS library is confined behind this
	interface and implemented in one quictls_<backend>.c file.  The
	ngtcp2 crypto callbacks themselves are already backend-neutral, so
	only credential and session setup plus randomness live here.
									*/

#ifndef QUICTLS_H
#define QUICTLS_H

#include "quiccla.h"
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

/*	Per-session credentials (cert / key / trust anchors), shared by all
 *	connections of one QuicSession.  Opaque; defined by the backend.  */
typedef struct QuicTlsCreds QuicTlsCreds;

/*	Per-connection TLS session.  Opaque; defined by the backend.	*/
typedef struct QuicTlsConn QuicTlsConn;

/*	Fill buf with len cryptographically strong random bytes.  Returns
 *	0 on success, -1 on failure.					*/
int quicTlsRand(void *buf, size_t len);

/*	Allocate credentials from cfg for a client (isServer == 0) or a
 *	server (isServer != 0).  A server requires cert + key; a client
 *	verifies against cfg->caFile, or the system trust store when none
 *	is given.  Returns NULL on failure.				*/
QuicTlsCreds *quicTlsCredsNew(const QuicClaConfig *cfg, int isServer);
void quicTlsCredsFree(QuicTlsCreds *creds);

/*	Create a TLS session bound to creds and to connRef (which ngtcp2's
 *	crypto layer uses to recover the ngtcp2_conn).  ALPN, SNI and peer
 *	verification are taken from cfg.  Returns NULL on failure.	*/
QuicTlsConn *quicTlsConnNew(const QuicClaConfig *cfg, QuicTlsCreds *creds,
		ngtcp2_crypto_conn_ref *connRef, int isServer);
void quicTlsConnFree(QuicTlsConn *conn);

/*	The native TLS handle to pass to ngtcp2_conn_set_tls_native_handle. */
void *quicTlsNativeHandle(QuicTlsConn *conn);

#ifdef __cplusplus
}
#endif

#endif /* QUICTLS_H */
