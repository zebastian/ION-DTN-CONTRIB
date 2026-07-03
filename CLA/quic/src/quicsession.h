/*
	quicsession.h:	ngtcp2 + GnuTLS QUIC engine shared by quicclo
			(client) and quiccli (server).
								*/

#ifndef QUICSESSION_H
#define QUICSESSION_H

#include "quiccla.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct QuicSession QuicSession;

/*	Delivers one reassembled bundle (induct side).  Return 0 on
 *	success, -1 to stop the server loop.				*/
typedef int (*QuicBundleCb)(void *user, unsigned char *bundle, int len);

/*	*	*	Client (quicclo)	*	*	*	*/

/*	Connect to cfg->host:cfg->port and complete the QUIC/TLS
 *	handshake.  Spawns an internal I/O thread that keeps the
 *	connection serviced.  Returns NULL on failure.
 *
 *	QUICCL sessions are peer-symmetric: the passive peer may push
 *	bundles back over the same connection.  If cb is non-NULL, each such
 *	reverse-direction bundle is delivered via cb (as on the server);
 *	pass NULL for a send-only outduct.				*/
QuicSession *quicClientStart(const QuicClaConfig *cfg, QuicBundleCb cb,
		void *user);

/*	Send one bundle on the connection, as QUICCL XFER_SEGMENT(s) on the
 *	data stream selected by ordinal (the bundle's ECOS ordinal, 0-254;
 *	higher is more urgent).  Blocks until the data is handed to QUIC or
 *	the connection fails.  Returns 0 on success, -1 on failure (caller
 *	should reconnect).						*/
int quicClientSend(QuicSession *s, const unsigned char *bundle, int len,
		int ordinal);

void quicClientStop(QuicSession *s);

/*	*	*	Server (quiccli)	*	*	*	*/

/*	Bind a UDP socket to cfg->host:cfg->port.  Returns NULL on
 *	failure.							*/
QuicSession *quicServerStart(const QuicClaConfig *cfg);

/*	Run the server I/O loop in the caller's thread, delivering each
 *	reassembled bundle via cb, until *running becomes 0.  Returns 0
 *	on clean exit, -1 on error.					*/
int quicServerRun(QuicSession *s, QuicBundleCb cb, void *user,
		volatile int *running);

void quicServerStop(QuicSession *s);

#ifdef __cplusplus
}
#endif

#endif /* QUICSESSION_H */
