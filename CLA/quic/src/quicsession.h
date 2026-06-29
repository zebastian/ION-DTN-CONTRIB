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
 *	connection serviced.  Returns NULL on failure.			*/
QuicSession *quicClientStart(const QuicClaConfig *cfg);

/*	Send one bundle (length-prefixed) on the connection.  Blocks
 *	until the data is handed to QUIC or the connection fails.
 *	Returns 0 on success, -1 on failure (caller should reconnect).	*/
int quicClientSend(QuicSession *s, const unsigned char *bundle, int len);

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
