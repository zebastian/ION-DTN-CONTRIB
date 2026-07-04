/*
	quicsession.h:	ngtcp2 + GnuTLS QUIC engine for the QUICCL
			convergence layer.

	The engine drives every QUIC connection.  QUICCL sessions are
	peer-symmetric (draft-caini-dtn-quiccl): once established, either peer
	may send bundles over the connection, regardless of which peer opened
	it.  The engine both accepts inbound connections and initiates outbound
	ones on a single bound UDP socket, and carries bundles in both
	directions on every connection.
								*/

#ifndef QUICSESSION_H
#define QUICSESSION_H

#include "quiccla.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct QuicSession QuicSession;

/*	Delivers one reassembled bundle received on any connection.  Return 0
 *	on success, -1 to tear the connection down.			*/
typedef int (*QuicBundleCb)(void *user, unsigned char *bundle, int len);

/*	Start the QUICCL engine: bind a UDP socket to cfg->host:cfg->port, load
 *	TLS credentials, and spawn the internal I/O thread.  The engine accepts
 *	inbound connections and can initiate outbound ones on that socket;
 *	every connection carries bundles both ways.  Each received bundle is
 *	delivered via cb.  Returns NULL on failure.			*/
QuicSession *quicEngineStart(const QuicClaConfig *cfg, QuicBundleCb cb,
		void *user);

/*	Send one bundle to node nodeNbr, whose QUICCL induct is at host:port.
 *	If a live session to that node already exists - whether this node
 *	accepted it or opened it - it is reused; otherwise a new connection is
 *	opened.  The bundle is sent as QUICCL XFER_SEGMENT(s) on the data
 *	stream selected by ordinal (the bundle's ECOS ordinal, 0-254; higher
 *	is more urgent), or as QUIC datagrams when the unreliable service is
 *	configured.  Blocks until the data is handed to QUIC or the connection
 *	fails.  Returns 0 on success, -1 on failure.			*/
int quicEngineSendTo(QuicSession *s, uvast nodeNbr, const char *host, int port,
		const unsigned char *bundle, int len, int ordinal);

/*	Stop the engine: cleanly terminate every session and join the I/O
 *	thread.								*/
void quicEngineStop(QuicSession *s);

#ifdef __cplusplus
}
#endif

#endif /* QUICSESSION_H */
