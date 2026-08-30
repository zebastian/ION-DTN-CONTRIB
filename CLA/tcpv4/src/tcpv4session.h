/*
	tcpv4session.h:	TCPCLv4 (RFC 9174) session engine for the tcpv4
			convergence layer.

	The engine drives every TCPCL session.  TCPCLv4 sessions are
	bidirectional: once established, either entity may transfer bundles
	over the session regardless of which one opened the TCP connection.
	The engine both accepts inbound connections on a listening socket
	and initiates outbound ones, and carries bundles in both directions
	on every session.

	Each session gets its own receiver thread, so the reception context
	(in ION terms, an acquisition work area and its attendant) is
	per-session too: the engine asks the caller to open one when a
	session is established and to close it when the session ends.
								*/

#ifndef TCPV4SESSION_H
#define TCPV4SESSION_H

#include "tcpv4cla.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Tcpv4Engine Tcpv4Engine;

/*	Reception interface, called on each session's receiver thread.
 *
 *	open	 creates the per-session reception context; returns NULL to
 *		 fail the session.
 *	deliver	 hands over one fully received bundle transfer; returns 0 on
 *		 success, -1 to fail the session.
 *	close	 releases the context when the session ends.		*/
typedef struct
{
	void *(*open)(void *user);
	int (*deliver)(void *rx, unsigned char *bundle, int len);
	void (*close)(void *rx);
	void *user;
} Tcpv4Receiver;

/*	Start the engine: bind and listen on cfg->host:cfg->port, load TLS
 *	credentials, and spawn the accept and clock threads.  The engine
 *	accepts inbound sessions and can initiate outbound ones; every
 *	session carries bundles both ways.  Returns NULL on failure.	*/
Tcpv4Engine *tcpv4EngineStart(const Tcpv4ClaConfig *cfg,
		const Tcpv4Receiver *rx);

/*	Send one bundle to node nodeNbr, whose TCPCLv4 induct is named by
 *	ductName ("host[:port]").  If an established session to that node
 *	already exists - whether this node accepted it or opened it - it is
 *	reused; otherwise a new session is opened, subject to the
 *	reconnection backoff of RFC 9174 4.1.  The bundle is sent as one
 *	TCPCL transfer, segmented to the peer's Segment MTU, and the call
 *	blocks until the peer has acknowledged the whole transfer.
 *	Returns 0 on success, -1 on failure.				*/
int tcpv4EngineSendTo(Tcpv4Engine *e, uvast nodeNbr, const char *ductName,
		const unsigned char *bundle, int len);

/*	Stop the engine: terminate every session with SESS_TERM, close the
 *	listening socket, and join the internal threads.  Callers must stop
 *	their sender threads first.					*/
void tcpv4EngineStop(Tcpv4Engine *e);

#ifdef __cplusplus
}
#endif

#endif /* TCPV4SESSION_H */
