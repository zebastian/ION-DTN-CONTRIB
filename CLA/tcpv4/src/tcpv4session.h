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

/*	Transmission interface.  The engine never touches a bundle's
 *	storage or BP itself: it reads the octets it has to write through
 *	open/read/close, and reports the outcome of the whole transfer
 *	through done.  A bundle is streamed rather than held in memory, so
 *	read is called repeatedly as the transfer is written.
 *
 *	open	 starts reading one bundle and yields a cursor; returns 0,
 *		 or -1 to fail the transfer.
 *	read	 fills into with up to len octets; returns the count, or -1.
 *	close	 releases the cursor once the last octet has been read.
 *	done	 reports the transfer's outcome, on whichever thread
 *		 established it; succeeded is 1 or 0.  Every bundle handed
 *		 to tcpv4EngineSendTo is reported exactly once.		*/
typedef struct
{
	int (*open)(void *user, Object bundle, void **cursor);
	int (*read)(void *user, void *cursor, char *into, int len);
	void (*close)(void *user, void *cursor);
	void (*done)(void *user, Object bundle, int succeeded);
	void *user;
} Tcpv4Transmitter;

/*	Start the engine: bind and listen on cfg->host:cfg->port, load TLS
 *	credentials, and spawn the accept and clock threads.  The engine
 *	accepts inbound sessions and can initiate outbound ones; every
 *	session carries bundles both ways.  Returns NULL on failure.	*/
Tcpv4Engine *tcpv4EngineStart(const Tcpv4ClaConfig *cfg,
		const Tcpv4Receiver *rx, const Tcpv4Transmitter *tx);

/*	Hand one bundle, of the stated length, to the session to node
 *	nodeNbr, whose TCPCLv4 induct is named by ductName ("host[:port]").
 *	If an established session to that node already exists - whether this
 *	node accepted it or opened it - it is reused; otherwise a new session
 *	is opened, subject to the reconnection backoff of RFC 9174 4.1.
 *
 *	The bundle is queued, not sent: the call returns as soon as the
 *	session has accepted it, and the session's transmit thread writes it
 *	as one TCPCL transfer segmented to the peer's Segment MTU.  Several
 *	transfers may be outstanding at once, so a caller is not made to wait
 *	a round trip per bundle.  The transfer's outcome is reported later
 *	through the transmitter's done callback.
 *
 *	Returns 0 when the bundle has been accepted - the engine is then
 *	responsible for reporting its outcome - and -1 when it has not, in
 *	which case the caller still owns it and done is never called.	*/
int tcpv4EngineSendTo(Tcpv4Engine *e, uvast nodeNbr, const char *ductName,
		Object bundle, vast length);

/*	Stop the engine: terminate every session with SESS_TERM, close the
 *	listening socket, and join the internal threads.  Callers must stop
 *	their sender threads first.					*/
void tcpv4EngineStop(Tcpv4Engine *e);

#ifdef __cplusplus
}
#endif

#endif /* TCPV4SESSION_H */
