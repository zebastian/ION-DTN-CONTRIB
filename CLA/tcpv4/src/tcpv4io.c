/*
	tcpv4io.c:	message-level I/O for the TCPCLv4 session engine.

			Everything that puts octets on a session, or takes
			them off, without interpreting them: the framing
			reads and writes (plain socket or TLS record), the
			socket options a TCPCL connection wants, and the
			encoders for the short session messages whose whole
			content is known at the call site.

			RFC 9174 5.2.4 makes a TCPCL message indivisible, so
			every writer here takes the session's sendMutex for
			the duration of one message.  Reads are the other
			way round - a message is taken apart a field at a
			time - so an established session reads through a
			buffer that one stream read fills.
								*/

#include "tcpv4sessint.h"
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include "ion_network.h"

/*	Read exactly len octets off the stream itself, bypassing the
 *	buffer.  Returns len, 0 at end of stream, or -1 on failure.	*/

static int connRecvExactly(Tcpv4Conn *conn, void *into, int len)
{
	char *cursor = (char *) into;
	int   got = 0;

	if (conn->tls != NULL)
	{
		while (got < len)
		{
			int n = tcpv4TlsRecv(conn->tls, cursor + got, len - got);

			if (n <= 0)
			{
				return n;
			}

			got += n;
		}

		return got;
	}

	return itcp_recv(&conn->sock, cursor, len);
}

/*	One read on the stream, returning however much the peer has ready:
 *	the count, 0 at end of stream, or -1 on failure.  The error mapping
 *	follows itcp_recv, which reports an interrupted or reset socket as
 *	an orderly end of stream rather than as a failure.		*/

static int connRecvSome(Tcpv4Conn *conn, void *into, int cap)
{
	int n;

	if (conn->tls != NULL)
	{
		return tcpv4TlsRecv(conn->tls, into, cap);
	}

	if (conn->sock == -1) /*	Socket has been closed.		*/
	{
		return 0;
	}

	n = irecv(conn->sock, into, cap, 0);
	if (n < 0)
	{
		switch (errno)
		{
		case EINTR: /*	Shutdown.				*/
		case EBADF:
		case ECONNRESET:
			return 0;

		default:
			putSysErrmsg("tcpv4cla: irecv() error on TCP socket",
					NULL);
			return -1;
		}
	}

	return n;
}

/*	Turn on read-ahead for this session.  This is safe only once the
 *	session is established: up to that point the stream may hand off to
 *	the TLS layer immediately after the contact header, and an octet
 *	read ahead into this buffer is an octet GnuTLS never sees.	*/

void tcpv4ConnStartBuffering(Tcpv4Conn *conn)
{
	if (conn->rxBuf != NULL)
	{
		return;
	}

	conn->rxBuf = MTAKE(TCPV4_RXBUF_SIZE);
	if (conn->rxBuf == NULL)
	{
		/*	Not fatal: the session goes on reading a protocol
		 *	field at a time, just more expensively.		*/

		writeMemoNote("[?] tcpv4cla: no memory for a receive buffer;"
			      " reading unbuffered from",
				conn->peerName);
		return;
	}

	conn->rxBufLen = 0;
	conn->rxBufOff = 0;
}

/*	Receive exactly len octets.  Returns len, 0 if the peer closed the
 *	connection, or -1 on failure.  Only the receiver thread reads.
 *
 *	A TCPCL message is read out a field at a time - an XFER_SEGMENT
 *	header alone costs five calls - so once the session is established
 *	the reads are served from a buffer that one stream read fills.
 *	That also picks up whatever followed the message in the same
 *	segment, which is where pipelined acknowledgments arrive.	*/

int tcpv4ConnRecv(Tcpv4Conn *conn, void *into, int len)
{
	char *cursor = (char *) into;
	int   got = 0;
	int   avail;

	if (conn->rxBuf == NULL) /*	Not buffered (yet).		*/
	{
		return connRecvExactly(conn, into, len);
	}

	avail = conn->rxBufLen - conn->rxBufOff;
	if (avail > 0)
	{
		got = (avail < len ? avail : len);
		memcpy(cursor, conn->rxBuf + conn->rxBufOff, got);
		conn->rxBufOff += got;
		if (got == len)
		{
			return len;
		}
	}

	/*	A bulk remainder - a segment payload - is read straight
	 *	into the caller's memory instead of being copied twice.	*/

	if (len - got >= TCPV4_RXBUF_DIRECT)
	{
		int n = connRecvExactly(conn, cursor + got, len - got);

		if (n == len - got)
		{
			return len;
		}

		/*	A stream that ends part way through a message
		 *	truncated it; that is a failure, not a clean
		 *	close.						*/

		return (got > 0 && n == 0) ? -1 : n;
	}

	while (got < len)
	{
		int want;
		int n = connRecvSome(conn, conn->rxBuf, TCPV4_RXBUF_SIZE);

		if (n <= 0)
		{
			return (got > 0 && n == 0) ? -1 : n;
		}

		conn->rxBufLen = n;
		want = (len - got < n ? len - got : n);
		memcpy(cursor + got, conn->rxBuf, want);
		conn->rxBufOff = want;
		got += want;
	}

	return len;
}

/*	Send len octets as one indivisible unit.  RFC 9174 5.2.4 notes that
 *	a TCPCL message cannot be cut short or preempted by another, so
 *	every writer takes sendMutex for the whole message.  Returns 0 on
 *	success, -1 on failure.						*/

static int connSendLocked(Tcpv4Conn *conn, const void *data, int len)
{
	if (conn->tls != NULL)
	{
		return tcpv4TlsSend(conn->tls, data, len) == len ? 0 : -1;
	}

	return itcp_send(&conn->sock, (char *) data, len) == len ? 0 : -1;
}

int tcpv4ConnSend(Tcpv4Conn *conn, const void *data, int len)
{
	int result;

	pthread_mutex_lock(&conn->sendMutex);
	result = connSendLocked(conn, data, len);
	pthread_mutex_unlock(&conn->sendMutex);
	if (result == 0)
	{
		conn->secSinceTx = 0;
	}

	return result;
}

/*	Send a sequence of buffers as one write.  Handing a segment's header
 *	and its payload to the kernel separately is what makes a TCPCL
 *	sender pay Nagle's small-write penalty on every segment: the header
 *	goes out alone and the payload then waits for its acknowledgment.
 *	A single writev - or, under TLS, a single corked record - keeps a
 *	run of segments in one write.  Caller holds sendMutex.		*/

int tcpv4ConnSendIov(Tcpv4Conn *conn, struct iovec *iov, int count)
{
	size_t remaining = 0;
	int    i;

	if (count < 1)
	{
		return 0;
	}

	if (conn->tls != NULL)
	{
		int result = 0;

		tcpv4TlsCork(conn->tls);
		for (i = 0; i < count; i++)
		{
			if (iov[i].iov_len == 0)
			{
				continue;
			}

			if (tcpv4TlsSend(conn->tls, iov[i].iov_base,
					    (int) iov[i].iov_len)
					!= (int) iov[i].iov_len)
			{
				result = -1;
				break;
			}
		}

		if (tcpv4TlsUncork(conn->tls) < 0)
		{
			result = -1;
		}

		return result;
	}

	for (i = 0; i < count; i++)
	{
		remaining += iov[i].iov_len;
	}

	while (remaining > 0)
	{
		ssize_t sent = writev(conn->sock, iov, count);

		if (sent < 0)
		{
			if (errno == EINTR)
			{
				continue;
			}

			return -1;
		}

		remaining -= (size_t) sent;
		if (remaining == 0)
		{
			return 0;
		}

		/*	A partial write: drop the octets already sent and
		 *	go round again with what is left.		*/

		while (sent > 0 && (size_t) sent >= iov[0].iov_len)
		{
			sent -= iov[0].iov_len;
			iov++;
			count--;
			if (count == 0)
			{
				return 0;
			}
		}

		if (sent > 0)
		{
			iov[0].iov_base
					= (void *) ((char *) iov[0].iov_base
							+ sent);
			iov[0].iov_len -= (size_t) sent;
		}
	}

	return 0;
}

/*	Settings every TCPCL socket wants: TCP_NODELAY, because a TCPCL
 *	sender alternates a small header with a large payload and Nagle
 *	would hold each header until the previous write was acknowledged,
 *	and the operator's socket buffer sizes when they asked for them.	*/

void tcpv4TuneSocket(const Tcpv4ClaConfig *cfg, int sock)
{
	int on = 1;

	oK(setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof on));

	if (cfg->rcvBufSize > 0)
	{
		int size = cfg->rcvBufSize;

		oK(setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *) &size,
				sizeof size));
	}

	if (cfg->sndBufSize > 0)
	{
		int size = cfg->sndBufSize;

		oK(setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *) &size,
				sizeof size));
	}
}

/*	Mark a session dead and wake everybody waiting on it.  The socket is
 *	shut down rather than closed so that a blocked reader returns while
 *	the descriptor stays valid until the session is reaped.		*/

void tcpv4ConnFail(Tcpv4Conn *conn)
{
	Tcpv4Engine *e = conn->owner;

	pthread_mutex_lock(&e->mutex);
	conn->failed = 1;
	pthread_cond_broadcast(&e->cond);
	pthread_mutex_unlock(&e->mutex);
	if (conn->sock != -1)
	{
		oK(shutdown(conn->sock, SHUT_RDWR));
	}
}

/*	*	*	Message transmission	*	*	*	*/

int tcpv4SendKeepalive(Tcpv4Conn *conn)
{
	uint8_t buf[1];
	int	len = tcpv4MsgEncodeKeepalive(buf, sizeof(buf));

	return len < 0 ? -1 : tcpv4ConnSend(conn, buf, len);
}

int tcpv4SendSessTerm(Tcpv4Conn *conn, uint8_t reason, int reply)
{
	Tcpv4SessTerm term;
	uint8_t	      buf[3];
	int	      len;

	memset(&term, 0, sizeof(term));
	term.flags = reply ? TMSG_TERM_FLAG_REPLY : 0;
	term.reason = reason;
	len = tcpv4MsgEncodeSessTerm(buf, sizeof(buf), &term);
	if (len < 0)
	{
		return -1;
	}

	writeMemoNote("[i] tcpv4cla sending SESS_TERM to", conn->peerName);
	return tcpv4ConnSend(conn, buf, len);
}

int tcpv4SendMsgReject(Tcpv4Conn *conn, uint8_t reason, uint8_t rejectedType)
{
	Tcpv4MsgReject rej;
	uint8_t	       buf[3];
	int	       len;

	memset(&rej, 0, sizeof(rej));
	rej.reason = reason;
	rej.rejectedType = rejectedType;
	len = tcpv4MsgEncodeMsgReject(buf, sizeof(buf), &rej);
	if (len < 0)
	{
		return -1;
	}

	writeMemoNote("[?] tcpv4cla sending MSG_REJECT to", conn->peerName);
	return tcpv4ConnSend(conn, buf, len);
}

int tcpv4SendXferAck(Tcpv4Conn *conn, uint8_t flags, uint64_t transferId,
		uint64_t ackLength)
{
	Tcpv4XferAck ack;
	uint8_t	     buf[18];
	int	     len;

	memset(&ack, 0, sizeof(ack));
	ack.flags = flags; /* RFC 9174 5.2.3: echo the segment's flags.	*/
	ack.transferId = transferId;
	ack.ackLength = ackLength;
	len = tcpv4MsgEncodeXferAck(buf, sizeof(buf), &ack);
	return len < 0 ? -1 : tcpv4ConnSend(conn, buf, len);
}

int tcpv4SendXferRefuse(Tcpv4Conn *conn, uint8_t reason, uint64_t transferId)
{
	Tcpv4XferRefuse refuse;
	uint8_t		buf[10];
	int		len;

	memset(&refuse, 0, sizeof(refuse));
	refuse.reason = reason;
	refuse.transferId = transferId;
	len = tcpv4MsgEncodeXferRefuse(buf, sizeof(buf), &refuse);
	return len < 0 ? -1 : tcpv4ConnSend(conn, buf, len);
}
