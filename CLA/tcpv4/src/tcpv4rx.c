/*
	tcpv4rx.c:	the receive path of the TCPCLv4 session engine.

			Runs on each session's receiver thread once the
			session is established: reassembles the XFER_SEGMENT
			sequence of one transfer (RFC 9174 5.2.2) into a
			bundle and hands it to the caller's receiver, and
			handles the messages that arrive alongside -
			XFER_ACK, XFER_REFUSE, KEEPALIVE, SESS_TERM.

			The reassembly state of a session belongs to this
			thread alone; the clock thread only reads rxActive.
								*/

#include "tcpv4sessint.h"
#include <string.h>

/*	Grow the reassembly buffer to hold at least want octets.		*/

static int rxReserve(Tcpv4Conn *conn, int want)
{
	unsigned char *bigger;
	int	       cap;

	if (want <= conn->rxCap)
	{
		return 0;
	}

	cap = (conn->rxCap == 0 ? 8192 : conn->rxCap);
	while (cap < want)
	{
		cap <<= 1;
	}

	bigger = MTAKE(cap);
	if (bigger == NULL)
	{
		putErrmsg("tcpv4cla: no memory for transfer reassembly.", NULL);
		return -1;
	}

	if (conn->rxLen > 0)
	{
		memcpy(bigger, conn->rxBundle, conn->rxLen);
	}

	if (conn->rxBundle != NULL)
	{
		MRELEASE(conn->rxBundle);
	}

	conn->rxBundle = bigger;
	conn->rxCap = cap;
	return 0;
}

/*	Acknowledgments have to reach the peer in transfer order, and the
 *	END segment's is sent by the delivery thread once BP has the
 *	bundle.  So anything this thread sends about a transfer waits for
 *	the hand-off to drain first.  For the common single-segment
 *	transfer that costs nothing: this thread sends no acknowledgment
 *	at all, and goes straight on to read the next transfer while BP
 *	acquires the last one.						*/

static int rxAwaitDelivery(Tcpv4Conn *conn)
{
	int bad;

	pthread_mutex_lock(&conn->dlvMutex);
	while (conn->dlvPending && !conn->dlvStopped && !conn->dlvFailed)
	{
		pthread_cond_wait(&conn->dlvCond, &conn->dlvMutex);
	}

	bad = conn->dlvStopped || conn->dlvFailed;
	pthread_mutex_unlock(&conn->dlvMutex);
	return bad ? -1 : 0;
}

static int rxSendAck(Tcpv4Conn *conn, uint8_t flags, uint64_t transferId,
		uint64_t ackLength)
{
	return rxAwaitDelivery(conn) < 0
			? -1
			: tcpv4SendXferAck(conn, flags, transferId, ackLength);
}

static int rxSendRefuse(Tcpv4Conn *conn, uint8_t reason, uint64_t transferId)
{
	return rxAwaitDelivery(conn) < 0
			? -1
			: tcpv4SendXferRefuse(conn, reason, transferId);
}

/*	Hand a reassembled transfer to the delivery thread, which delivers
 *	it to BP and then acknowledges it.  The buffers are swapped rather
 *	than copied, so this thread goes on filling the one the delivery
 *	thread has just emptied.					*/

static int handOverTransfer(Tcpv4Conn *conn, const Tcpv4XferSegment *seg)
{
	unsigned char *buf;
	int	       cap;

	pthread_mutex_lock(&conn->dlvMutex);
	while (conn->dlvPending && !conn->dlvStopped && !conn->dlvFailed)
	{
		pthread_cond_wait(&conn->dlvCond, &conn->dlvMutex);
	}

	if (conn->dlvStopped || conn->dlvFailed)
	{
		pthread_mutex_unlock(&conn->dlvMutex);
		return -1;
	}

	buf = conn->dlvBundle;
	cap = conn->dlvCap;
	conn->dlvBundle = conn->rxBundle;
	conn->dlvCap = conn->rxCap;
	conn->rxBundle = buf;
	conn->rxCap = cap;
	conn->dlvLen = conn->rxLen;
	conn->dlvId = seg->transferId;
	conn->dlvFlags = seg->flags;
	conn->dlvPending = 1;
	conn->rxLen = 0;
	pthread_cond_broadcast(&conn->dlvCond);
	pthread_mutex_unlock(&conn->dlvMutex);
	return 0;
}

/*	Read and discard len octets, to stay in sync with the message
 *	stream while a transfer is being refused.			*/

static int drainOctets(Tcpv4Conn *conn, uint64_t len)
{
	unsigned char scratch[4096];

	while (len > 0)
	{
		int chunk = (len > sizeof scratch ? (int) sizeof scratch
						  : (int) len);

		if (tcpv4ConnRecv(conn, scratch, chunk) != chunk)
		{
			return -1;
		}

		len -= chunk;
	}

	return 0;
}

/*	Read one XFER_SEGMENT header (whose length varies with the START
 *	flag) into buf and decode it.  Returns 0 on success, -1 on
 *	failure.							*/

static int recvXferSegmentHdr(Tcpv4Conn *conn, uint8_t *buf, size_t cap,
		Tcpv4XferSegment *seg)
{
	uint32_t extLen = 0;
	int	 off;

	buf[0] = TMSG_XFER_SEGMENT;
	if (tcpv4ConnRecv(conn, buf + 1, 9) != 9) /* flags + Transfer ID.	*/
	{
		return -1;
	}

	off = 10;
	if (buf[1] & TMSG_FLAG_START)
	{
		if (tcpv4ConnRecv(conn, buf + off, 4) != 4)
		{
			return -1;
		}

		extLen = ((uint32_t) buf[off] << 24)
				| ((uint32_t) buf[off + 1] << 16)
				| ((uint32_t) buf[off + 2] << 8)
				| (uint32_t) buf[off + 3];
		off += 4;
		if (extLen > TCPV4_MAX_EXT_LEN)
		{
			writeMemoNote("[?] tcpv4cla got an oversized transfer"
				      " extension list from",
					conn->peerName);
			return -1;
		}

		if (extLen > 0)
		{
			if (tcpv4ConnRecv(conn, buf + off, extLen) != (int) extLen)
			{
				return -1;
			}

			off += extLen;
		}
	}

	if (tcpv4ConnRecv(conn, buf + off, 8) != 8) /* Data length.		*/
	{
		return -1;
	}

	off += 8;
	if ((size_t) off > cap
			|| tcpv4MsgDecodeXferSegmentHdr(buf, off, seg) != off)
	{
		writeMemoNote("[?] tcpv4cla got a malformed XFER_SEGMENT from",
				conn->peerName);
		return -1;
	}

	return 0;
}

/*	Non-zero when the segment carries a transfer extension item that is
 *	both unknown to us (all of them are) and marked CRITICAL, which
 *	RFC 9174 5.2.5 answers with XFER_REFUSE "Extension Failure".	*/

static int segmentHasCriticalExt(const Tcpv4XferSegment *seg)
{
	Tcpv4ExtItem item;
	size_t	     off = 0;
	int	     rc;

	while ((rc = tcpv4MsgNextExtItem(seg->xferExt, seg->xferExtLen, &off,
				&item))
			== 1)
	{
		if (item.flags & TMSG_EXT_CRITICAL)
		{
			return 1;
		}
	}

	return rc < 0 ? 1 : 0;
}

static int handleXferSegment(Tcpv4Conn *conn)
{
	Tcpv4Engine	*e = conn->owner;
	Tcpv4XferSegment seg;
	uint8_t		 hdr[32 + TCPV4_MAX_EXT_LEN];
	int		 dataLen;

	if (recvXferSegmentHdr(conn, hdr, sizeof(hdr), &seg) < 0)
	{
		return -1;
	}

	/*	RFC 9174 4.6: the peer must honour the Segment MRU we
	 *	advertised.  An oversized segment cannot be drained safely
	 *	(its length is attacker-chosen), so end the session.	*/

	if (seg.dataLength > (uint64_t) e->cfg.segmentMru)
	{
		writeMemoNote("[?] tcpv4cla got a segment larger than the"
			      " advertised Segment MRU from",
				conn->peerName);
		oK(tcpv4SendSessTerm(conn, TMSG_TERM_RESOURCE_EXHAUSTION, 0));
		return -1;
	}

	dataLen = (int) seg.dataLength;

	if (seg.flags & TMSG_FLAG_START)
	{
		if (conn->rxActive)
		{
			/*	RFC 9174 5.2.2 forbids interleaving
			 *	transfers within one session.		*/

			writeMemoNote("[?] tcpv4cla got interleaved transfers"
				      " from",
					conn->peerName);
			oK(tcpv4SendMsgReject(conn, TMSG_REJECT_UNEXPECTED,
					TMSG_XFER_SEGMENT));
			return -1;
		}

		pthread_mutex_lock(&e->mutex);
		conn->rxActive = 1;
		pthread_mutex_unlock(&e->mutex);
		conn->rxId = seg.transferId;
		conn->rxLen = 0;
		conn->rxRefused = 0;

		if (conn->state == TCS_ENDING)
		{
			/*	RFC 9174 6.1: no new incoming transfer is
			 *	accepted while the session is Ending.	*/

			conn->rxRefused = 1;
			oK(rxSendRefuse(conn, TMSG_REFUSE_SESS_TERM,
					seg.transferId));
		}
		else if (segmentHasCriticalExt(&seg))
		{
			conn->rxRefused = 1;
			oK(rxSendRefuse(conn, TMSG_REFUSE_EXT_FAILURE,
					seg.transferId));
		}
	}
	else
	{
		if (!conn->rxActive || seg.transferId != conn->rxId)
		{
			writeMemoNote("[?] tcpv4cla got a segment outside any"
				      " transfer from",
					conn->peerName);
			oK(tcpv4SendMsgReject(conn, TMSG_REJECT_UNEXPECTED,
					TMSG_XFER_SEGMENT));
			return -1;
		}
	}

	/*	RFC 9174 4.6: the whole transfer must fit the Transfer MRU
	 *	we advertised; refuse (and drain) the rest if it does not.	*/

	if (!conn->rxRefused
			&& (uint64_t) conn->rxLen + seg.dataLength
					> (uint64_t) e->cfg.transferMru)
	{
		conn->rxRefused = 1;
		oK(rxSendRefuse(conn, TMSG_REFUSE_NO_RESOURCES,
				seg.transferId));
	}

	if (conn->rxRefused)
	{
		if (drainOctets(conn, seg.dataLength) < 0)
		{
			return -1;
		}
	}
	else
	{
		if (rxReserve(conn, conn->rxLen + dataLen) < 0)
		{
			oK(tcpv4SendSessTerm(conn, TMSG_TERM_RESOURCE_EXHAUSTION, 0));
			return -1;
		}

		if (dataLen > 0
				&& tcpv4ConnRecv(conn, conn->rxBundle + conn->rxLen,
						   dataLen)
						!= dataLen)
		{
			return -1;
		}

		conn->rxLen += dataLen;
	}

	if (seg.flags & TMSG_FLAG_END)
	{
		pthread_mutex_lock(&e->mutex);
		conn->rxActive = 0;
		pthread_mutex_unlock(&e->mutex);

		if (!conn->rxRefused)
		{
			/*	RFC 9174 5.2.3 acknowledges a segment only
			 *	once it has been processed, which for the
			 *	last segment means BP has the bundle.  The
			 *	delivery thread does both, so that the
			 *	acquisition - an SDR transaction, and a wait
			 *	for ZCO space when reception is congested -
			 *	overlaps with reading whatever the peer
			 *	sends next.				*/

			return handOverTransfer(conn, &seg);
		}

		return 0;
	}

	if (!conn->rxRefused)
	{
		if (rxSendAck(conn, seg.flags, seg.transferId,
				    (uint64_t) conn->rxLen)
				< 0)
		{
			return -1;
		}
	}

	return 0;
}

static int handleXferAck(Tcpv4Conn *conn)
{
	Tcpv4Engine *e = conn->owner;
	Tcpv4XferAck ack;
	uint8_t	     buf[18];
	int	     known;

	buf[0] = TMSG_XFER_ACK;
	if (tcpv4ConnRecv(conn, buf + 1, 17) != 17)
	{
		return -1;
	}

	if (tcpv4MsgDecodeXferAck(buf, 18, &ack) != 18)
	{
		return -1;
	}

	pthread_mutex_lock(&e->mutex);
	known = (conn->txActive && ack.transferId == conn->txId);
	if (known)
	{
		conn->txAcked = ack.ackLength;
		pthread_cond_broadcast(&e->cond);
	}

	pthread_mutex_unlock(&e->mutex);

	if (!known)
	{
		/*	RFC 9174 5.1.2 names an XFER_ACK with an unknown
		 *	Transfer ID as a "Message Unexpected" case; it does
		 *	not require closing the session.		*/

		oK(tcpv4SendMsgReject(conn, TMSG_REJECT_UNEXPECTED, TMSG_XFER_ACK));
	}

	return 0;
}

static int handleXferRefuse(Tcpv4Conn *conn)
{
	Tcpv4Engine    *e = conn->owner;
	Tcpv4XferRefuse refuse;
	uint8_t		buf[10];
	int		known;

	buf[0] = TMSG_XFER_REFUSE;
	if (tcpv4ConnRecv(conn, buf + 1, 9) != 9)
	{
		return -1;
	}

	if (tcpv4MsgDecodeXferRefuse(buf, 10, &refuse) != 10)
	{
		return -1;
	}

	pthread_mutex_lock(&e->mutex);
	known = (conn->txActive && refuse.transferId == conn->txId);
	if (known)
	{
		conn->txRefused = refuse.reason + 1;
		pthread_cond_broadcast(&e->cond);
	}

	pthread_mutex_unlock(&e->mutex);

	if (known)
	{
		writeMemoNote("[i] tcpv4cla transfer refused by",
				conn->peerName);
	}
	else
	{
		oK(tcpv4SendMsgReject(conn, TMSG_REJECT_UNEXPECTED,
				TMSG_XFER_REFUSE));
	}

	return 0;
}

/*	*	*	Delivery thread	*	*	*	*	*/

void *tcpv4DeliveryThread(void *parm)
{
	Tcpv4Conn   *conn = parm;
	Tcpv4Engine *e = conn->owner;

	for (;;)
	{
		int failed;

		pthread_mutex_lock(&conn->dlvMutex);
		while (!conn->dlvPending && !conn->dlvStopped)
		{
			pthread_cond_wait(&conn->dlvCond, &conn->dlvMutex);
		}

		if (!conn->dlvPending) /*	Stopped, nothing left.	*/
		{
			pthread_mutex_unlock(&conn->dlvMutex);
			break;
		}

		pthread_mutex_unlock(&conn->dlvMutex);

		/*	RFC 9174 5.2.3: the last segment is acknowledged
		 *	only once it has been fully processed, which for a
		 *	transfer means BP has taken the bundle.		*/

		failed = (e->rx.deliver(conn->rx, conn->dlvBundle, conn->dlvLen)
				< 0);
		if (!failed)
		{
			failed = (tcpv4SendXferAck(conn, conn->dlvFlags,
						  conn->dlvId,
						  (uint64_t) conn->dlvLen)
					< 0);
		}

		pthread_mutex_lock(&conn->dlvMutex);
		conn->dlvPending = 0;
		if (failed)
		{
			conn->dlvFailed = 1;
		}

		pthread_cond_broadcast(&conn->dlvCond);
		pthread_mutex_unlock(&conn->dlvMutex);

		if (failed)
		{
			tcpv4ConnFail(conn);
			break;
		}
	}

	writeErrmsgMemos();
	return NULL;
}

void tcpv4DeliveryStop(Tcpv4Conn *conn)
{
	if (!conn->hasDlvMutex)
	{
		return;
	}

	pthread_mutex_lock(&conn->dlvMutex);
	conn->dlvStopped = 1;
	pthread_cond_broadcast(&conn->dlvCond);
	pthread_mutex_unlock(&conn->dlvMutex);
}

/*	Returns 1 when the session is to be closed cleanly, 0 to keep
 *	reading, -1 on failure.						*/

static int handleSessTerm(Tcpv4Conn *conn)
{
	Tcpv4Engine  *e = conn->owner;
	Tcpv4SessTerm term;
	uint8_t	      buf[3];
	int	      replyNeeded;

	buf[0] = TMSG_SESS_TERM;
	if (tcpv4ConnRecv(conn, buf + 1, 2) != 2)
	{
		return -1;
	}

	if (tcpv4MsgDecodeSessTerm(buf, 3, &term) != 3)
	{
		return -1;
	}

	pthread_mutex_lock(&e->mutex);
	replyNeeded = !(term.flags & TMSG_TERM_FLAG_REPLY) && !conn->termSent;
	conn->state = TCS_ENDING;
	conn->termSent = 1;
	pthread_cond_broadcast(&e->cond);
	pthread_mutex_unlock(&e->mutex);

	if (replyNeeded)
	{
		/*	RFC 9174 6.1: the acknowledging SESS_TERM repeats
		 *	the content of the message being acknowledged, with
		 *	the REPLY flag set.				*/

		oK(tcpv4SendSessTerm(conn, term.reason, 1));

		/*	Stay in the loop: the peer may still finish an
		 *	in-progress transfer before it closes.		*/

		return 0;
	}

	return 1; /* Our own termination was acknowledged.		*/
}

/*	The message loop of an established session.  Returns 0 on a clean
 *	end, -1 on failure.						*/

int tcpv4MessageLoop(Tcpv4Conn *conn)
{
	Tcpv4Engine *e = conn->owner;
	uint8_t	     type;
	int	     result;

	/*	Now that negotiation is over - and, with it, any handing
	 *	off of the stream to the TLS layer - reads can run ahead
	 *	of the field being parsed.				*/

	tcpv4ConnStartBuffering(conn);

	for (;;)
	{
		result = tcpv4ConnRecv(conn, &type, 1);
		if (result != 1)
		{
			/*	0 is the peer closing; RFC 9174 6.1 makes
			 *	a close during a transfer a failure of that
			 *	transfer, which the sender learns from the
			 *	session going away.			*/

			return result == 0 && conn->state == TCS_ENDING ? 0
									: -1;
		}

		pthread_mutex_lock(&e->mutex);
		conn->secSinceRx = 0;
		if (type != TMSG_KEEPALIVE)
		{
			conn->secSinceData = 0;
		}

		pthread_mutex_unlock(&e->mutex);

		switch (type)
		{
		case TMSG_XFER_SEGMENT:
			if (handleXferSegment(conn) < 0)
			{
				return -1;
			}

			break;

		case TMSG_XFER_ACK:
			if (handleXferAck(conn) < 0)
			{
				return -1;
			}

			break;

		case TMSG_XFER_REFUSE:
			if (handleXferRefuse(conn) < 0)
			{
				return -1;
			}

			break;

		case TMSG_KEEPALIVE:
			break;

		case TMSG_SESS_TERM:
			result = handleSessTerm(conn);
			if (result != 0)
			{
				return result < 0 ? -1 : 0;
			}

			break;

		case TMSG_SESS_INIT:
			/*	RFC 9174 5.1.2: a SESS_INIT after the
			 *	session is established is "Message
			 *	Unexpected".				*/

			oK(tcpv4SendMsgReject(conn, TMSG_REJECT_UNEXPECTED, type));
			return -1;

		default:
			/*	RFC 9174 5.1.2: an unknown message type is
			 *	rejected and the connection closed.	*/

			oK(tcpv4SendMsgReject(conn, TMSG_REJECT_TYPE_UNKNOWN, type));
			return -1;
		}
	}
}
