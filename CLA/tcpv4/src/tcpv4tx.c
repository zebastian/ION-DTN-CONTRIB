/*
	tcpv4tx.c:	the send path of the TCPCLv4 session engine.

			Runs on the caller's sender threads: finds or opens
			a session to the destination node, then sends one
			bundle as one TCPCL transfer, segmented to the
			peer's Segment MTU, and waits for the peer to
			acknowledge the whole of it.

			RFC 9174 5.2.2 forbids interleaving transfers within
			a session, so a sender claims the transmit side of
			the session for the whole transfer.
								*/

#include "tcpv4sessint.h"
#include <string.h>
#include <time.h>

/*	Claim the transmit side of an established session to nodeNbr.
 *	*exists reports whether any session to that node is alive, so the
 *	caller can wait for one that is still negotiating instead of
 *	opening a second connection.  Called with e->mutex held.	*/

static Tcpv4Conn *claimConn(Tcpv4Engine *e, uvast nodeNbr, int *exists)
{
	Tcpv4Conn *conn;

	*exists = 0;
	if (nodeNbr == 0)
	{
		return NULL;
	}

	for (conn = e->conns; conn != NULL; conn = conn->next)
	{
		/*	peerNode is left 0 for any session whose peer identity
		 *	is not established well enough to route on, so such a
		 *	session is never selected here (see applySessInit).	*/

		if (conn->failed || conn->receiverDone || conn->peerNode == 0
				|| conn->peerNode != nodeNbr)
		{
			continue;
		}

		if (conn->state == TCS_ENDING)
		{
			continue; /* RFC 9174 6.1: no new transfers.	*/
		}

		*exists = 1;
		if (conn->state != TCS_ESTABLISHED || conn->sendBusy)
		{
			continue;
		}

		conn->sendBusy = 1;
		return conn;
	}

	return NULL;
}

/*	Send one bundle as a single TCPCL transfer, segmented to the peer's
 *	Segment MTU, then wait for it to be acknowledged in full.	*/

static int doSend(Tcpv4Conn *conn, const unsigned char *bundle, int len)
{
	Tcpv4Engine	*e = conn->owner;
	Tcpv4XferSegment seg;
	uint8_t		 hdr[32];
	struct timespec	 deadline;
	int		 hdrLen;
	int		 off = 0;
	int		 result = 0;

	if ((uint64_t) len > conn->transferMtu)
	{
		writeMemoNote("[?] tcpv4cla: bundle exceeds the peer's"
			      " Transfer MRU;",
				conn->peerName);
		return -1;
	}

	pthread_mutex_lock(&e->mutex);
	conn->txId = conn->nextTxId++;
	conn->txAcked = 0;
	conn->txRefused = 0;
	conn->txActive = 1;
	conn->secSinceData = 0;
	pthread_mutex_unlock(&e->mutex);

	/*	RFC 9174 5.2.3 recommends sending segments without waiting
	 *	for each acknowledgment, so the whole transfer is written
	 *	before the cumulative acknowledgment is awaited.	*/

	do
	{
		int chunk = len - off;

		if ((uint64_t) chunk > conn->segmentMtu)
		{
			chunk = (int) conn->segmentMtu;
		}

		memset(&seg, 0, sizeof(seg));
		seg.flags = (off == 0 ? TMSG_FLAG_START : 0);
		if (off + chunk == len)
		{
			seg.flags |= TMSG_FLAG_END;
		}

		seg.transferId = conn->txId;
		seg.dataLength = (uint64_t) chunk;
		hdrLen = tcpv4MsgEncodeXferSegmentHdr(hdr, sizeof(hdr), &seg);
		if (hdrLen < 0)
		{
			result = -1;
			break;
		}

		/*	RFC 9174 5.2.4: a message cannot be preempted part
		 *	way through, so header and data go out under one
		 *	hold of the send mutex.				*/

		pthread_mutex_lock(&conn->sendMutex);
		if (tcpv4ConnSendSegment(conn, hdr, hdrLen, bundle + off, chunk) < 0)
		{
			result = -1;
		}

		pthread_mutex_unlock(&conn->sendMutex);
		if (result < 0)
		{
			break;
		}

		conn->secSinceTx = 0;
		off += chunk;
	} while (off < len);

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += TCPV4_XFER_TIMEOUT;
	pthread_mutex_lock(&e->mutex);
	while (result == 0 && !conn->failed && conn->txRefused == 0
			&& conn->txAcked < (uint64_t) len)
	{
		if (pthread_cond_timedwait(&e->cond, &e->mutex, &deadline)
				== ETIMEDOUT)
		{
			writeMemoNote("[?] tcpv4cla timed out awaiting"
				      " XFER_ACK from",
					conn->peerName);
			break;
		}
	}

	if (conn->failed || conn->txRefused != 0
			|| conn->txAcked < (uint64_t) len)
	{
		result = -1;
	}

	conn->txActive = 0;
	conn->secSinceData = 0;
	pthread_mutex_unlock(&e->mutex);
	return result;
}

int tcpv4EngineSendTo(Tcpv4Engine *e, uvast nodeNbr, const char *ductName,
		const unsigned char *bundle, int len)
{
	Tcpv4Conn *conn;
	int	   exists;
	int	   dialed = 0;
	int	   waited = 0;
	int	   result;

	for (;;)
	{
		if (!e->running)
		{
			return -1;
		}

		pthread_mutex_lock(&e->mutex);
		conn = claimConn(e, nodeNbr, &exists);
		pthread_mutex_unlock(&e->mutex);
		if (conn != NULL)
		{
			break;
		}

		if (exists)
		{
			/*	A session to this node is coming up or is
			 *	busy with another bundle; wait for it rather
			 *	than opening a second one.		*/

			if (waited >= 100)
			{
				return -1;
			}

			microsnooze(100000);
			waited++;
			continue;
		}

		if (dialed || tcpv4OpenSession(e, nodeNbr, ductName) < 0)
		{
			return -1;
		}

		dialed = 1;
	}

	result = doSend(conn, bundle, len);

	pthread_mutex_lock(&e->mutex);
	conn->sendBusy = 0;
	pthread_cond_broadcast(&e->cond);
	pthread_mutex_unlock(&e->mutex);
	return result;
}
