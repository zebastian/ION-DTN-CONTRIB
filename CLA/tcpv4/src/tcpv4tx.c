/*
	tcpv4tx.c:	the send path of the TCPCLv4 session engine.

			Two threads meet here.  A caller's sender thread
			finds or opens a session to the destination node and
			leaves the bundle on that session's queue, which is
			all tcpv4EngineSendTo does; it does not wait for the
			bundle to be written, let alone acknowledged.  The
			session's own transmit thread then writes the queued
			transfers one at a time, streaming each out of its
			bundle rather than holding it in memory.

			RFC 9174 5.2.2 forbids interleaving the segments of
			two transfers within a session, which is why only
			the transmit thread writes XFER_SEGMENTs.  It does
			not forbid beginning a transfer before the previous
			one has been acknowledged, and not waiting is what
			keeps a link with any real round-trip time busy: the
			window here is what stands between one bundle per
			round trip and a full pipe.

			A transfer sits on the queue from before its first
			octet is written until its outcome has been
			reported, so a session that fails reports every
			bundle it was carrying rather than losing it.
								*/

#include "tcpv4sessint.h"
#include <errno.h>
#include <string.h>
#include <time.h>

/*	*	*	Transfer lists	*	*	*	*	*/

static void txAppend(Tcpv4Xfer **head, Tcpv4Xfer **tail, Tcpv4Xfer *x)
{
	x->next = NULL;
	if (*tail == NULL)
	{
		*head = x;
	}
	else
	{
		(*tail)->next = x;
	}

	*tail = x;
}

static int txUnlink(Tcpv4Xfer **head, Tcpv4Xfer **tail, Tcpv4Xfer *x)
{
	Tcpv4Xfer **pp = head;
	Tcpv4Xfer  *prev = NULL;

	while (*pp != NULL)
	{
		if (*pp == x)
		{
			*pp = x->next;
			if (*tail == x)
			{
				*tail = prev;
			}

			x->next = NULL;
			return 1;
		}

		prev = *pp;
		pp = &(*pp)->next;
	}

	return 0;
}

Tcpv4Xfer *tcpv4TxFinished(Tcpv4Conn *conn, Tcpv4Xfer *x)
{
	if (x == NULL || x->inFlight || (!x->acked && !x->refused))
	{
		return NULL;
	}

	/*	Only the oldest outstanding transfer is ever acknowledged,
	 *	so the running acknowledgment length belongs to the head and
	 *	restarts when the head is retired.			*/

	if (conn->txWindow == x)
	{
		conn->txAckedLen = 0;
	}

	if (!txUnlink(&conn->txWindow, &conn->txWindowTail, x))
	{
		return NULL;
	}

	conn->txCount--;
	conn->txBytes -= x->length;
	conn->txActive = (conn->txCount != 0);
	pthread_cond_broadcast(&conn->txCond);
	return x;
}

void tcpv4TxStop(Tcpv4Conn *conn)
{
	if (!conn->hasTxMutex)
	{
		return;
	}

	pthread_mutex_lock(&conn->txMutex);
	conn->txStopped = 1;
	pthread_cond_broadcast(&conn->txCond);
	pthread_mutex_unlock(&conn->txMutex);
}

void tcpv4TxDrain(Tcpv4Conn *conn)
{
	Tcpv4Engine *e = conn->owner;
	Tcpv4Xfer   *dead = NULL;
	Tcpv4Xfer   *x;

	if (!conn->hasTxMutex)
	{
		return;
	}

	/*	Both lists are spliced out under the lock and reported
	 *	afterwards, because reporting reaches into BP.		*/

	pthread_mutex_lock(&conn->txMutex);
	conn->txStopped = 1;
	while ((x = conn->txQueue) != NULL)
	{
		conn->txQueue = x->next;
		x->next = dead;
		dead = x;
	}

	while ((x = conn->txWindow) != NULL)
	{
		conn->txWindow = x->next;
		x->next = dead;
		dead = x;
	}

	conn->txQueueTail = NULL;
	conn->txWindowTail = NULL;
	conn->txCount = 0;
	conn->txBytes = 0;
	conn->txActive = 0;
	pthread_mutex_unlock(&conn->txMutex);

	while (dead != NULL)
	{
		x = dead;
		dead = x->next;
		e->tx.done(e->tx.user, x->bundle, 0);
		MRELEASE(x);
	}
}

/*	*	*	Writing a transfer	*	*	*	*/

/*	Cut one bufferful into Segment MTU sized XFER_SEGMENTs and hand as
 *	many of them to the kernel per write as one iovec holds.  off is
 *	where this bufferful starts within the transfer, whose whole length
 *	is total.  Returns 0, or -1 when the session failed.		*/

static int sendSegments(Tcpv4Conn *conn, Tcpv4Xfer *x, const char *data,
		int len, vast off, vast total)
{
	uint8_t hdrs[TCPV4_TX_SEGS_PER_WRITE][32 + TMSG_XFEREXT_LENGTH_LEN];
	struct iovec iov[TCPV4_TX_SEGS_PER_WRITE * 2];
	int	     used = 0;
	int	     segs = 0;
	int	     consumed = 0;

	while (consumed < len)
	{
		Tcpv4XferSegment seg;
		uint8_t		 ext[TMSG_XFEREXT_LENGTH_LEN];
		int		 chunk = len - consumed;
		int		 hdrLen;

		if ((uint64_t) chunk > conn->segmentMtu)
		{
			chunk = (int) conn->segmentMtu;
		}

		memset(&seg, 0, sizeof(seg));
		seg.transferId = x->transferId;
		seg.dataLength = (uint64_t) chunk;
		if (off + consumed == 0)
		{
			seg.flags |= TMSG_FLAG_START;

			/*	RFC 9174 5.2.5.1: telling the peer how long
			 *	the whole transfer is lets it size its
			 *	reassembly once and refuse an over-large
			 *	transfer at this first segment rather than
			 *	part way through.			*/

			hdrLen = tcpv4MsgEncodeXferLengthExt(ext, sizeof(ext),
					(uint64_t) total);
			if (hdrLen < 0)
			{
				return -1;
			}

			seg.xferExt = ext;
			seg.xferExtLen = (uint32_t) hdrLen;
		}

		if (off + consumed + chunk == total)
		{
			seg.flags |= TMSG_FLAG_END;
		}

		hdrLen = tcpv4MsgEncodeXferSegmentHdr(hdrs[segs],
				sizeof(hdrs[segs]), &seg);
		if (hdrLen < 0)
		{
			return -1;
		}

		iov[used].iov_base = hdrs[segs];
		iov[used].iov_len = hdrLen;
		used++;
		iov[used].iov_base = (void *) (data + consumed);
		iov[used].iov_len = chunk;
		used++;
		segs++;
		consumed += chunk;

		if (segs == TCPV4_TX_SEGS_PER_WRITE || consumed == len)
		{
			int result;

			/*	RFC 9174 5.2.4: a message cannot be
			 *	preempted part way through, so the whole
			 *	run goes out under one hold of the mutex.	*/

			pthread_mutex_lock(&conn->sendMutex);
			result = tcpv4ConnSendIov(conn, iov, used);
			pthread_mutex_unlock(&conn->sendMutex);
			if (result < 0)
			{
				return -1;
			}

			conn->secSinceTx = 0;
			segs = 0;
			used = 0;
		}
	}

	return 0;
}

/*	Write one transfer, reading its bundle a bufferful at a time.
 *	Returns 0 when the transfer was written or abandoned because the
 *	peer refused it, -1 when the session failed.			*/

static int sendTransfer(Tcpv4Conn *conn, Tcpv4Xfer *x, char *buffer)
{
	Tcpv4Engine *e = conn->owner;
	void	    *cursor = NULL;
	vast	     off = 0;
	int	     result = 0;

	if (e->tx.open(e->tx.user, x->bundle, &cursor) < 0)
	{
		putErrmsg("tcpv4cla can't read a bundle for transmission.",
				conn->peerName);
		return -1;
	}

	while (off < x->length)
	{
		int want = (int) (x->length - off);
		int got;
		int refused;

		if (want > TCPV4_TXBUF_SIZE)
		{
			want = TCPV4_TXBUF_SIZE;
		}

		got = e->tx.read(e->tx.user, cursor, buffer, want);
		if (got != want)
		{
			putErrmsg("tcpv4cla can't issue from a bundle.",
					conn->peerName);
			result = -1;
			break;
		}

		if (sendSegments(conn, x, buffer, got, off, x->length) < 0)
		{
			result = -1;
			break;
		}

		off += got;

		/*	RFC 9174 5.2.4: once the peer has refused a
		 *	transfer there is no point sending the rest of it.	*/

		pthread_mutex_lock(&conn->txMutex);
		refused = x->refused;
		pthread_mutex_unlock(&conn->txMutex);
		if (refused)
		{
			break;
		}
	}

	e->tx.close(e->tx.user, cursor);
	return result;
}

void *tcpv4XmitThread(void *parm)
{
	Tcpv4Conn   *conn = parm;
	Tcpv4Engine *e = conn->owner;
	char	    *buffer;

	buffer = MTAKE(TCPV4_TXBUF_SIZE);
	if (buffer == NULL)
	{
		putErrmsg("tcpv4cla: no memory for a transmit buffer.",
				conn->peerName);
		tcpv4ConnFail(conn);
		return NULL;
	}

	for (;;)
	{
		Tcpv4Xfer *x;
		Tcpv4Xfer *done;
		int	   failed;

		pthread_mutex_lock(&conn->txMutex);
		while (conn->txQueue == NULL && !conn->txStopped)
		{
			pthread_cond_wait(&conn->txCond, &conn->txMutex);
		}

		x = conn->txQueue;
		if (x == NULL) /*	Stopped, and nothing left.	*/
		{
			pthread_mutex_unlock(&conn->txMutex);
			break;
		}

		if (conn->txStopped)
		{
			/*	The session is going away; leave the queue
			 *	for the drain to report.		*/

			pthread_mutex_unlock(&conn->txMutex);
			break;
		}

		/*	Move it to the window before writing a single
		 *	octet of it, so that it is never on neither list.	*/

		oK(txUnlink(&conn->txQueue, &conn->txQueueTail, x));
		x->transferId = conn->nextTxId++;
		x->inFlight = 1;
		txAppend(&conn->txWindow, &conn->txWindowTail, x);
		pthread_mutex_unlock(&conn->txMutex);

		failed = (sendTransfer(conn, x, buffer) < 0);

		/*	Let go of the transfer.  From here the receiver
		 *	thread may retire it, so it must not be touched
		 *	again outside the lock.				*/

		pthread_mutex_lock(&conn->txMutex);
		x->inFlight = 0;
		if (failed)
		{
			x->refused = 1;
		}

		done = tcpv4TxFinished(conn, x);
		pthread_mutex_unlock(&conn->txMutex);

		if (done != NULL)
		{
			e->tx.done(e->tx.user, done->bundle,
					done->acked && !done->refused);
			MRELEASE(done);
		}

		if (failed)
		{
			tcpv4ConnFail(conn);
			break;
		}
	}

	MRELEASE(buffer);
	writeErrmsgMemos();
	return NULL;
}

/*	*	*	Handing a bundle to a session	*	*	*/

/*	Find an established session to nodeNbr.  *exists reports whether any
 *	session to that node is alive, so the caller can wait for one that
 *	is still negotiating instead of opening a second connection.
 *	Called with e->mutex held.					*/

static Tcpv4Conn *findConn(Tcpv4Engine *e, uvast nodeNbr, int *exists)
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
		if (conn->state != TCS_ESTABLISHED)
		{
			continue;
		}

		/*	Hold the session for as long as this sender is
		 *	using it, so that the clock thread cannot reap it
		 *	out from under the queue insertion below.	*/

		conn->txSenders++;
		return conn;
	}

	return NULL;
}

static void releaseConn(Tcpv4Engine *e, Tcpv4Conn *conn)
{
	pthread_mutex_lock(&e->mutex);
	conn->txSenders--;
	pthread_cond_broadcast(&e->cond);
	pthread_mutex_unlock(&e->mutex);
}

/*	Queue one transfer on a session, waiting for room in its window.
 *	Returns 0 when the session has taken the bundle, -1 otherwise.	*/

static int queueXfer(Tcpv4Conn *conn, Object bundle, vast length)
{
	Tcpv4Xfer      *x;
	struct timespec deadline;
	int		result = 0;

	if ((uint64_t) length > conn->transferMtu)
	{
		writeMemoNote("[?] tcpv4cla: bundle exceeds the peer's"
			      " Transfer MRU;",
				conn->peerName);
		return -1;
	}

	x = MTAKE(sizeof(Tcpv4Xfer));
	if (x == NULL)
	{
		putErrmsg("tcpv4cla: no memory for a transfer.", NULL);
		return -1;
	}

	memset(x, 0, sizeof(*x));
	x->bundle = bundle;
	x->length = length;

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += TCPV4_XFER_TIMEOUT;
	pthread_mutex_lock(&conn->txMutex);

	/*	Wait for room, unless the window is empty - a bundle larger
	 *	than the whole byte budget still has to go somewhere.	*/

	while (!conn->txStopped && conn->txCount > 0
			&& (conn->txCount >= TCPV4_TX_WINDOW
					|| conn->txBytes + length
							> TCPV4_TX_WINDOW_BYTES))
	{
		if (pthread_cond_timedwait(&conn->txCond, &conn->txMutex,
				    &deadline)
				== ETIMEDOUT)
		{
			writeMemoNote("[?] tcpv4cla timed out waiting for"
				      " transmission window room on",
					conn->peerName);
			result = -1;
			break;
		}
	}

	if (result == 0 && conn->txStopped)
	{
		result = -1;
	}

	if (result == 0)
	{
		txAppend(&conn->txQueue, &conn->txQueueTail, x);
		conn->txCount++;
		conn->txBytes += length;
		conn->txActive = 1;
		conn->secSinceData = 0;
		pthread_cond_broadcast(&conn->txCond);
	}

	pthread_mutex_unlock(&conn->txMutex);
	if (result < 0)
	{
		MRELEASE(x);
	}

	return result;
}

int tcpv4EngineSendTo(Tcpv4Engine *e, uvast nodeNbr, const char *ductName,
		Object bundle, vast length)
{
	Tcpv4Conn      *conn;
	struct timespec deadline;
	int		exists;
	int		dialed = 0;
	int		result;

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += TCPV4_CLAIM_TIMEOUT;
	pthread_mutex_lock(&e->mutex);
	for (;;)
	{
		if (!e->running)
		{
			pthread_mutex_unlock(&e->mutex);
			return -1;
		}

		conn = findConn(e, nodeNbr, &exists);
		if (conn != NULL)
		{
			break;
		}

		if (exists)
		{
			/*	A session to this node is coming up; wait
			 *	for it rather than opening a second one.
			 *	Establishment and session failure both
			 *	broadcast on e->cond.			*/

			if (pthread_cond_timedwait(&e->cond, &e->mutex,
					    &deadline)
					== ETIMEDOUT)
			{
				pthread_mutex_unlock(&e->mutex);
				writeMemoNote("[?] tcpv4cla timed out waiting"
					      " for a session to",
						(char *) ductName);
				return -1;
			}

			continue;
		}

		if (dialed) /*	Dialled once already, and it is gone.	*/
		{
			pthread_mutex_unlock(&e->mutex);
			return -1;
		}

		/*	No session at all: dial one.  tcpv4OpenSession takes
		 *	e->mutex itself, and the session it starts appears in
		 *	the list before it returns, so the next pass round
		 *	sees it and waits for it to establish.		*/

		pthread_mutex_unlock(&e->mutex);
		if (tcpv4OpenSession(e, nodeNbr, ductName) < 0)
		{
			return -1;
		}

		dialed = 1;
		pthread_mutex_lock(&e->mutex);
	}

	pthread_mutex_unlock(&e->mutex);
	result = queueXfer(conn, bundle, length);
	releaseConn(e, conn);
	return result;
}
