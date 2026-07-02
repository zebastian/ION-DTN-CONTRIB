/*
	quicudp.c:	UDP GSO/GRO offload for the QUICCL convergence layer
			(see quicudp.h).
								*/

#include "quicudp.h"
#include "quiccla.h" /* ION platform: putSysErrmsg, itoa.		*/
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/udp.h>

void quicUdpApplyOpts(int fd, int rcvBufSize, int sndBufSize, int *useGso,
		int *useGro)
{
	int v;

	if (rcvBufSize > 0)
	{
		v = rcvBufSize;
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof v) < 0)
		{
			putSysErrmsg("quiccla: SO_RCVBUF failed", itoa(v));
		}
	}

	if (sndBufSize > 0)
	{
		v = sndBufSize;
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof v) < 0)
		{
			putSysErrmsg("quiccla: SO_SNDBUF failed", itoa(v));
		}
	}

#ifdef UDP_SEGMENT
	*useGso = 1;
#endif
#ifdef UDP_GRO
	v = 1;
	if (setsockopt(fd, SOL_UDP, UDP_GRO, &v, sizeof v) == 0)
	{
		*useGro = 1;
	}
#endif
}

/*	Send [buf, buf+len) as gso-byte datagrams one at a time, used when GSO
 *	is unavailable or the kernel rejected a GSO send at runtime.		*/

static int sendPerDatagram(int fd, const uint8_t *buf, size_t len, size_t gso,
		const struct sockaddr *dest, socklen_t destLen)
{
	size_t off = 0;

	if (gso == 0)
	{
		gso = len;
	}

	while (off < len)
	{
		size_t	l = (len - off) < gso ? (len - off) : gso;
		ssize_t r;

		if (dest)
		{
			r = sendto(fd, buf + off, l, 0, dest, destLen);
		}
		else
		{
			r = sendto(fd, buf + off, l, 0, NULL, 0);
		}

		if (r < 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				return 1;
			}

			return -1;
		}

		off += l;
	}

	return 0;
}

/*	Send the coalesced batch [buf, buf+len) as gso_size-byte UDP segments
 *	via a single sendmsg() (kernel-segmented).			*/

static int sendBatch(int fd, int *useGso, const uint8_t *buf, size_t len,
		size_t gso_size, const struct sockaddr *dest,
		socklen_t destLen)
{
	struct msghdr msg;
	struct iovec  iov;
	ssize_t	      rc;

	if (len == 0)
	{
		return 0;
	}

#ifdef UDP_SEGMENT
	if (*useGso && gso_size != 0 && len > gso_size)
	{
		unsigned char	cbuf[CMSG_SPACE(sizeof(uint16_t))];
		struct cmsghdr *cm;
		uint16_t	seg = (uint16_t) gso_size;

		memset(&msg, 0, sizeof msg);
		iov.iov_base = (void *) buf;
		iov.iov_len = len;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		if (dest)
		{
			msg.msg_name = (void *) dest;
			msg.msg_namelen = destLen;
		}

		memset(cbuf, 0, sizeof cbuf);
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof cbuf;
		cm = CMSG_FIRSTHDR(&msg);
		cm->cmsg_level = SOL_UDP;
		cm->cmsg_type = UDP_SEGMENT;
		cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
		memcpy(CMSG_DATA(cm), &seg, sizeof seg);

		rc = sendmsg(fd, &msg, 0);
		if (rc >= 0)
		{
			return 0;
		}

		if (errno == EAGAIN || errno == EWOULDBLOCK)
		{
			return 1;
		}

		/*	GSO unsupported at runtime (older kernel): disable and
		 *	fall back to one datagram per segment.			*/

		*useGso = 0;
	}
#endif
	return sendPerDatagram(fd, buf, len, gso_size, dest, destLen);
}

void quicTxBatchInit(QuicTxBatch *b, int fd, int *useGso,
		const struct sockaddr *dest, socklen_t destLen)
{
	b->fd = fd;
	b->useGso = useGso;
	b->dest = dest;
	b->destLen = destLen;
	b->gsoSize = 0;
	b->pktCount = 0;
	b->pos = b->buf;
}

int quicTxBatchFlush(QuicTxBatch *b)
{
	int rc = sendBatch(b->fd, b->useGso, b->buf, (size_t) (b->pos - b->buf),
			b->gsoSize, b->dest, b->destLen);

	if (rc == 0)
	{
		b->pos = b->buf;
		b->pktCount = 0;
		b->gsoSize = 0;
	}

	return rc;
}

int quicTxBatchReserve(QuicTxBatch *b)
{
	if ((size_t) (b->buf + sizeof b->buf - b->pos) < (size_t) QUIC_MAX_UDP)
	{
		return quicTxBatchFlush(b);
	}

	return 0;
}

uint8_t *quicTxBatchTail(QuicTxBatch *b)
{
	return b->pos;
}

size_t quicTxBatchLimit(QuicTxBatch *b)
{
	/*	Cap this packet to the batch's segment size so every segment
	 *	but the last is gso_size bytes (the UDP GSO invariant).	*/

	return b->pktCount == 0 ? (size_t) QUIC_MAX_UDP : b->gsoSize;
}

int quicTxBatchCommit(QuicTxBatch *b, size_t nwrite)
{
	b->pos += nwrite;
	if (b->pktCount == 0)
	{
		b->gsoSize = nwrite;
	}

	b->pktCount++;

	/*	A short packet ends the GSO train (only the last segment may
	 *	be smaller); also flush at the packet cap.			*/

	if (nwrite < b->gsoSize || b->pktCount >= QUIC_TX_MAX_PKTS)
	{
		return quicTxBatchFlush(b);
	}

	return 0;
}

ssize_t quicUdpRecv(int fd, int useGro, void *buf, size_t buflen,
		struct sockaddr_storage *from, socklen_t *fromlen,
		int *segSize)
{
	struct iovec  iov;
	struct msghdr msg;
	ssize_t	      n;
#ifdef UDP_GRO
	unsigned char cbuf[CMSG_SPACE(sizeof(int))];
#endif

	*segSize = 0;
	memset(&msg, 0, sizeof msg);
	iov.iov_base = buf;
	iov.iov_len = buflen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (from)
	{
		msg.msg_name = from;
		msg.msg_namelen = sizeof(*from);
	}
#ifdef UDP_GRO
	if (useGro)
	{
		msg.msg_control = cbuf;
		msg.msg_controllen = sizeof cbuf;
	}
#endif

	n = recvmsg(fd, &msg, 0);
	if (n < 0)
	{
		return n;
	}

	if (fromlen)
	{
		*fromlen = msg.msg_namelen;
	}

#ifdef UDP_GRO
	if (useGro)
	{
		struct cmsghdr *cm;

		for (cm = CMSG_FIRSTHDR(&msg); cm != NULL;
				cm = CMSG_NXTHDR(&msg, cm))
		{
			if (cm->cmsg_level == SOL_UDP
					&& cm->cmsg_type == UDP_GRO)
			{
				int gso;

				memcpy(&gso, CMSG_DATA(cm), sizeof gso);
				*segSize = gso;
			}
		}
	}
#endif
	return n;
}

int quicUdpForEachPacket(uint8_t *buf, size_t n, int seg,
		int (*cb)(void *user, const uint8_t *pkt, size_t len),
		void *user)
{
	size_t segLen = seg > 0 ? (size_t) seg : n;
	size_t off;

	for (off = 0; off < n; off += segLen)
	{
		size_t pktLen = (n - off) < segLen ? (n - off) : segLen;

		if (cb(user, buf + off, pktLen) < 0)
		{
			return -1;
		}
	}

	return 0;
}
