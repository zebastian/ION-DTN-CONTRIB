/*
	quicudp.h:	UDP GSO/GRO offload for the QUICCL convergence layer.
			Coalesce many equal-sized QUIC packets into one
			sendmsg() (GSO) and split GRO-coalesced reads back into
			individual packets, staying within the kernel's 64 KB /
			64-segment UDP GSO limit.
								*/

#ifndef QUICUDP_H
#define QUICUDP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QUIC_MAX_UDP 1452 /* Conservative QUIC datagram.		*/

/*	TX coalesces up to QUIC_TX_MAX_PKTS equal-sized QUIC packets into one
 *	sendmsg(); RX accepts GRO-coalesced reads of up to QUIC_RX_BUFSZ into
 *	one recvmsg().							*/
#define QUIC_TX_MAX_PKTS 44
#define QUIC_TX_BATCH	 (QUIC_MAX_UDP * QUIC_TX_MAX_PKTS)
#define QUIC_RX_BUFSZ	 (64 * 1024)

/*	Apply socket-buffer sizing and best-effort UDP GSO/GRO offload to a
 *	freshly created UDP socket.  GSO needs no socket option (it is a
 *	per-sendmsg cmsg); GRO is enabled here if the kernel supports it.
 *	*useGso is set when UDP_SEGMENT is available; *useGro is set when the
 *	kernel accepts UDP_GRO.						*/
void quicUdpApplyOpts(int fd, int rcvBufSize, int sndBufSize, int *useGso,
		int *useGro);

/*	*	*	Transmit batching	*	*	*	*	*/

/*	Accumulates equal-sized QUIC packets in one buffer and flushes them as
 *	a single GSO sendmsg().  The producer writes each packet at Tail(),
 *	bounded by Limit(), then calls Commit().  Reserve() before producing
 *	guarantees room; Flush() sends whatever remains.  All three return 0
 *	on success, 1 if the send would block, -1 on fatal error.		*/
typedef struct
{
	int		       fd;
	int		      *useGso;	 /* cleared on runtime GSO failure.*/
	const struct sockaddr *dest;	 /* NULL == connected socket.	*/
	socklen_t	       destLen;
	size_t		       gsoSize;	 /* segment size of this batch.	*/
	size_t		       pktCount; /* packets buffered this batch.	*/
	uint8_t		      *pos;	 /* next packet write point.	*/
	uint8_t		       buf[QUIC_TX_BATCH];
} QuicTxBatch;

/*	dest == NULL sends on a connected socket (client); otherwise
 *	dest/destLen name the peer (server).  *useGso is cleared if GSO fails
 *	at runtime (fallback to one datagram per segment).		*/
void quicTxBatchInit(QuicTxBatch *b, int fd, int *useGso,
		const struct sockaddr *dest, socklen_t destLen);

/*	Flush the batch if the next full-size packet would not fit.	*/
int quicTxBatchReserve(QuicTxBatch *b);

/*	Where the next packet is produced, and its size cap (which keeps every
 *	segment but the last equal to the batch's segment size, the UDP GSO
 *	invariant).							*/
uint8_t *quicTxBatchTail(QuicTxBatch *b);
size_t	 quicTxBatchLimit(QuicTxBatch *b);

/*	Record a produced packet of nwrite octets; flushes when the GSO train
 *	ends (a short packet) or the packet cap is reached.		*/
int quicTxBatchCommit(QuicTxBatch *b, size_t nwrite);

/*	Send any buffered packets.					*/
int quicTxBatchFlush(QuicTxBatch *b);

/*	*	*	Receive		*	*	*	*	*	*/

/*	recvmsg() one UDP read, reporting the GRO segment size (0 if the read
 *	is a single datagram) in *segSize so the caller can split a coalesced
 *	buffer back into individual QUIC packets.			*/
ssize_t quicUdpRecv(int fd, int useGro, void *buf, size_t buflen,
		struct sockaddr_storage *from, socklen_t *fromlen,
		int *segSize);

/*	Split a (possibly GRO-coalesced) read of n octets into seg-byte
 *	packets (seg == 0 means the whole read is one packet), invoking
 *	cb(user, pkt, len) for each.  Returns 0 when all packets were
 *	processed, or -1 if a callback returned < 0 (stopped early).	*/
int quicUdpForEachPacket(uint8_t *buf, size_t n, int seg,
		int (*cb)(void *user, const uint8_t *pkt, size_t len),
		void *user);

#ifdef __cplusplus
}
#endif

#endif /* QUICUDP_H */
