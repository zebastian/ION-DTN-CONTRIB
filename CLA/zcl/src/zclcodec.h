/*	zclcodec.h:	wire format, compressor and receive state machine
			of the zcl compressing tunnel CLA.

	Depends on libzstd and libc only, so it can be unit-tested and
	fuzzed without ION.  See doc/design.md for the format.		*/

#ifndef ZCLCODEC_H
#define ZCLCODEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	ZCL_HDR_LEN		36
#define	ZCL_FLAG_END		0x01
#define	ZCL_REC_HDR_LEN		4

/*	The data label carriers are sent with: ASCII "zcl".		*/
#define	ZCL_DEFAULT_LABEL	8020844

#define	ZCL_DEFAULT_LEVEL	3
#define	ZCL_DEFAULT_WINDOWLOG	23
#define	ZCL_MAX_CARRIER		(64 * 1024 * 1024)

typedef struct
{
	uint8_t		flags;
	uint64_t	streamId;
	uint64_t	chunkId;
	uint32_t	seq;
	uint32_t	length;		/*	zstd bytes after header	*/
} ZclHeader;

extern uint32_t	zclCrc32c(uint32_t crc, const unsigned char *data,
			size_t len);

/*	Writes the header for 'payload' (h->length bytes) into 'out'.	*/
extern void	zclHeaderPut(unsigned char *out, const ZclHeader *h,
			const unsigned char *payload);

/*	Parses and checks a whole carrier: 0 if valid, else -1.	*/
extern int	zclHeaderGet(const unsigned char *carrier, size_t len,
			ZclHeader *h);

/*	*	*	Compressor	*	*	*	*	*/

typedef struct
{
	void		*cctx;		/*	ZSTD_CCtx		*/
	uint64_t	streamId;
	uint64_t	chunkId;
	uint32_t	seq;
	int		inChunk;	/*	frame begun		*/
	uint64_t	chunkIn;	/*	bytes in this chunk	*/
	uint64_t	pendingIn;	/*	bytes since last carrier*/
	unsigned char	*out;		/*	header room + zstd data	*/
	size_t		outLen;
	size_t		outCap;
} ZclEnc;

extern int	zclEncInit(ZclEnc *enc, int level, int windowLog,
			uint64_t streamId);
extern void	zclEncFree(ZclEnc *enc);

/*	Appends one bundle to the open chunk as a record.  -1 on error,
 *	after which the chunk must be abandoned with zclEncAbort.	*/
extern int	zclEncAdd(ZclEnc *enc, const unsigned char *bundle,
			size_t len);

/*	Cuts a carrier from everything added since the last one; with
 *	'endChunk' the chunk ends with it.  On 1 the carrier is in
 *	*carrier (malloc'd, the caller frees it); 0 means there was
 *	nothing to cut; -1 is an error (abandon the chunk).		*/
extern int	zclEncCut(ZclEnc *enc, int endChunk,
			unsigned char **carrier, size_t *len);

/*	Drops the open chunk; what is added next starts a new one.	*/
extern void	zclEncAbort(ZclEnc *enc);

/*	*	*	Receiver	*	*	*	*	*/

typedef int	(*ZclEmitFn)(void *ctx, const unsigned char *bundle,
			size_t len);

typedef struct
{
	size_t		maxBundle;	/*	record length		*/
	uint64_t	maxChunkOut;	/*	decompressed per chunk	*/
	unsigned int	reorderMs;	/*	gap patience		*/
	unsigned int	maxCarriers;	/*	reorder buffer, count	*/
	size_t		maxBufBytes;	/*	reorder buffer, bytes	*/
	int		windowLogMax;
	unsigned int	maxStreams;
} ZclRxLimits;

typedef struct
{
	uint64_t	carriersIn;
	uint64_t	carriersBad;	/*	header, CRC, size	*/
	uint64_t	carriersStale;	/*	old or duplicate	*/
	uint64_t	carriersDropped;/*	discarded undecoded	*/
	uint64_t	bytesIn;	/*	zstd bytes decoded	*/
	uint64_t	bundlesOut;
	uint64_t	bytesOut;
	uint64_t	emitFailed;
	uint64_t	chunksDone;
	uint64_t	chunksLost;	/*	gap not filled		*/
	uint64_t	chunksCorrupt;	/*	undecodable		*/
	uint64_t	streamsEvicted;
} ZclRxStats;

typedef struct ZclRx	ZclRx;

extern void	zclRxDefaults(ZclRxLimits *limits);
extern ZclRx	*zclRxNew(const ZclRxLimits *limits, ZclEmitFn emit,
			void *ctx);
extern void	zclRxFree(ZclRx *rx);

/*	Takes one received carrier; complete bundles are passed to the
 *	emit function before it returns.  -1 if the carrier was refused
 *	(malformed), else 0.						*/
extern int	zclRxCarrier(ZclRx *rx, const unsigned char *carrier,
			size_t len, uint64_t nowMs);

/*	Applies the reorder timeout; call it now and then.		*/
extern void	zclRxTick(ZclRx *rx, uint64_t nowMs);

extern void	zclRxGetStats(const ZclRx *rx, ZclRxStats *stats);

#ifdef __cplusplus
}
#endif

#endif /* ZCLCODEC_H */
