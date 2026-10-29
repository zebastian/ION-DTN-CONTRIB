/*	zclcodec.c:	wire format, compressor and receive state machine
			of the zcl compressing tunnel CLA.		*/

#include "zclcodec.h"

#include <stdlib.h>
#include <string.h>
#include <zstd.h>

static const unsigned char	zclMagic[4] = { 0x5a, 0x43, 0x4c, 0x01 };

/*	*	*	CRC-32C (Castagnoli), reflected	*	*	*/

static const uint32_t	crcTable[256] =
{
	0x00000000, 0xf26b8303, 0xe13b70f7, 0x1350f3f4,
	0xc79a971f, 0x35f1141c, 0x26a1e7e8, 0xd4ca64eb,
	0x8ad958cf, 0x78b2dbcc, 0x6be22838, 0x9989ab3b,
	0x4d43cfd0, 0xbf284cd3, 0xac78bf27, 0x5e133c24,
	0x105ec76f, 0xe235446c, 0xf165b798, 0x030e349b,
	0xd7c45070, 0x25afd373, 0x36ff2087, 0xc494a384,
	0x9a879fa0, 0x68ec1ca3, 0x7bbcef57, 0x89d76c54,
	0x5d1d08bf, 0xaf768bbc, 0xbc267848, 0x4e4dfb4b,
	0x20bd8ede, 0xd2d60ddd, 0xc186fe29, 0x33ed7d2a,
	0xe72719c1, 0x154c9ac2, 0x061c6936, 0xf477ea35,
	0xaa64d611, 0x580f5512, 0x4b5fa6e6, 0xb93425e5,
	0x6dfe410e, 0x9f95c20d, 0x8cc531f9, 0x7eaeb2fa,
	0x30e349b1, 0xc288cab2, 0xd1d83946, 0x23b3ba45,
	0xf779deae, 0x05125dad, 0x1642ae59, 0xe4292d5a,
	0xba3a117e, 0x4851927d, 0x5b016189, 0xa96ae28a,
	0x7da08661, 0x8fcb0562, 0x9c9bf696, 0x6ef07595,
	0x417b1dbc, 0xb3109ebf, 0xa0406d4b, 0x522bee48,
	0x86e18aa3, 0x748a09a0, 0x67dafa54, 0x95b17957,
	0xcba24573, 0x39c9c670, 0x2a993584, 0xd8f2b687,
	0x0c38d26c, 0xfe53516f, 0xed03a29b, 0x1f682198,
	0x5125dad3, 0xa34e59d0, 0xb01eaa24, 0x42752927,
	0x96bf4dcc, 0x64d4cecf, 0x77843d3b, 0x85efbe38,
	0xdbfc821c, 0x2997011f, 0x3ac7f2eb, 0xc8ac71e8,
	0x1c661503, 0xee0d9600, 0xfd5d65f4, 0x0f36e6f7,
	0x61c69362, 0x93ad1061, 0x80fde395, 0x72966096,
	0xa65c047d, 0x5437877e, 0x4767748a, 0xb50cf789,
	0xeb1fcbad, 0x197448ae, 0x0a24bb5a, 0xf84f3859,
	0x2c855cb2, 0xdeeedfb1, 0xcdbe2c45, 0x3fd5af46,
	0x7198540d, 0x83f3d70e, 0x90a324fa, 0x62c8a7f9,
	0xb602c312, 0x44694011, 0x5739b3e5, 0xa55230e6,
	0xfb410cc2, 0x092a8fc1, 0x1a7a7c35, 0xe811ff36,
	0x3cdb9bdd, 0xceb018de, 0xdde0eb2a, 0x2f8b6829,
	0x82f63b78, 0x709db87b, 0x63cd4b8f, 0x91a6c88c,
	0x456cac67, 0xb7072f64, 0xa457dc90, 0x563c5f93,
	0x082f63b7, 0xfa44e0b4, 0xe9141340, 0x1b7f9043,
	0xcfb5f4a8, 0x3dde77ab, 0x2e8e845f, 0xdce5075c,
	0x92a8fc17, 0x60c37f14, 0x73938ce0, 0x81f80fe3,
	0x55326b08, 0xa759e80b, 0xb4091bff, 0x466298fc,
	0x1871a4d8, 0xea1a27db, 0xf94ad42f, 0x0b21572c,
	0xdfeb33c7, 0x2d80b0c4, 0x3ed04330, 0xccbbc033,
	0xa24bb5a6, 0x502036a5, 0x4370c551, 0xb11b4652,
	0x65d122b9, 0x97baa1ba, 0x84ea524e, 0x7681d14d,
	0x2892ed69, 0xdaf96e6a, 0xc9a99d9e, 0x3bc21e9d,
	0xef087a76, 0x1d63f975, 0x0e330a81, 0xfc588982,
	0xb21572c9, 0x407ef1ca, 0x532e023e, 0xa145813d,
	0x758fe5d6, 0x87e466d5, 0x94b49521, 0x66df1622,
	0x38cc2a06, 0xcaa7a905, 0xd9f75af1, 0x2b9cd9f2,
	0xff56bd19, 0x0d3d3e1a, 0x1e6dcdee, 0xec064eed,
	0xc38d26c4, 0x31e6a5c7, 0x22b65633, 0xd0ddd530,
	0x0417b1db, 0xf67c32d8, 0xe52cc12c, 0x1747422f,
	0x49547e0b, 0xbb3ffd08, 0xa86f0efc, 0x5a048dff,
	0x8ecee914, 0x7ca56a17, 0x6ff599e3, 0x9d9e1ae0,
	0xd3d3e1ab, 0x21b862a8, 0x32e8915c, 0xc083125f,
	0x144976b4, 0xe622f5b7, 0xf5720643, 0x07198540,
	0x590ab964, 0xab613a67, 0xb831c993, 0x4a5a4a90,
	0x9e902e7b, 0x6cfbad78, 0x7fab5e8c, 0x8dc0dd8f,
	0xe330a81a, 0x115b2b19, 0x020bd8ed, 0xf0605bee,
	0x24aa3f05, 0xd6c1bc06, 0xc5914ff2, 0x37faccf1,
	0x69e9f0d5, 0x9b8273d6, 0x88d28022, 0x7ab90321,
	0xae7367ca, 0x5c18e4c9, 0x4f48173d, 0xbd23943e,
	0xf36e6f75, 0x0105ec76, 0x12551f82, 0xe03e9c81,
	0x34f4f86a, 0xc69f7b69, 0xd5cf889d, 0x27a40b9e,
	0x79b737ba, 0x8bdcb4b9, 0x988c474d, 0x6ae7c44e,
	0xbe2da0a5, 0x4c4623a6, 0x5f16d052, 0xad7d5351
};

uint32_t	zclCrc32c(uint32_t crc, const unsigned char *data, size_t len)
{
	crc = ~crc;
	while (len-- > 0)
	{
		crc = crcTable[(crc ^ *data++) & 0xff] ^ (crc >> 8);
	}

	return ~crc;
}

/*	*	*	Header	*	*	*	*	*	*/

static void	put32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char) (v >> 24);
	p[1] = (unsigned char) (v >> 16);
	p[2] = (unsigned char) (v >> 8);
	p[3] = (unsigned char) v;
}

static void	put64(unsigned char *p, uint64_t v)
{
	put32(p, (uint32_t) (v >> 32));
	put32(p + 4, (uint32_t) v);
}

static uint32_t	get32(const unsigned char *p)
{
	return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
		| ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

static uint64_t	get64(const unsigned char *p)
{
	return ((uint64_t) get32(p) << 32) | get32(p + 4);
}

void	zclHeaderPut(unsigned char *out, const ZclHeader *h,
		const unsigned char *payload)
{
	uint32_t	crc;

	memcpy(out, zclMagic, 4);
	out[4] = h->flags;
	out[5] = out[6] = out[7] = 0;
	put64(out + 8, h->streamId);
	put64(out + 16, h->chunkId);
	put32(out + 24, h->seq);
	put32(out + 28, h->length);
	crc = zclCrc32c(0, out, 32);
	crc = zclCrc32c(crc, payload, h->length);
	put32(out + 32, crc);
}

int	zclHeaderGet(const unsigned char *carrier, size_t len, ZclHeader *h)
{
	uint32_t	crc;

	if (len < ZCL_HDR_LEN || len - ZCL_HDR_LEN > ZCL_MAX_CARRIER
	|| memcmp(carrier, zclMagic, 4) != 0
	|| (carrier[4] & ~ZCL_FLAG_END) != 0
	|| carrier[5] != 0 || carrier[6] != 0 || carrier[7] != 0)
	{
		return -1;
	}

	h->flags = carrier[4];
	h->streamId = get64(carrier + 8);
	h->chunkId = get64(carrier + 16);
	h->seq = get32(carrier + 24);
	h->length = get32(carrier + 28);
	if (h->length != len - ZCL_HDR_LEN)
	{
		return -1;
	}

	crc = zclCrc32c(0, carrier, 32);
	crc = zclCrc32c(crc, carrier + ZCL_HDR_LEN, h->length);
	return crc == get32(carrier + 32) ? 0 : -1;
}

/*	*	*	Compressor	*	*	*	*	*/

int	zclEncInit(ZclEnc *enc, int level, int windowLog, uint64_t streamId)
{
	ZSTD_CCtx	*cctx;

	memset(enc, 0, sizeof(ZclEnc));
	cctx = ZSTD_createCCtx();
	if (cctx == NULL)
	{
		return -1;
	}

	if (ZSTD_isError(ZSTD_CCtx_setParameter(cctx,
			ZSTD_c_compressionLevel, level))
	|| ZSTD_isError(ZSTD_CCtx_setParameter(cctx,
			ZSTD_c_checksumFlag, 1))
	|| (windowLog > 0 && ZSTD_isError(ZSTD_CCtx_setParameter(cctx,
			ZSTD_c_windowLog, windowLog))))
	{
		ZSTD_freeCCtx(cctx);
		return -1;
	}

	enc->cctx = cctx;
	enc->streamId = streamId;
	return 0;
}

void	zclEncFree(ZclEnc *enc)
{
	ZSTD_freeCCtx((ZSTD_CCtx *) enc->cctx);
	free(enc->out);
	memset(enc, 0, sizeof(ZclEnc));
}

static int	growOut(ZclEnc *enc, size_t want)
{
	size_t		cap = enc->outCap ? enc->outCap : 64 * 1024;
	unsigned char	*out;

	while (cap < want)
	{
		cap *= 2;
	}

	if (cap == enc->outCap)
	{
		return 0;
	}

	out = realloc(enc->out, cap);
	if (out == NULL)
	{
		return -1;
	}

	enc->out = out;
	enc->outCap = cap;
	return 0;
}

/*	Runs the compressor over 'data' with 'directive', appending what
 *	it emits behind the header room.  For flush and end it runs until
 *	zstd reports nothing left to emit.				*/
static int	compress(ZclEnc *enc, const void *data, size_t len,
			ZSTD_EndDirective directive)
{
	ZSTD_inBuffer	in = { data, len, 0 };
	ZSTD_outBuffer	out;
	size_t		ret;

	if (enc->out == NULL)
	{
		if (growOut(enc, ZCL_HDR_LEN + ZSTD_CStreamOutSize()) < 0)
		{
			return -1;
		}

		enc->outLen = ZCL_HDR_LEN;
	}

	while (1)
	{
		if (enc->outCap - enc->outLen < ZSTD_CStreamOutSize()
		&& growOut(enc, enc->outLen + ZSTD_CStreamOutSize()) < 0)
		{
			return -1;
		}

		out.dst = enc->out;
		out.size = enc->outCap;
		out.pos = enc->outLen;
		ret = ZSTD_compressStream2((ZSTD_CCtx *) enc->cctx, &out, &in,
				directive);
		enc->outLen = out.pos;
		if (ZSTD_isError(ret))
		{
			return -1;
		}

		if (directive == ZSTD_e_continue ? in.pos == in.size : ret == 0)
		{
			return 0;
		}
	}
}

int	zclEncAdd(ZclEnc *enc, const unsigned char *bundle, size_t len)
{
	unsigned char	recHdr[ZCL_REC_HDR_LEN];

	if (len == 0 || len > 0xffffffffu)
	{
		return -1;
	}

	put32(recHdr, (uint32_t) len);
	if (compress(enc, recHdr, sizeof recHdr, ZSTD_e_continue) < 0
	|| compress(enc, bundle, len, ZSTD_e_continue) < 0)
	{
		return -1;
	}

	enc->inChunk = 1;
	enc->chunkIn += len;
	enc->pendingIn += len;
	return 0;
}

int	zclEncCut(ZclEnc *enc, int endChunk, unsigned char **carrier,
		size_t *len)
{
	ZclHeader	h;

	if (!enc->inChunk || (enc->pendingIn == 0 && !endChunk))
	{
		return 0;
	}

	if (compress(enc, NULL, 0, endChunk ? ZSTD_e_end : ZSTD_e_flush) < 0)
	{
		return -1;
	}

	if (enc->outLen - ZCL_HDR_LEN > ZCL_MAX_CARRIER)
	{
		return -1;	/*	The receiver would refuse it.	*/
	}

	h.flags = endChunk ? ZCL_FLAG_END : 0;
	h.streamId = enc->streamId;
	h.chunkId = enc->chunkId;
	h.seq = enc->seq;
	h.length = (uint32_t) (enc->outLen - ZCL_HDR_LEN);
	zclHeaderPut(enc->out, &h, enc->out + ZCL_HDR_LEN);
	*carrier = enc->out;
	*len = enc->outLen;
	enc->out = NULL;
	enc->outLen = enc->outCap = 0;
	enc->pendingIn = 0;
	enc->seq++;
	if (endChunk)
	{
		enc->chunkId++;
		enc->seq = 0;
		enc->inChunk = 0;
		enc->chunkIn = 0;
	}

	return 1;
}

void	zclEncAbort(ZclEnc *enc)
{
	ZSTD_CCtx_reset((ZSTD_CCtx *) enc->cctx, ZSTD_reset_session_only);
	free(enc->out);
	enc->out = NULL;
	enc->outLen = enc->outCap = 0;

	/*	A chunk nothing was sent of may keep its number; one that
	 *	is partly out must not be continued under it.		*/

	if (enc->seq > 0)
	{
		enc->chunkId++;
	}

	enc->seq = 0;
	enc->inChunk = 0;
	enc->chunkIn = 0;
	enc->pendingIn = 0;
}

/*	*	*	Receiver	*	*	*	*	*/

typedef struct pending
{
	struct pending	*next;
	uint64_t	chunk;
	uint32_t	seq;
	int		end;
	uint64_t	at;		/*	arrival, ms		*/
	size_t		len;
	unsigned char	data[];
} Pending;

typedef struct
{
	int		used;
	uint64_t	id;
	uint64_t	lastUse;

	int		synced;
	uint64_t	cur;		/*	chunk being decoded	*/
	uint32_t	next;		/*	seq expected next	*/
	int		haveDone;
	uint64_t	done;		/*	chunks <= done are over	*/

	ZSTD_DCtx	*dctx;
	int		frameDone;
	uint64_t	chunkOut;

	unsigned char	lenBuf[ZCL_REC_HDR_LEN];
	unsigned int	lenHave;
	size_t		recLen;
	unsigned char	*rec;
	size_t		recHave;
	size_t		recCap;

	Pending		*buf;		/*	sorted by (chunk, seq)	*/
	unsigned int	bufCount;
	size_t		bufBytes;
} ZclStream;

struct ZclRx
{
	ZclRxLimits	limits;
	ZclEmitFn	emit;
	void		*ctx;
	ZclStream	*streams;
	uint64_t	useClock;
	unsigned char	*tmp;
	size_t		tmpLen;
	ZclRxStats	stats;
};

void	zclRxDefaults(ZclRxLimits *limits)
{
	limits->maxBundle = 64 * 1024 * 1024;
	limits->maxChunkOut = (uint64_t) 1024 * 1024 * 1024;
	limits->reorderMs = 10000;
	limits->maxCarriers = 4096;
	limits->maxBufBytes = 64 * 1024 * 1024;
	limits->windowLogMax = ZCL_DEFAULT_WINDOWLOG;
	limits->maxStreams = 16;
}

ZclRx	*zclRxNew(const ZclRxLimits *limits, ZclEmitFn emit, void *ctx)
{
	ZclRx	*rx;

	if (limits->maxStreams == 0 || limits->maxBundle == 0)
	{
		return NULL;
	}

	rx = calloc(1, sizeof(ZclRx));
	if (rx == NULL)
	{
		return NULL;
	}

	rx->limits = *limits;
	rx->emit = emit;
	rx->ctx = ctx;
	rx->tmpLen = ZSTD_DStreamOutSize();
	rx->tmp = malloc(rx->tmpLen);
	rx->streams = calloc(limits->maxStreams, sizeof(ZclStream));
	if (rx->tmp == NULL || rx->streams == NULL)
	{
		free(rx->tmp);
		free(rx->streams);
		free(rx);
		return NULL;
	}

	return rx;
}

static void	dropPending(ZclRx *rx, ZclStream *s, Pending **link)
{
	Pending	*p = *link;

	*link = p->next;
	s->bufCount--;
	s->bufBytes -= p->len;
	free(p);
	rx->stats.carriersDropped++;
}

/*	Drops the buffered carriers of chunks below 'chunk'.		*/
static void	dropBelow(ZclRx *rx, ZclStream *s, uint64_t chunk)
{
	while (s->buf && s->buf->chunk < chunk)
	{
		dropPending(rx, s, &s->buf);
	}
}

static void	resetChunk(ZclStream *s)
{
	ZSTD_DCtx_reset(s->dctx, ZSTD_reset_session_only);
	s->frameDone = 0;
	s->chunkOut = 0;
	s->lenHave = 0;
	s->recLen = 0;
	s->recHave = 0;
	if (s->recCap > 1024 * 1024)
	{
		free(s->rec);
		s->rec = NULL;
		s->recCap = 0;
	}
}

static void	freeStream(ZclStream *s)
{
	while (s->buf)
	{
		Pending	*p = s->buf;

		s->buf = p->next;
		free(p);
	}

	ZSTD_freeDCtx(s->dctx);
	free(s->rec);
	memset(s, 0, sizeof(ZclStream));
}

void	zclRxFree(ZclRx *rx)
{
	unsigned int	i;

	if (rx == NULL)
	{
		return;
	}

	for (i = 0; i < rx->limits.maxStreams; i++)
	{
		freeStream(&rx->streams[i]);
	}

	free(rx->streams);
	free(rx->tmp);
	free(rx);
}

void	zclRxGetStats(const ZclRx *rx, ZclRxStats *stats)
{
	*stats = rx->stats;
}

static ZclStream	*findStream(ZclRx *rx, uint64_t id)
{
	ZclStream	*s;
	ZclStream	*victim = NULL;
	unsigned int	i;

	for (i = 0; i < rx->limits.maxStreams; i++)
	{
		s = &rx->streams[i];
		if (s->used && s->id == id)
		{
			s->lastUse = ++rx->useClock;
			return s;
		}

		if (victim == NULL || !s->used
		|| (victim->used && s->lastUse < victim->lastUse))
		{
			victim = s;
		}
	}

	if (victim->used)
	{
		rx->stats.carriersDropped += victim->bufCount;
		freeStream(victim);
		rx->stats.streamsEvicted++;
	}

	victim->dctx = ZSTD_createDCtx();
	if (victim->dctx == NULL
	|| ZSTD_isError(ZSTD_DCtx_setParameter(victim->dctx,
			ZSTD_d_windowLogMax, rx->limits.windowLogMax)))
	{
		ZSTD_freeDCtx(victim->dctx);
		victim->dctx = NULL;
		return NULL;
	}

	victim->used = 1;
	victim->id = id;
	victim->lastUse = ++rx->useClock;
	return victim;
}

/*	Takes decompressed bytes into records; complete ones are emitted.
 *	-1 if the chunk is corrupt.					*/
static int	takeRecords(ZclRx *rx, ZclStream *s, const unsigned char *data,
			size_t len)
{
	size_t	take;

	if (len > rx->limits.maxChunkOut - s->chunkOut)
	{
		return -1;
	}

	s->chunkOut += len;
	while (len > 0)
	{
		if (s->lenHave < ZCL_REC_HDR_LEN)
		{
			s->lenBuf[s->lenHave++] = *data++;
			len--;
			if (s->lenHave == ZCL_REC_HDR_LEN)
			{
				s->recLen = get32(s->lenBuf);
				s->recHave = 0;
				if (s->recLen == 0
				|| s->recLen > rx->limits.maxBundle)
				{
					return -1;
				}
			}

			continue;
		}

		take = s->recLen - s->recHave;
		if (take > len)
		{
			take = len;
		}

		/*	Grow with the data, not with the claimed length,
		 *	so a header alone cannot make us allocate.	*/

		if (s->recHave + take > s->recCap)
		{
			size_t		cap = s->recCap ? s->recCap : 4096;
			unsigned char	*rec;

			while (cap < s->recHave + take)
			{
				cap *= 2;
			}

			if (cap > s->recLen)
			{
				cap = s->recLen;
			}

			rec = realloc(s->rec, cap);
			if (rec == NULL)
			{
				return -1;
			}

			s->rec = rec;
			s->recCap = cap;
		}

		memcpy(s->rec + s->recHave, data, take);
		s->recHave += take;
		data += take;
		len -= take;
		if (s->recHave == s->recLen)
		{
			if (rx->emit(rx->ctx, s->rec, s->recLen) < 0)
			{
				rx->stats.emitFailed++;
			}
			else
			{
				rx->stats.bundlesOut++;
				rx->stats.bytesOut += s->recLen;
			}

			s->lenHave = 0;
			s->recLen = 0;
			s->recHave = 0;
		}
	}

	return 0;
}

/*	Decodes the next carrier of the current chunk.  -1 if the chunk
 *	is corrupt.							*/
static int	decodeCarrier(ZclRx *rx, ZclStream *s, const Pending *p)
{
	ZSTD_inBuffer	in = { p->data, p->len, 0 };
	ZSTD_outBuffer	out;
	size_t		ret;

	if (s->frameDone)
	{
		return -1;	/*	Data after the end of a frame.	*/
	}

	rx->stats.bytesIn += p->len;
	do
	{
		out.dst = rx->tmp;
		out.size = rx->tmpLen;
		out.pos = 0;
		ret = ZSTD_decompressStream(s->dctx, &out, &in);
		if (ZSTD_isError(ret)
		|| takeRecords(rx, s, rx->tmp, out.pos) < 0)
		{
			return -1;
		}

		if (ret == 0)
		{
			s->frameDone = 1;
			break;
		}
	} while (in.pos < in.size || out.pos == out.size);

	if (in.pos < in.size)
	{
		return -1;
	}

	if (p->end)
	{
		/*	The chunk must end on a frame and a record.	*/

		if (!s->frameDone || s->lenHave != 0)
		{
			return -1;
		}
	}
	else if (s->frameDone)
	{
		return -1;	/*	Frame ended before END.		*/
	}

	return 0;
}

/*	Ends the current chunk; what is buffered for it goes too.	*/
static void	endChunk(ZclRx *rx, ZclStream *s)
{
	s->synced = 0;
	s->haveDone = 1;
	s->done = s->cur;
	dropBelow(rx, s, s->cur + 1);
	resetChunk(s);
}

static void	syncTo(ZclRx *rx, ZclStream *s, uint64_t chunk)
{
	dropBelow(rx, s, chunk);
	s->synced = 1;
	s->cur = chunk;
	s->next = 0;
	resetChunk(s);
}

/*	Decodes everything that is next in line.			*/
static void	drain(ZclRx *rx, ZclStream *s)
{
	Pending	*p;

	while ((p = s->buf) != NULL)
	{
		if (!s->synced)
		{
			Pending	*start;

			/*	Start on chunk done+1 at once - on chunk 0
			 *	for a stream not seen before; any other
			 *	chunk start waits for the timeout, in case
			 *	the chunks between are still on the way.	*/

			for (start = s->buf; start; start = start->next)
			{
				if (start->seq == 0)
				{
					break;
				}
			}

			if (start == NULL || start->chunk
					!= (s->haveDone ? s->done + 1 : 0))
			{
				break;
			}

			syncTo(rx, s, start->chunk);
			continue;
		}

		if (p->chunk != s->cur || p->seq != s->next)
		{
			break;
		}

		s->buf = p->next;
		s->bufCount--;
		s->bufBytes -= p->len;
		if (decodeCarrier(rx, s, p) < 0)
		{
			rx->stats.chunksCorrupt++;
			endChunk(rx, s);
		}
		else if (p->end)
		{
			rx->stats.chunksDone++;
			endChunk(rx, s);
		}
		else
		{
			s->next++;
		}

		free(p);
	}
}

/*	Gives up waiting for what is missing at the head of the buffer.	*/
static void	resolveGap(ZclRx *rx, ZclStream *s)
{
	Pending	*p;

	if (s->synced)
	{
		rx->stats.chunksLost++;
		endChunk(rx, s);
		return;
	}

	for (p = s->buf; p; p = p->next)
	{
		if (p->seq == 0)
		{
			syncTo(rx, s, p->chunk);
			return;
		}
	}

	/*	No chunk start buffered: the lowest chunk's start is lost.	*/

	s->haveDone = 1;
	s->done = s->buf->chunk;
	dropBelow(rx, s, s->done + 1);
}

/*	Decodes what it can and gives up the gaps that have lasted.
 *	What is missing at a gap was sent before the carrier now at the
 *	head of the buffer, so the gap is given up once that carrier has
 *	waited the reorder timeout since it arrived.  Measuring each gap
 *	from the carrier behind it, not from when the receiver began to
 *	wait for it, lets gaps that queued up behind one another be given
 *	up together.							*/
static void	settle(ZclRx *rx, ZclStream *s, uint64_t nowMs)
{
	int	rounds;

	/*	Every round drains or drops something, so the bound is
	 *	only a guard.						*/

	for (rounds = 0; rounds < 1000000 && s->buf; rounds++)
	{
		drain(rx, s);
		if (s->buf == NULL)
		{
			break;
		}

		if (s->bufCount > rx->limits.maxCarriers
		|| s->bufBytes > rx->limits.maxBufBytes
		|| (nowMs >= s->buf->at
			&& nowMs - s->buf->at >= rx->limits.reorderMs))
		{
			resolveGap(rx, s);
			continue;
		}

		break;
	}
}

int	zclRxCarrier(ZclRx *rx, const unsigned char *carrier, size_t len,
		uint64_t nowMs)
{
	ZclHeader	h;
	ZclStream	*s;
	Pending		**link;
	Pending		*p;

	rx->stats.carriersIn++;
	if (zclHeaderGet(carrier, len, &h) < 0)
	{
		rx->stats.carriersBad++;
		return -1;
	}

	s = findStream(rx, h.streamId);
	if (s == NULL)
	{
		rx->stats.carriersDropped++;
		return 0;
	}

	if ((s->haveDone && h.chunkId <= s->done)
	|| (s->synced && h.chunkId == s->cur && h.seq < s->next)
	|| (s->synced && h.chunkId < s->cur))
	{
		rx->stats.carriersStale++;
		return 0;
	}

	for (link = &s->buf; *link; link = &(*link)->next)
	{
		if ((*link)->chunk > h.chunkId
		|| ((*link)->chunk == h.chunkId && (*link)->seq >= h.seq))
		{
			break;
		}
	}

	if (*link && (*link)->chunk == h.chunkId && (*link)->seq == h.seq)
	{
		rx->stats.carriersStale++;
		return 0;
	}

	p = malloc(sizeof(Pending) + h.length);
	if (p == NULL)
	{
		rx->stats.carriersDropped++;
		return 0;
	}

	p->chunk = h.chunkId;
	p->seq = h.seq;
	p->end = (h.flags & ZCL_FLAG_END) != 0;
	p->at = nowMs;
	p->len = h.length;
	memcpy(p->data, carrier + ZCL_HDR_LEN, h.length);
	p->next = *link;
	*link = p;
	s->bufCount++;
	s->bufBytes += p->len;
	settle(rx, s, nowMs);
	return 0;
}

void	zclRxTick(ZclRx *rx, uint64_t nowMs)
{
	unsigned int	i;

	for (i = 0; i < rx->limits.maxStreams; i++)
	{
		if (rx->streams[i].used)
		{
			settle(rx, &rx->streams[i], nowMs);
		}
	}
}
