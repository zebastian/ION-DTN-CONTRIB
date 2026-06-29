/*
	quicmsg.c:	QUICCL wire-message codec (see quicmsg.h).
									*/

#include "quicmsg.h"
#include <string.h>

/*	*	*	Big-endian writer	*	*	*	*/

typedef struct
{
	uint8_t *buf;
	size_t	 cap;
	size_t	 len;
	int	 ok;
} Writer;

static void wInit(Writer *w, uint8_t *buf, size_t cap)
{
	w->buf = buf;
	w->cap = cap;
	w->len = 0;
	w->ok = 1;
}

static void wU8(Writer *w, uint8_t v)
{
	if (!w->ok || w->len + 1 > w->cap)
	{
		w->ok = 0;
		return;
	}

	w->buf[w->len++] = v;
}

static void wU16(Writer *w, uint16_t v)
{
	wU8(w, (uint8_t) (v >> 8));
	wU8(w, (uint8_t) v);
}

static void wU32(Writer *w, uint32_t v)
{
	wU16(w, (uint16_t) (v >> 16));
	wU16(w, (uint16_t) v);
}

static void wU64(Writer *w, uint64_t v)
{
	wU32(w, (uint32_t) (v >> 32));
	wU32(w, (uint32_t) v);
}

static void wBytes(Writer *w, const uint8_t *p, size_t n)
{
	if (!w->ok || w->len + n > w->cap)
	{
		w->ok = 0;
		return;
	}

	if (n > 0)
	{
		memcpy(w->buf + w->len, p, n);
		w->len += n;
	}
}

/*	*	*	Big-endian reader	*	*	*	*/

typedef struct
{
	const uint8_t *buf;
	size_t	       len;
	size_t	       off;
	int	       ok; /* 0 once an underflow occurs (need more).	*/
} Reader;

static void rInit(Reader *r, const uint8_t *buf, size_t len)
{
	r->buf = buf;
	r->len = len;
	r->off = 0;
	r->ok = 1;
}

static uint8_t rU8(Reader *r)
{
	if (!r->ok || r->off + 1 > r->len)
	{
		r->ok = 0;
		return 0;
	}

	return r->buf[r->off++];
}

static uint16_t rU16(Reader *r)
{
	uint16_t hi = rU8(r);

	return (uint16_t) ((hi << 8) | rU8(r));
}

static uint32_t rU32(Reader *r)
{
	uint32_t hi = rU16(r);

	return (hi << 16) | rU16(r);
}

static uint64_t rU64(Reader *r)
{
	uint64_t hi = rU32(r);

	return (hi << 32) | rU32(r);
}

/*	Reference len octets at the current offset without copying.
 *	Returns NULL (and marks underflow) if fewer than len remain.	*/
static const uint8_t *rBytes(Reader *r, size_t len)
{
	const uint8_t *p;

	if (!r->ok || r->off + len > r->len)
	{
		r->ok = 0;
		return NULL;
	}

	p = r->buf + r->off;
	r->off += len;
	return p;
}

/*	*	*	Common	*	*	*	*	*	*/

int quicMsgType(const uint8_t *buf, size_t len)
{
	return len == 0 ? -1 : buf[0];
}

/*	*	*	SESS_INIT	*	*	*	*	*/

int quicMsgEncodeSessInit(uint8_t *buf, size_t cap, const QuicSessInit *m)
{
	Writer w;

	wInit(&w, buf, cap);
	wU8(&w, QMSG_SESS_INIT);
	wU16(&w, m->keepalive);
	wU64(&w, m->segmentMru);
	wU64(&w, m->datagramMru);
	wU64(&w, m->transferMru);
	wU16(&w, m->nodeIdLen);
	wBytes(&w, m->nodeId, m->nodeIdLen);
	wU32(&w, m->sessExtLen);
	wBytes(&w, m->sessExt, m->sessExtLen);
	return w.ok ? (int) w.len : -1;
}

int quicMsgDecodeSessInit(const uint8_t *buf, size_t len, QuicSessInit *m)
{
	Reader r;

	rInit(&r, buf, len);
	if (rU8(&r) != QMSG_SESS_INIT)
	{
		return r.ok ? -1 : 0;
	}

	memset(m, 0, sizeof(*m));
	m->keepalive = rU16(&r);
	m->segmentMru = rU64(&r);
	m->datagramMru = rU64(&r);
	m->transferMru = rU64(&r);
	m->nodeIdLen = rU16(&r);
	m->nodeId = rBytes(&r, m->nodeIdLen);
	m->sessExtLen = rU32(&r);
	m->sessExt = rBytes(&r, m->sessExtLen);
	if (!r.ok)
	{
		return 0; /* Need more octets.			*/
	}

	return (int) r.off;
}

/*	*	*	XFER_SEGMENT (header only)	*	*	*/

int quicMsgEncodeXferSegmentHdr(uint8_t *buf, size_t cap,
		const QuicXferSegment *m)
{
	Writer w;

	wInit(&w, buf, cap);
	wU8(&w, QMSG_XFER_SEGMENT);
	wU8(&w, m->flags);
	wU16(&w, m->segmentId);
	wU16(&w, m->totalSegments);
	wU64(&w, m->transferId);
	if (m->flags & QMSG_FLAG_START)
	{
		wU32(&w, m->xferExtLen);
		wBytes(&w, m->xferExt, m->xferExtLen);
	}

	wU64(&w, m->segmentLength);
	wU64(&w, m->bundleLength);
	wU8(&w, m->serviceMode);
	return w.ok ? (int) w.len : -1;
}

int quicMsgDecodeXferSegmentHdr(const uint8_t *buf, size_t len,
		QuicXferSegment *m)
{
	Reader r;

	rInit(&r, buf, len);
	if (rU8(&r) != QMSG_XFER_SEGMENT)
	{
		return r.ok ? -1 : 0;
	}

	memset(m, 0, sizeof(*m));
	m->flags = rU8(&r);
	m->segmentId = rU16(&r);
	m->totalSegments = rU16(&r);
	m->transferId = rU64(&r);
	if (m->flags & QMSG_FLAG_START)
	{
		m->xferExtLen = rU32(&r);
		m->xferExt = rBytes(&r, m->xferExtLen);
	}

	m->segmentLength = rU64(&r);
	m->bundleLength = rU64(&r);
	m->serviceMode = rU8(&r);
	if (!r.ok)
	{
		return 0;
	}

	return (int) r.off;
}

/*	*	*	XFER_ACK	*	*	*	*	*/

int quicMsgEncodeXferAck(uint8_t *buf, size_t cap, const QuicXferAck *m)
{
	Writer w;

	wInit(&w, buf, cap);
	wU8(&w, QMSG_XFER_ACK);
	wU8(&w, m->flags);
	wU16(&w, m->segmentId);
	wU64(&w, m->transferId);
	wU64(&w, m->ackLength);
	return w.ok ? (int) w.len : -1;
}

int quicMsgDecodeXferAck(const uint8_t *buf, size_t len, QuicXferAck *m)
{
	Reader r;

	rInit(&r, buf, len);
	if (rU8(&r) != QMSG_XFER_ACK)
	{
		return r.ok ? -1 : 0;
	}

	memset(m, 0, sizeof(*m));
	m->flags = rU8(&r);
	m->segmentId = rU16(&r);
	m->transferId = rU64(&r);
	m->ackLength = rU64(&r);
	return r.ok ? (int) r.off : 0;
}

/*	*	*	XFER_REFUSE	*	*	*	*	*/

int quicMsgEncodeXferRefuse(uint8_t *buf, size_t cap, const QuicXferRefuse *m)
{
	Writer w;

	wInit(&w, buf, cap);
	wU8(&w, QMSG_XFER_REFUSE);
	wU8(&w, m->reason);
	wU64(&w, m->transferId);
	return w.ok ? (int) w.len : -1;
}

int quicMsgDecodeXferRefuse(const uint8_t *buf, size_t len, QuicXferRefuse *m)
{
	Reader r;

	rInit(&r, buf, len);
	if (rU8(&r) != QMSG_XFER_REFUSE)
	{
		return r.ok ? -1 : 0;
	}

	memset(m, 0, sizeof(*m));
	m->reason = rU8(&r);
	m->transferId = rU64(&r);
	return r.ok ? (int) r.off : 0;
}

/*	*	*	KEEPALIVE	*	*	*	*	*/

int quicMsgEncodeKeepalive(uint8_t *buf, size_t cap)
{
	Writer w;

	wInit(&w, buf, cap);
	wU8(&w, QMSG_KEEPALIVE);
	return w.ok ? (int) w.len : -1;
}

/*	*	*	SESS_TERM	*	*	*	*	*/

int quicMsgEncodeSessTerm(uint8_t *buf, size_t cap, const QuicSessTerm *m)
{
	Writer w;

	wInit(&w, buf, cap);
	wU8(&w, QMSG_SESS_TERM);
	wU8(&w, m->flags);
	wU8(&w, m->reason);
	return w.ok ? (int) w.len : -1;
}

int quicMsgDecodeSessTerm(const uint8_t *buf, size_t len, QuicSessTerm *m)
{
	Reader r;

	rInit(&r, buf, len);
	if (rU8(&r) != QMSG_SESS_TERM)
	{
		return r.ok ? -1 : 0;
	}

	memset(m, 0, sizeof(*m));
	m->flags = rU8(&r);
	m->reason = rU8(&r);
	return r.ok ? (int) r.off : 0;
}

/*	*	*	MSG_REJECT	*	*	*	*	*/

int quicMsgEncodeMsgReject(uint8_t *buf, size_t cap, const QuicMsgReject *m)
{
	Writer w;

	wInit(&w, buf, cap);
	wU8(&w, QMSG_MSG_REJECT);
	wU8(&w, m->reason);
	wU8(&w, m->rejectedType);
	return w.ok ? (int) w.len : -1;
}

int quicMsgDecodeMsgReject(const uint8_t *buf, size_t len, QuicMsgReject *m)
{
	Reader r;

	rInit(&r, buf, len);
	if (rU8(&r) != QMSG_MSG_REJECT)
	{
		return r.ok ? -1 : 0;
	}

	memset(m, 0, sizeof(*m));
	m->reason = rU8(&r);
	m->rejectedType = rU8(&r);
	return r.ok ? (int) r.off : 0;
}
