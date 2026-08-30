/*
	tcpv4msg.c:	TCPCLv4 wire-message codec (see tcpv4msg.h).
									*/

#include "tcpv4msg.h"
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

	if (!r->ok || len > r->len - r->off)
	{
		r->ok = 0;
		return NULL;
	}

	p = r->buf + r->off;
	r->off += len;
	return p;
}

/*	*	*	Common	*	*	*	*	*	*/

int tcpv4MsgType(const uint8_t *buf, size_t len)
{
	return len == 0 ? -1 : buf[0];
}

/*	*	*	Contact header	*	*	*	*	*/

int tcpv4MsgEncodeContact(uint8_t *buf, size_t cap, const Tcpv4Contact *m)
{
	Writer w;

	wInit(&w, buf, cap);
	wBytes(&w, (const uint8_t *) TMSG_MAGIC, TMSG_MAGIC_LEN);
	wU8(&w, m->version);
	wU8(&w, m->flags);
	return w.ok ? (int) w.len : -1;
}

int tcpv4MsgDecodeContact(const uint8_t *buf, size_t len, Tcpv4Contact *m)
{
	Reader	       r;
	const uint8_t *magic;

	rInit(&r, buf, len);
	magic = rBytes(&r, TMSG_MAGIC_LEN);
	if (magic != NULL && memcmp(magic, TMSG_MAGIC, TMSG_MAGIC_LEN) != 0)
	{
		return -1; /* Not TCPCL at all; close the connection.	*/
	}

	memset(m, 0, sizeof(*m));
	m->version = rU8(&r);
	m->flags = rU8(&r);
	return r.ok ? (int) r.off : 0;
}

/*	*	*	SESS_INIT	*	*	*	*	*/

int tcpv4MsgEncodeSessInit(uint8_t *buf, size_t cap, const Tcpv4SessInit *m)
{
	Writer w;

	wInit(&w, buf, cap);
	wU8(&w, TMSG_SESS_INIT);
	wU16(&w, m->keepalive);
	wU64(&w, m->segmentMru);
	wU64(&w, m->transferMru);
	wU16(&w, m->nodeIdLen);
	wBytes(&w, m->nodeId, m->nodeIdLen);
	wU32(&w, m->sessExtLen);
	wBytes(&w, m->sessExt, m->sessExtLen);
	return w.ok ? (int) w.len : -1;
}

int tcpv4MsgDecodeSessInit(const uint8_t *buf, size_t len, Tcpv4SessInit *m)
{
	Reader r;

	rInit(&r, buf, len);
	if (rU8(&r) != TMSG_SESS_INIT)
	{
		return r.ok ? -1 : 0;
	}

	memset(m, 0, sizeof(*m));
	m->keepalive = rU16(&r);
	m->segmentMru = rU64(&r);
	m->transferMru = rU64(&r);
	m->nodeIdLen = rU16(&r);
	m->nodeId = rBytes(&r, m->nodeIdLen);
	m->sessExtLen = rU32(&r);
	m->sessExt = rBytes(&r, m->sessExtLen);
	if (!r.ok)
	{
		return 0; /* Need more octets.				*/
	}

	return (int) r.off;
}

/*	*	*	XFER_SEGMENT (header only)	*	*	*/

int tcpv4MsgEncodeXferSegmentHdr(uint8_t *buf, size_t cap,
		const Tcpv4XferSegment *m)
{
	Writer w;

	wInit(&w, buf, cap);
	wU8(&w, TMSG_XFER_SEGMENT);
	wU8(&w, m->flags);
	wU64(&w, m->transferId);
	if (m->flags & TMSG_FLAG_START)
	{
		wU32(&w, m->xferExtLen);
		wBytes(&w, m->xferExt, m->xferExtLen);
	}

	wU64(&w, m->dataLength);
	return w.ok ? (int) w.len : -1;
}

int tcpv4MsgDecodeXferSegmentHdr(const uint8_t *buf, size_t len,
		Tcpv4XferSegment *m)
{
	Reader r;

	rInit(&r, buf, len);
	if (rU8(&r) != TMSG_XFER_SEGMENT)
	{
		return r.ok ? -1 : 0;
	}

	memset(m, 0, sizeof(*m));
	m->flags = rU8(&r);
	m->transferId = rU64(&r);
	if (m->flags & TMSG_FLAG_START)
	{
		m->xferExtLen = rU32(&r);
		m->xferExt = rBytes(&r, m->xferExtLen);
	}

	m->dataLength = rU64(&r);
	if (!r.ok)
	{
		return 0;
	}

	return (int) r.off;
}

/*	*	*	XFER_ACK	*	*	*	*	*/

int tcpv4MsgEncodeXferAck(uint8_t *buf, size_t cap, const Tcpv4XferAck *m)
{
	Writer w;

	wInit(&w, buf, cap);
	wU8(&w, TMSG_XFER_ACK);
	wU8(&w, m->flags);
	wU64(&w, m->transferId);
	wU64(&w, m->ackLength);
	return w.ok ? (int) w.len : -1;
}

int tcpv4MsgDecodeXferAck(const uint8_t *buf, size_t len, Tcpv4XferAck *m)
{
	Reader r;

	rInit(&r, buf, len);
	if (rU8(&r) != TMSG_XFER_ACK)
	{
		return r.ok ? -1 : 0;
	}

	memset(m, 0, sizeof(*m));
	m->flags = rU8(&r);
	m->transferId = rU64(&r);
	m->ackLength = rU64(&r);
	return r.ok ? (int) r.off : 0;
}

/*	*	*	XFER_REFUSE	*	*	*	*	*/

int tcpv4MsgEncodeXferRefuse(uint8_t *buf, size_t cap, const Tcpv4XferRefuse *m)
{
	Writer w;

	wInit(&w, buf, cap);
	wU8(&w, TMSG_XFER_REFUSE);
	wU8(&w, m->reason);
	wU64(&w, m->transferId);
	return w.ok ? (int) w.len : -1;
}

int tcpv4MsgDecodeXferRefuse(const uint8_t *buf, size_t len, Tcpv4XferRefuse *m)
{
	Reader r;

	rInit(&r, buf, len);
	if (rU8(&r) != TMSG_XFER_REFUSE)
	{
		return r.ok ? -1 : 0;
	}

	memset(m, 0, sizeof(*m));
	m->reason = rU8(&r);
	m->transferId = rU64(&r);
	return r.ok ? (int) r.off : 0;
}

/*	*	*	KEEPALIVE	*	*	*	*	*/

int tcpv4MsgEncodeKeepalive(uint8_t *buf, size_t cap)
{
	Writer w;

	wInit(&w, buf, cap);
	wU8(&w, TMSG_KEEPALIVE);
	return w.ok ? (int) w.len : -1;
}

/*	*	*	SESS_TERM	*	*	*	*	*/

int tcpv4MsgEncodeSessTerm(uint8_t *buf, size_t cap, const Tcpv4SessTerm *m)
{
	Writer w;

	wInit(&w, buf, cap);
	wU8(&w, TMSG_SESS_TERM);
	wU8(&w, m->flags);
	wU8(&w, m->reason);
	return w.ok ? (int) w.len : -1;
}

int tcpv4MsgDecodeSessTerm(const uint8_t *buf, size_t len, Tcpv4SessTerm *m)
{
	Reader r;

	rInit(&r, buf, len);
	if (rU8(&r) != TMSG_SESS_TERM)
	{
		return r.ok ? -1 : 0;
	}

	memset(m, 0, sizeof(*m));
	m->flags = rU8(&r);
	m->reason = rU8(&r);
	return r.ok ? (int) r.off : 0;
}

/*	*	*	MSG_REJECT	*	*	*	*	*/

int tcpv4MsgEncodeMsgReject(uint8_t *buf, size_t cap, const Tcpv4MsgReject *m)
{
	Writer w;

	wInit(&w, buf, cap);
	wU8(&w, TMSG_MSG_REJECT);
	wU8(&w, m->reason);
	wU8(&w, m->rejectedType);
	return w.ok ? (int) w.len : -1;
}

int tcpv4MsgDecodeMsgReject(const uint8_t *buf, size_t len, Tcpv4MsgReject *m)
{
	Reader r;

	rInit(&r, buf, len);
	if (rU8(&r) != TMSG_MSG_REJECT)
	{
		return r.ok ? -1 : 0;
	}

	memset(m, 0, sizeof(*m));
	m->reason = rU8(&r);
	m->rejectedType = rU8(&r);
	return r.ok ? (int) r.off : 0;
}

/*	*	*	Extension items	*	*	*	*	*/

int tcpv4MsgNextExtItem(const uint8_t *buf, size_t len, size_t *off,
		Tcpv4ExtItem *item)
{
	Reader r;

	if (*off == len)
	{
		return 0; /* End of the list, exactly as declared.	*/
	}

	rInit(&r, buf, len);
	r.off = *off;
	memset(item, 0, sizeof(*item));
	item->flags = rU8(&r);
	item->type = rU16(&r);
	item->length = rU16(&r);
	item->value = rBytes(&r, item->length);
	if (!r.ok)
	{
		/*	The last item runs past the declared list length;
		 *	RFC 9174 4.8 makes that a reception failure.	*/

		return -1;
	}

	*off = r.off;
	return 1;
}
