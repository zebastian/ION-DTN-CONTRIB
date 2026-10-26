/*
	fuzz_quicmsg.c:	fuzz target for the QUICCL wire-message codec.

	Every decoder is run over the same input.  Whatever a decoder
	accepts must lie inside the input - the pointers it hands back
	into the buffer included - and must encode back to exactly the
	octets it consumed, so a decoder that reads past its input, or
	that accepts something it then misreports, is caught here rather
	than on a live session.

	Built two ways: as a libFuzzer target (`make fuzz`), and against
	fuzz_replay.c to replay the checked-in corpus under `make check`.
									*/

#include <assert.h>
#include <string.h>
#include "quicmsg.h"

static uint8_t out[1 << 17];

/*	A decode result is -1 (malformed), 0 (need more) or the number of
 *	octets consumed, which cannot be more than there were.		*/

static void checkConsumed(int rc, size_t len)
{
	assert(rc >= -1 && (rc < 0 || (size_t) rc <= len));
}

static void checkInside(const uint8_t *field, size_t fieldLen,
		const uint8_t *data, size_t len)
{
	if (fieldLen > 0)
	{
		assert(field >= data && field + fieldLen <= data + len);
	}
}

static void checkReencoded(int encoded, int consumed, const uint8_t *in)
{
	assert(encoded == consumed);
	assert(memcmp(out, in, (size_t) consumed) == 0);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len)
{
	QuicSessInit	init;
	QuicXferSegment seg;
	QuicXferAck	ack;
	QuicXferRefuse	refuse;
	QuicSessTerm	term;
	QuicMsgReject	reject;
	int		rc;

	assert(quicMsgType(data, len) == (len > 0 ? data[0] : -1));

	rc = quicMsgDecodeSessInit(data, len, &init);
	checkConsumed(rc, len);
	if (rc > 0)
	{
		checkInside(init.nodeId, init.nodeIdLen, data, len);
		checkInside(init.sessExt, init.sessExtLen, data, len);
		checkReencoded(quicMsgEncodeSessInit(out, sizeof(out), &init),
				rc, data);
	}

	rc = quicMsgDecodeXferSegmentHdr(data, len, &seg);
	checkConsumed(rc, len);
	if (rc > 0)
	{
		checkInside(seg.xferExt, seg.xferExtLen, data, len);
		checkReencoded(quicMsgEncodeXferSegmentHdr(out, sizeof(out),
				&seg), rc, data);
	}

	rc = quicMsgDecodeXferAck(data, len, &ack);
	checkConsumed(rc, len);
	if (rc > 0)
	{
		checkReencoded(quicMsgEncodeXferAck(out, sizeof(out), &ack),
				rc, data);
	}

	rc = quicMsgDecodeXferRefuse(data, len, &refuse);
	checkConsumed(rc, len);
	if (rc > 0)
	{
		checkReencoded(quicMsgEncodeXferRefuse(out, sizeof(out),
				&refuse), rc, data);
	}

	rc = quicMsgDecodeSessTerm(data, len, &term);
	checkConsumed(rc, len);
	if (rc > 0)
	{
		checkInside(term.sessExt, term.sessExtLen, data, len);
		checkReencoded(quicMsgEncodeSessTerm(out, sizeof(out), &term),
				rc, data);
	}

	rc = quicMsgDecodeMsgReject(data, len, &reject);
	checkConsumed(rc, len);
	if (rc > 0)
	{
		checkReencoded(quicMsgEncodeMsgReject(out, sizeof(out),
				&reject), rc, data);
	}

	return 0;
}
