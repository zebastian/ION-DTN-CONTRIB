/*
	fuzz_msg.c:	fuzz target for the TCPCLv4 wire-message codec.

	Every decoder is run over the same input.  Whatever a decoder
	accepts must lie inside the input - the pointers it hands back
	into the buffer included - and must encode back to exactly the
	octets it consumed, so a decoder that reads past its input, or
	that accepts something it then misreports, is caught here rather
	than on a live session.  The extension-item walker is run over
	the input as a list in its own right as well.

	Built two ways: as a libFuzzer target (`make fuzz`), and against
	fuzz_replay.c to replay the checked-in corpus under `make check`.
									*/

#include <assert.h>
#include <string.h>
#include "tcpv4msg.h"

static uint8_t out[1 << 17];

/*	Walk an extension item list, checking each item stays inside it.	*/

static void walkExtItems(const uint8_t *list, size_t len)
{
	Tcpv4ExtItem item;
	size_t	     off = 0;
	size_t	     prev = 0;
	uint64_t     length;

	while (tcpv4MsgNextExtItem(list, len, &off, &item) == 1)
	{
		assert(off > prev && off <= len);
		assert(item.value + item.length <= list + len);
		prev = off;
	}

	(void) tcpv4MsgFindXferLength(list, len, &length);
}

/*	A decode result is -1 (malformed), 0 (need more) or the number of
 *	octets consumed, which cannot be more than there were.		*/

static void checkConsumed(int rc, size_t len)
{
	assert(rc >= -1 && (rc < 0 || (size_t) rc <= len));
}

static void checkReencoded(int encoded, int consumed, const uint8_t *in)
{
	assert(encoded == consumed);
	assert(memcmp(out, in, (size_t) consumed) == 0);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len)
{
	Tcpv4Contact	 contact;
	Tcpv4SessInit	 init;
	Tcpv4XferSegment seg;
	Tcpv4XferAck	 ack;
	Tcpv4XferRefuse	 refuse;
	Tcpv4SessTerm	 term;
	Tcpv4MsgReject	 reject;
	int		 rc;

	rc = tcpv4MsgDecodeContact(data, len, &contact);
	checkConsumed(rc, len);
	if (rc > 0)
	{
		checkReencoded(tcpv4MsgEncodeContact(out, sizeof(out),
				&contact), rc, data);
	}

	rc = tcpv4MsgDecodeSessInit(data, len, &init);
	checkConsumed(rc, len);
	if (rc > 0)
	{
		if (init.nodeIdLen > 0)
		{
			assert(init.nodeId >= data
				&& init.nodeId + init.nodeIdLen <= data + len);
		}

		if (init.sessExtLen > 0)
		{
			assert(init.sessExt >= data
				&& init.sessExt + init.sessExtLen <= data + len);
			walkExtItems(init.sessExt, init.sessExtLen);
		}

		checkReencoded(tcpv4MsgEncodeSessInit(out, sizeof(out),
				&init), rc, data);
	}

	rc = tcpv4MsgDecodeXferSegmentHdr(data, len, &seg);
	checkConsumed(rc, len);
	if (rc > 0)
	{
		if (seg.xferExtLen > 0)
		{
			assert(seg.xferExt >= data
				&& seg.xferExt + seg.xferExtLen <= data + len);
			walkExtItems(seg.xferExt, seg.xferExtLen);
		}

		checkReencoded(tcpv4MsgEncodeXferSegmentHdr(out, sizeof(out),
				&seg), rc, data);
	}

	rc = tcpv4MsgDecodeXferAck(data, len, &ack);
	checkConsumed(rc, len);
	if (rc > 0)
	{
		checkReencoded(tcpv4MsgEncodeXferAck(out, sizeof(out), &ack),
				rc, data);
	}

	rc = tcpv4MsgDecodeXferRefuse(data, len, &refuse);
	checkConsumed(rc, len);
	if (rc > 0)
	{
		checkReencoded(tcpv4MsgEncodeXferRefuse(out, sizeof(out),
				&refuse), rc, data);
	}

	rc = tcpv4MsgDecodeSessTerm(data, len, &term);
	checkConsumed(rc, len);
	if (rc > 0)
	{
		checkReencoded(tcpv4MsgEncodeSessTerm(out, sizeof(out), &term),
				rc, data);
	}

	rc = tcpv4MsgDecodeMsgReject(data, len, &reject);
	checkConsumed(rc, len);
	if (rc > 0)
	{
		checkReencoded(tcpv4MsgEncodeMsgReject(out, sizeof(out),
				&reject), rc, data);
	}

	walkExtItems(data, len);
	return 0;
}
