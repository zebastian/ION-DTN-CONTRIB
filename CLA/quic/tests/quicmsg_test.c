/*
	quicmsg_test.c:	round-trip unit tests for the QUICCL codec.
			Built and run via `make check`.
									*/

#include <assert.h>
#include <string.h>
#include "quicmsg.h"

static uint8_t buf[512];

static void test_sess_init(void)
{
	const char  *nodeId = "ipn:1.0";
	QuicSessInit in;
	QuicSessInit out;
	int	     n;

	memset(&in, 0, sizeof(in));
	in.keepalive = 30;
	in.segmentMru = 65536;
	in.datagramMru = 1200;
	in.transferMru = 1000000;
	in.nodeId = (const uint8_t *) nodeId;
	in.nodeIdLen = (uint16_t) strlen(nodeId);

	n = quicMsgEncodeSessInit(buf, sizeof(buf), &in);
	assert(n > 0);
	assert(quicMsgType(buf, n) == QMSG_SESS_INIT);
	assert(quicMsgDecodeSessInit(buf, n, &out) == n);
	assert(out.keepalive == 30);
	assert(out.segmentMru == 65536);
	assert(out.datagramMru == 1200);
	assert(out.transferMru == 1000000);
	assert(out.nodeIdLen == in.nodeIdLen);
	assert(memcmp(out.nodeId, nodeId, out.nodeIdLen) == 0);
	assert(out.sessExtLen == 0);

	/*	A truncated buffer must report "need more" (0).		*/
	assert(quicMsgDecodeSessInit(buf, n - 1, &out) == 0);
}

static void test_xfer_segment(void)
{
	QuicXferSegment in;
	QuicXferSegment out;
	int		n;

	memset(&in, 0, sizeof(in));
	in.flags = QMSG_FLAG_START | QMSG_FLAG_END;
	in.segmentId = 1;
	in.totalSegments = 1;
	in.transferId = 0x1122334455667788ULL;
	in.segmentLength = 4096;
	in.bundleLength = 4096;
	in.serviceMode = QMSG_SVC_RELIABLE;

	n = quicMsgEncodeXferSegmentHdr(buf, sizeof(buf), &in);
	assert(n > 0);
	assert(quicMsgDecodeXferSegmentHdr(buf, n, &out) == n);
	assert(out.flags == in.flags);
	assert(out.segmentId == 1);
	assert(out.totalSegments == 1);
	assert(out.transferId == in.transferId);
	assert(out.xferExtLen == 0);
	assert(out.segmentLength == 4096);
	assert(out.bundleLength == 4096);
	assert(out.serviceMode == QMSG_SVC_RELIABLE);

	/*	Without START the 4-octet Transfer Extension Items Length
	 *	field is omitted, so the header is 4 octets shorter.	*/
	in.flags = QMSG_FLAG_END;
	assert(quicMsgEncodeXferSegmentHdr(buf, sizeof(buf), &in) == n - 4);
}

static void test_xfer_ack(void)
{
	QuicXferAck in = { QMSG_FLAG_END, 7, 0xABCDEF01ULL, 13371337ULL };
	QuicXferAck out;
	int	    n;

	n = quicMsgEncodeXferAck(buf, sizeof(buf), &in);
	assert(n > 0);
	assert(quicMsgDecodeXferAck(buf, n, &out) == n);
	assert(out.flags == QMSG_FLAG_END);
	assert(out.segmentId == 7);
	assert(out.transferId == 0xABCDEF01ULL);
	assert(out.ackLength == 13371337ULL);
}

static void test_small_messages(void)
{
	QuicXferRefuse refIn = { QMSG_REFUSE_NO_RESOURCES, 42 };
	QuicXferRefuse refOut;
	QuicSessTerm termIn = { QMSG_TERM_FLAG_REPLY, QMSG_TERM_UNKNOWN, NULL, 0 };
	QuicSessTerm  termOut;
	QuicMsgReject rejIn = { QMSG_KEEPALIVE, QMSG_REJECT_UNEXPECTED };
	QuicMsgReject rejOut;
	int	      n;

	n = quicMsgEncodeXferRefuse(buf, sizeof(buf), &refIn);
	assert(n > 0 && quicMsgDecodeXferRefuse(buf, n, &refOut) == n);
	assert(refOut.reason == QMSG_REFUSE_NO_RESOURCES
			&& refOut.transferId == 42);

	n = quicMsgEncodeKeepalive(buf, sizeof(buf));
	assert(n == 1 && quicMsgType(buf, n) == QMSG_KEEPALIVE);

	n = quicMsgEncodeSessTerm(buf, sizeof(buf), &termIn);
	assert(n > 0 && quicMsgDecodeSessTerm(buf, n, &termOut) == n);
	assert(termOut.flags == QMSG_TERM_FLAG_REPLY);
	assert(termOut.reason == QMSG_TERM_UNKNOWN && termOut.sessExtLen == 0);

	n = quicMsgEncodeMsgReject(buf, sizeof(buf), &rejIn);
	assert(n > 0 && quicMsgDecodeMsgReject(buf, n, &rejOut) == n);
	assert(rejOut.rejectedType == QMSG_KEEPALIVE);
	assert(rejOut.reason == QMSG_REJECT_UNEXPECTED);
}

static void test_wrong_type(void)
{
	QuicXferAck out;

	/*	A complete message of the wrong type is malformed (-1), not
	 *	"need more".						*/
	assert(quicMsgEncodeKeepalive(buf, sizeof(buf)) == 1);
	assert(quicMsgDecodeXferAck(buf, 1, &out) == -1);
}

int main(void)
{
	test_sess_init();
	test_xfer_segment();
	test_xfer_ack();
	test_small_messages();
	test_wrong_type();
	return 0;
}
