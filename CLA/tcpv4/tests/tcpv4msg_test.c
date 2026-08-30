/*
	tcpv4msg_test.c:	round-trip unit tests for the TCPCLv4 codec.
				Built and run via `make check`.
									*/

#include <assert.h>
#include <string.h>
#include "tcpv4msg.h"

static uint8_t buf[512];

static void test_contact(void)
{
	Tcpv4Contact in;
	Tcpv4Contact out;
	int	     n;

	memset(&in, 0, sizeof(in));
	in.version = TMSG_VERSION;
	in.flags = TMSG_CONTACT_CAN_TLS;

	n = tcpv4MsgEncodeContact(buf, sizeof(buf), &in);
	assert(n == TMSG_CONTACT_LEN);
	assert(memcmp(buf, TMSG_MAGIC, TMSG_MAGIC_LEN) == 0);
	assert(tcpv4MsgDecodeContact(buf, n, &out) == n);
	assert(out.version == TMSG_VERSION);
	assert(out.flags == TMSG_CONTACT_CAN_TLS);

	/*	A truncated header must report "need more" (0)...	*/
	assert(tcpv4MsgDecodeContact(buf, n - 1, &out) == 0);

	/*	...but a wrong magic string is a hard error (-1), which
	 *	RFC 9174 4.3 answers by closing the connection.		*/
	buf[1] = 'X';
	assert(tcpv4MsgDecodeContact(buf, n, &out) == -1);
	buf[1] = 't';
}

static void test_sess_init(void)
{
	const char   *nodeId = "ipn:1.0";
	Tcpv4SessInit in;
	Tcpv4SessInit out;
	int	      n;

	memset(&in, 0, sizeof(in));
	in.keepalive = 30;
	in.segmentMru = 65536;
	in.transferMru = 1000000;
	in.nodeId = (const uint8_t *) nodeId;
	in.nodeIdLen = (uint16_t) strlen(nodeId);

	n = tcpv4MsgEncodeSessInit(buf, sizeof(buf), &in);
	assert(n > 0);
	assert(tcpv4MsgType(buf, n) == TMSG_SESS_INIT);

	/*	Fixed part is 1 + 2 + 8 + 8 + 2 octets, then the node ID
	 *	and the 4-octet extension list length.			*/
	assert(n == 21 + (int) strlen(nodeId) + 4);

	assert(tcpv4MsgDecodeSessInit(buf, n, &out) == n);
	assert(out.keepalive == 30);
	assert(out.segmentMru == 65536);
	assert(out.transferMru == 1000000);
	assert(out.nodeIdLen == in.nodeIdLen);
	assert(memcmp(out.nodeId, nodeId, out.nodeIdLen) == 0);
	assert(out.sessExtLen == 0);

	/*	A truncated buffer must report "need more" (0).		*/
	assert(tcpv4MsgDecodeSessInit(buf, n - 1, &out) == 0);
}

static void test_sess_init_extensions(void)
{
	/*	One extension item: flags 0x01 (CRITICAL), type 0x0102,
	 *	length 2, value {0xAA, 0xBB}.				*/
	static const uint8_t ext[] = {0x01, 0x01, 0x02, 0x00, 0x02, 0xAA, 0xBB};
	Tcpv4SessInit	     in;
	Tcpv4SessInit	     out;
	Tcpv4ExtItem	     item;
	size_t		     off = 0;
	int		     n;

	memset(&in, 0, sizeof(in));
	in.keepalive = 15;
	in.segmentMru = 1024;
	in.transferMru = 4096;
	in.sessExt = ext;
	in.sessExtLen = sizeof(ext);

	n = tcpv4MsgEncodeSessInit(buf, sizeof(buf), &in);
	assert(n > 0);
	assert(tcpv4MsgDecodeSessInit(buf, n, &out) == n);
	assert(out.nodeIdLen == 0); /* RFC 9174 4.6: no node ID.	*/
	assert(out.sessExtLen == sizeof(ext));

	assert(tcpv4MsgNextExtItem(out.sessExt, out.sessExtLen, &off, &item)
			== 1);
	assert(item.flags & TMSG_EXT_CRITICAL);
	assert(item.type == 0x0102);
	assert(item.length == 2);
	assert(item.value[0] == 0xAA && item.value[1] == 0xBB);
	assert(tcpv4MsgNextExtItem(out.sessExt, out.sessExtLen, &off, &item)
			== 0);

	/*	A list whose last item overruns the declared length is a
	 *	reception failure (RFC 9174 4.8).			*/
	off = 0;
	assert(tcpv4MsgNextExtItem(ext, sizeof(ext) - 1, &off, &item) == -1);
}

static void test_xfer_segment(void)
{
	Tcpv4XferSegment in;
	Tcpv4XferSegment out;
	int		 n;

	memset(&in, 0, sizeof(in));
	in.flags = TMSG_FLAG_START | TMSG_FLAG_END;
	in.transferId = 0x1122334455667788ULL;
	in.dataLength = 4096;

	n = tcpv4MsgEncodeXferSegmentHdr(buf, sizeof(buf), &in);
	assert(n == 22); /* type+flags+id+extlen+datalen.		*/
	assert(tcpv4MsgType(buf, n) == TMSG_XFER_SEGMENT);
	assert(tcpv4MsgDecodeXferSegmentHdr(buf, n, &out) == n);
	assert(out.flags == in.flags);
	assert(out.transferId == in.transferId);
	assert(out.xferExtLen == 0);
	assert(out.dataLength == 4096);

	/*	Without START the 4-octet Transfer Extension Items Length
	 *	is absent (RFC 9174 5.2.2), so the header is shorter.	*/
	in.flags = TMSG_FLAG_END;
	n = tcpv4MsgEncodeXferSegmentHdr(buf, sizeof(buf), &in);
	assert(n == 18);
	assert(tcpv4MsgDecodeXferSegmentHdr(buf, n, &out) == n);
	assert(out.flags == TMSG_FLAG_END);
	assert(out.dataLength == 4096);
	assert(tcpv4MsgDecodeXferSegmentHdr(buf, n - 1, &out) == 0);
}

static void test_xfer_ack(void)
{
	Tcpv4XferAck in;
	Tcpv4XferAck out;
	int	     n;

	memset(&in, 0, sizeof(in));
	in.flags = TMSG_FLAG_END;
	in.transferId = 7;
	in.ackLength = 1800;

	n = tcpv4MsgEncodeXferAck(buf, sizeof(buf), &in);
	assert(n == 18);
	assert(tcpv4MsgDecodeXferAck(buf, n, &out) == n);
	assert(out.flags == TMSG_FLAG_END);
	assert(out.transferId == 7);
	assert(out.ackLength == 1800);
	assert(tcpv4MsgDecodeXferAck(buf, n - 1, &out) == 0);
}

static void test_xfer_refuse(void)
{
	Tcpv4XferRefuse in;
	Tcpv4XferRefuse out;
	int		n;

	memset(&in, 0, sizeof(in));
	in.reason = TMSG_REFUSE_NO_RESOURCES;
	in.transferId = 42;

	n = tcpv4MsgEncodeXferRefuse(buf, sizeof(buf), &in);
	assert(n == 10);
	assert(tcpv4MsgDecodeXferRefuse(buf, n, &out) == n);
	assert(out.reason == TMSG_REFUSE_NO_RESOURCES);
	assert(out.transferId == 42);
	assert(tcpv4MsgDecodeXferRefuse(buf, n - 1, &out) == 0);
}

static void test_keepalive(void)
{
	int n = tcpv4MsgEncodeKeepalive(buf, sizeof(buf));

	assert(n == 1);
	assert(tcpv4MsgType(buf, n) == TMSG_KEEPALIVE);
	assert(tcpv4MsgType(buf, 0) == -1);
}

static void test_sess_term(void)
{
	Tcpv4SessTerm in;
	Tcpv4SessTerm out;
	int	      n;

	memset(&in, 0, sizeof(in));
	in.flags = TMSG_TERM_FLAG_REPLY;
	in.reason = TMSG_TERM_IDLE_TIMEOUT;

	n = tcpv4MsgEncodeSessTerm(buf, sizeof(buf), &in);
	assert(n == 3);
	assert(tcpv4MsgDecodeSessTerm(buf, n, &out) == n);
	assert(out.flags == TMSG_TERM_FLAG_REPLY);
	assert(out.reason == TMSG_TERM_IDLE_TIMEOUT);
	assert(tcpv4MsgDecodeSessTerm(buf, n - 1, &out) == 0);
}

static void test_msg_reject(void)
{
	Tcpv4MsgReject in;
	Tcpv4MsgReject out;
	int	       n;

	memset(&in, 0, sizeof(in));
	in.reason = TMSG_REJECT_TYPE_UNKNOWN;
	in.rejectedType = 0x7F;

	n = tcpv4MsgEncodeMsgReject(buf, sizeof(buf), &in);
	assert(n == 3);

	/*	RFC 9174 5.1.2 puts the Reason Code before the rejected
	 *	Message Header, unlike XFER_ACK's flags-first layout.	*/
	assert(buf[1] == TMSG_REJECT_TYPE_UNKNOWN);
	assert(buf[2] == 0x7F);

	assert(tcpv4MsgDecodeMsgReject(buf, n, &out) == n);
	assert(out.reason == TMSG_REJECT_TYPE_UNKNOWN);
	assert(out.rejectedType == 0x7F);
	assert(tcpv4MsgDecodeMsgReject(buf, n - 1, &out) == 0);
}

static void test_encode_overflow(void)
{
	Tcpv4XferAck ack;
	uint8_t	     tiny[4];

	memset(&ack, 0, sizeof(ack));
	assert(tcpv4MsgEncodeXferAck(tiny, sizeof(tiny), &ack) == -1);
	assert(tcpv4MsgEncodeKeepalive(tiny, 0) == -1);
}

int main(void)
{
	test_contact();
	test_sess_init();
	test_sess_init_extensions();
	test_xfer_segment();
	test_xfer_ack();
	test_xfer_refuse();
	test_keepalive();
	test_sess_term();
	test_msg_reject();
	test_encode_overflow();
	return 0;
}
