/*
	fuzz_proto.c:	fuzz target for the bpsh frame codec.

	Every bundle bpshd takes in is a frame from whoever sent it, and
	bpsh_decode is the first thing to read it.  A frame it accepts
	must lie inside the bundle - its payload, which aliases the
	bundle, included - and must survive being encoded again: decoding
	the re-encoding gives back the same frame.  CBOR has more than one
	way to spell an integer, so it is the frame that is compared, not
	the octets.

	The decoding itself is ION's CBOR, so this links against libbp and
	libici; only this code and bpsh_proto.c are instrumented.

	Built two ways: as a libFuzzer target (`make fuzz`), and against
	fuzz_replay.c to replay the checked-in corpus under `make check`.
									*/

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "bpsh_proto.h"

/*	Where the payload octets are summed, so that reading them is not
 *	optimized away before a sanitizer can see it.			*/

static volatile unsigned int sink;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len)
{
	BpshFrame      frame;
	BpshFrame      again;
	unsigned char *buf;
	unsigned char *enc;
	size_t	       encCap;
	unsigned int   sum = 0;
	uvast	       i;
	int	       rc;
	int	       n;

	/*	Copied to exactly its length, so that a sanitizer sees any
	 *	read past the end of the bundle.			*/

	buf = malloc(len > 0 ? len : 1);
	assert(buf != NULL);
	memcpy(buf, data, len);

	memset(&frame, 0, sizeof(frame));
	rc = bpsh_decode(buf, len, &frame);
	assert(rc == -1 || (rc > 0 && (size_t) rc <= len));
	if (rc > 0)
	{
		if (frame.payloadLen > 0)
		{
			assert(frame.payload >= buf
				&& frame.payloadLen <= len
				&& frame.payload + frame.payloadLen <= buf + len);
			for (i = 0; i < frame.payloadLen; i++)
			{
				sum += frame.payload[i];
			}
		}

		(void) bpsh_msgtype_name(frame.msgType);
		(void) bpsh_cause_name(frame.exitCause);

		encCap = BPSH_FRAME_OVERHEAD + (size_t) frame.payloadLen;
		enc = malloc(encCap);
		assert(enc != NULL);
		n = bpsh_encode(&frame, enc, encCap);
		assert(n > 0);

		memset(&again, 0, sizeof(again));
		assert(bpsh_decode(enc, (size_t) n, &again) == n);
		assert(again.version == frame.version);
		assert(again.msgType == frame.msgType);
		assert(again.sessionId == frame.sessionId);
		assert(again.seqNum == frame.seqNum);
		assert(again.payloadLen == frame.payloadLen);
		assert(frame.payloadLen == 0 || memcmp(again.payload,
				frame.payload, (size_t) frame.payloadLen) == 0);
		assert(again.exitCode == frame.exitCode);
		assert(again.exitCause == frame.exitCause);
		free(enc);
	}

	sink = sum;
	free(buf);
	return 0;
}
