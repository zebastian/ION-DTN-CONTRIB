/*
	fuzz_zclrx.c:	libFuzzer target for the zcl receive side.

	The input is a script of operations on one receiver:

	  0 len:2 bytes		a raw carrier, as received
	  1 ms:1		let time pass (ms * 50) and tick
	  2 flags stream chunk seq len:2 bytes
				a carrier with a valid header and CRC
				around arbitrary zstd data
	  3 ctl len:1 bytes	compress 'bytes' as a bundle with a real
				encoder and cut a carrier; ctl bit 0 ends
				the chunk, bit 1 loses the carrier, bit 2
				holds it back to arrive after the next one

	so the fuzzer reaches the decoder both with garbage and with
	streams that are valid but lost, reordered or duplicated.
									*/

#include "zclcodec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUNDLE	4096

static int	emit(void *ctx, const unsigned char *bundle, size_t len)
{
	(void) ctx;
	(void) bundle;

	if (len == 0 || len > MAX_BUNDLE)
	{
		abort();		/*	Limit not enforced.	*/
	}

	return 0;
}

int	LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	ZclRxLimits	lim;
	ZclRx		*rx;
	ZclEnc		enc;
	unsigned char	*held = NULL;
	size_t		heldLen = 0;
	unsigned char	*carrier;
	size_t		carrierLen;
	unsigned char	buf[ZCL_HDR_LEN + 65536];
	uint64_t	now = 0;
	size_t		len;

	zclRxDefaults(&lim);
	lim.maxBundle = MAX_BUNDLE;
	lim.maxChunkOut = 1024 * 1024;
	lim.maxCarriers = 16;
	lim.maxBufBytes = 64 * 1024;
	lim.reorderMs = 1000;
	lim.maxStreams = 3;
	lim.windowLogMax = 20;
	rx = zclRxNew(&lim, emit, NULL);
	if (rx == NULL || zclEncInit(&enc, 1, 18, 0x5a) < 0)
	{
		abort();
	}

	while (size > 0)
	{
		unsigned char	op = data[0] % 4;

		data++;
		size--;
		switch (op)
		{
		case 0:
			if (size < 2)
			{
				size = 0;
				break;
			}

			len = ((size_t) data[0] << 8) | data[1];
			data += 2;
			size -= 2;
			if (len > size)
			{
				len = size;
			}

			zclRxCarrier(rx, data, len, now);
			data += len;
			size -= len;
			break;

		case 1:
			if (size < 1)
			{
				size = 0;
				break;
			}

			now += (uint64_t) data[0] * 50;
			data++;
			size--;
			zclRxTick(rx, now);
			break;

		case 2:
		{
			ZclHeader	h;

			if (size < 6)
			{
				size = 0;
				break;
			}

			h.flags = data[0] & ZCL_FLAG_END;
			h.streamId = data[1] % 4;
			h.chunkId = data[2];
			h.seq = data[3];
			len = ((size_t) data[4] << 8) | data[5];
			data += 6;
			size -= 6;
			if (len > size)
			{
				len = size;
			}

			h.length = (uint32_t) len;
			memcpy(buf + ZCL_HDR_LEN, data, len);
			zclHeaderPut(buf, &h, buf + ZCL_HDR_LEN);
			zclRxCarrier(rx, buf, ZCL_HDR_LEN + len, now);
			data += len;
			size -= len;
			break;
		}

		case 3:
		{
			unsigned char	ctl;

			if (size < 2)
			{
				size = 0;
				break;
			}

			ctl = data[0];
			len = data[1];
			data += 2;
			size -= 2;
			if (len > size)
			{
				len = size;
			}

			if (len > 0 && zclEncAdd(&enc, data, len) < 0)
			{
				zclEncAbort(&enc);
			}

			data += len;
			size -= len;
			if (zclEncCut(&enc, ctl & 1, &carrier, &carrierLen) != 1)
			{
				break;
			}

			if (ctl & 2)
			{
				free(carrier);		/*	Lost.	*/
				break;
			}

			if (ctl & 4 && held == NULL)
			{
				held = carrier;		/*	Late.	*/
				heldLen = carrierLen;
				break;
			}

			zclRxCarrier(rx, carrier, carrierLen, now);
			free(carrier);
			if (held)
			{
				zclRxCarrier(rx, held, heldLen, now);
				free(held);
				held = NULL;
			}

			break;
		}
		}
	}

	if (held)
	{
		zclRxCarrier(rx, held, heldLen, now);
		free(held);
	}

	zclRxTick(rx, now + 100000);
	zclEncFree(&enc);
	zclRxFree(rx);
	return 0;
}
