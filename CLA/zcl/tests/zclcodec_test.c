/*	zclcodec_test.c:	unit tests for the zcl codec (no ION).	*/

#include "zclcodec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int	failures = 0;

#define CHECK(cond, what)						\
	do								\
	{								\
		if (!(cond))						\
		{							\
			printf("FAIL %s:%d: %s\n", __FILE__, __LINE__,	\
					what);				\
			failures++;					\
		}							\
	} while (0)

/*	*	*	Test bundles	*	*	*	*	*/

#define MAXB	64

/*	Bundle i: telemetry-like text, so it compresses, with its index
 *	in front so every one is distinct.				*/
static size_t	makeBundle(int i, unsigned char *buf, size_t cap)
{
	int	n;
	size_t	len;

	n = snprintf((char *) buf, cap,
		"#%05d ipn:10.1 -> ipn:20.1 temp=%d volt=%d.%02d mode=NOMINAL ",
		i, 20 + i % 7, 3, i % 100);
	len = (size_t) n;
	while (len + 16 < cap && len < (size_t) (80 + (i * 37) % 900))
	{
		buf[len] = (unsigned char) ('a' + (i + len) % 26);
		len++;
	}

	return len;
}

typedef struct
{
	int		count;
	int		seen[1000];	/*	times bundle i arrived	*/
	int		order[1000];
	int		bad;
} Sink;

static int	sinkEmit(void *ctx, const unsigned char *bundle, size_t len)
{
	Sink		*sk = (Sink *) ctx;
	unsigned char	want[2048];
	int		i;

	if (len < 7 || bundle[0] != '#' || sscanf((const char *) bundle + 1,
			"%5d", &i) != 1 || i < 0 || i >= 1000)
	{
		sk->bad++;
		return 0;
	}

	if (makeBundle(i, want, sizeof want) != len
	|| memcmp(want, bundle, len) != 0)
	{
		sk->bad++;
		return 0;
	}

	sk->seen[i]++;
	if (sk->count < 1000)
	{
		sk->order[sk->count] = i;
	}

	sk->count++;
	return 0;
}

/*	*	*	Carrier list	*	*	*	*	*/

typedef struct
{
	unsigned char	*data[512];
	size_t		len[512];
	int		first[512];	/*	first bundle in carrier	*/
	int		n;
} Carriers;

static void	freeCarriers(Carriers *c)
{
	int	i;

	for (i = 0; i < c->n; i++)
	{
		free(c->data[i]);
	}

	c->n = 0;
}

/*	Encodes bundles [0, count) cutting a carrier every 'perCarrier'
 *	bundles and ending a chunk every 'perChunk' carriers.		*/
static void	encode(Carriers *c, int count, int perCarrier, int perChunk,
			uint64_t streamId)
{
	ZclEnc		enc;
	unsigned char	b[2048];
	unsigned char	*carrier;
	size_t		len;
	size_t		blen;
	int		i;
	int		inCarrier = 0;
	int		carriersInChunk = 0;
	int		first = 0;

	memset(c, 0, sizeof(Carriers));
	CHECK(zclEncInit(&enc, 3, 0, streamId) == 0, "encoder init");
	for (i = 0; i < count; i++)
	{
		blen = makeBundle(i, b, sizeof b);
		CHECK(zclEncAdd(&enc, b, blen) == 0, "add bundle");
		if (++inCarrier == perCarrier || i == count - 1)
		{
			int	end = (++carriersInChunk == perChunk
					|| i == count - 1);

			CHECK(zclEncCut(&enc, end, &carrier, &len) == 1, "cut");
			c->data[c->n] = carrier;
			c->len[c->n] = len;
			c->first[c->n] = first;
			c->n++;
			first = i + 1;
			inCarrier = 0;
			if (end)
			{
				carriersInChunk = 0;
			}
		}
	}

	CHECK(zclEncCut(&enc, 0, &carrier, &len) == 0, "nothing to cut");
	zclEncFree(&enc);
}

static ZclRx	*newRx(Sink *sk, unsigned int reorderMs)
{
	ZclRxLimits	lim;

	memset(sk, 0, sizeof(Sink));
	zclRxDefaults(&lim);
	lim.reorderMs = reorderMs;
	return zclRxNew(&lim, sinkEmit, sk);
}

/*	*	*	Tests	*	*	*	*	*	*/

static void	testHeader(void)
{
	unsigned char	buf[ZCL_HDR_LEN + 3] = { 0 };
	ZclHeader	h = { ZCL_FLAG_END, 0x0102030405060708ull, 42, 7, 3 };
	ZclHeader	g;

	memcpy(buf + ZCL_HDR_LEN, "abc", 3);
	zclHeaderPut(buf, &h, buf + ZCL_HDR_LEN);
	CHECK(zclHeaderGet(buf, sizeof buf, &g) == 0, "header round trip");
	CHECK(g.flags == h.flags && g.streamId == h.streamId
		&& g.chunkId == 42 && g.seq == 7 && g.length == 3,
		"header fields");
	CHECK(zclHeaderGet(buf, sizeof buf - 1, &g) < 0, "short carrier");
	buf[ZCL_HDR_LEN + 1] ^= 1;
	CHECK(zclHeaderGet(buf, sizeof buf, &g) < 0, "payload CRC");
	buf[ZCL_HDR_LEN + 1] ^= 1;
	buf[5] = 1;
	CHECK(zclHeaderGet(buf, sizeof buf, &g) < 0, "reserved bits");

	/*	CRC-32C check value.					*/
	CHECK(zclCrc32c(0, (const unsigned char *) "123456789", 9)
		== 0xe3069283, "crc32c check value");
}

static void	testRoundTrip(void)
{
	Carriers	c;
	Sink		sk;
	ZclRx		*rx = newRx(&sk, 1000);
	ZclRxStats	st;
	size_t		in = 0;
	size_t		out = 0;
	int		i;

	encode(&c, 300, 10, 4, 1);
	for (i = 0; i < c.n; i++)
	{
		out += c.len[i];
		CHECK(zclRxCarrier(rx, c.data[i], c.len[i], 0) == 0, "accept");
	}

	for (i = 0; i < 300; i++)
	{
		unsigned char	b[2048];

		in += makeBundle(i, b, sizeof b);
	}

	CHECK(sk.count == 300 && sk.bad == 0, "all bundles delivered");
	for (i = 0; i < 300; i++)
	{
		CHECK(sk.order[i] == i, "in order");
	}

	zclRxGetStats(rx, &st);
	CHECK(st.chunksDone == 8, "8 chunks completed");
	CHECK(out < in / 3, "compresses");
	printf("round trip: %zu bytes of bundles in %zu bytes of carriers\n",
			in, out);
	zclRxFree(rx);
	freeCarriers(&c);
}

static void	testReorder(void)
{
	Carriers	c;
	Sink		sk;
	ZclRx		*rx = newRx(&sk, 1000);
	int		order[64];
	int		i;

	encode(&c, 200, 10, 5, 2);	/*	20 carriers, 4 chunks	*/
	for (i = 0; i < c.n; i++)
	{
		order[i] = i;
	}

	/*	Swap neighbours and move whole chunks around.		*/
	for (i = 0; i + 1 < c.n; i += 2)
	{
		int	t = order[i];

		order[i] = order[i + 1];
		order[i + 1] = t;
	}

	for (i = 0; i < 5; i++)
	{
		int	t = order[i];

		order[i] = order[i + 10];
		order[i + 10] = t;
	}

	for (i = 0; i < c.n; i++)
	{
		zclRxCarrier(rx, c.data[order[i]], c.len[order[i]], 10);
	}

	CHECK(sk.count == 200 && sk.bad == 0, "reordered: all delivered");
	for (i = 0; i < 200; i++)
	{
		CHECK(sk.seen[i] == 1, "reordered: each once");
	}

	zclRxFree(rx);
	freeCarriers(&c);
}

static void	testLoss(void)
{
	Carriers	c;
	Sink		sk;
	ZclRx		*rx = newRx(&sk, 500);
	ZclRxStats	st;
	int		lost = 7;	/*	chunk 1, seq 2		*/
	int		i;

	encode(&c, 200, 10, 5, 3);	/*	20 carriers, 4 chunks	*/
	for (i = 0; i < c.n; i++)
	{
		if (i != lost)
		{
			zclRxCarrier(rx, c.data[i], c.len[i], 100);
		}
	}

	/*	Chunk 1 waits for its missing carrier until the timeout;
	 *	chunks 2 and 3 wait behind it.				*/

	CHECK(sk.count == 70, "before timeout: chunk 0 and head of 1");
	zclRxTick(rx, 400);
	CHECK(sk.count == 70, "still waiting");
	zclRxTick(rx, 600);
	CHECK(sk.count == 170, "after timeout: chunks 2, 3 delivered");
	for (i = 0; i < 200; i++)
	{
		int	want = (i >= 70 && i < 100) ? 0 : 1;

		CHECK(sk.seen[i] == want, "rest of the lost chunk is gone");
	}

	zclRxGetStats(rx, &st);
	CHECK(st.chunksLost == 1 && st.chunksDone == 3, "one chunk lost");

	/*	The lost carrier turning up late changes nothing.	*/
	zclRxCarrier(rx, c.data[lost], c.len[lost], 700);
	CHECK(sk.count == 170, "late carrier ignored");
	zclRxFree(rx);
	freeCarriers(&c);
}

static void	testQueuedGaps(void)
{
	Carriers	c;
	Sink		sk;
	ZclRx		*rx = newRx(&sk, 500);
	ZclRxStats	st;
	int		i;

	/*	Chunks 1 and 2 each lose a carrier.  Both gaps are older
	 *	than the timeout at the same tick, so both are given up
	 *	then - not one per timeout.				*/

	encode(&c, 200, 10, 5, 10);	/*	20 carriers, 4 chunks	*/
	for (i = 0; i < c.n; i++)
	{
		if (i != 7 && i != 12)
		{
			zclRxCarrier(rx, c.data[i], c.len[i], 0);
		}
	}

	CHECK(sk.count == 70, "waiting at the first gap");
	zclRxTick(rx, 500);
	CHECK(sk.count == 140, "both gaps given up in one tick");
	zclRxGetStats(rx, &st);
	CHECK(st.chunksLost == 2 && st.chunksDone == 2, "two chunks lost");
	zclRxFree(rx);
	freeCarriers(&c);
}

static void	testLostStart(void)
{
	Carriers	c;
	Sink		sk;
	ZclRx		*rx = newRx(&sk, 500);
	int		i;

	encode(&c, 200, 10, 5, 4);
	for (i = 0; i < c.n; i++)
	{
		if (i != 5)		/*	chunk 1, seq 0		*/
		{
			zclRxCarrier(rx, c.data[i], c.len[i], 0);
		}
	}

	CHECK(sk.count == 50, "chunk 0 only");
	zclRxTick(rx, 1000);
	CHECK(sk.count == 150, "chunks 2, 3 after timeout");
	zclRxFree(rx);
	freeCarriers(&c);
}

static void	testCorruptAndDup(void)
{
	Carriers	c;
	Sink		sk;
	ZclRx		*rx = newRx(&sk, 500);
	ZclRxStats	st;
	int		i;

	encode(&c, 100, 10, 5, 5);	/*	10 carriers, 2 chunks	*/
	c.data[2][ZCL_HDR_LEN + 3] ^= 0x40;
	for (i = 0; i < c.n; i++)
	{
		zclRxCarrier(rx, c.data[i], c.len[i], 0);
		zclRxCarrier(rx, c.data[i], c.len[i], 0);
	}

	zclRxTick(rx, 1000);
	zclRxGetStats(rx, &st);
	CHECK(st.carriersBad == 2, "CRC catches corruption");
	CHECK(sk.count == 70, "chunk 0 up to the bad carrier, chunk 1");
	CHECK(st.carriersStale >= 8, "duplicates dropped");
	for (i = 0; i < 100; i++)
	{
		CHECK(sk.seen[i] <= 1, "no bundle twice");
	}

	zclRxFree(rx);
	freeCarriers(&c);
}

static void	testStreams(void)
{
	Carriers	a;
	Carriers	b;
	Sink		sk;
	ZclRx		*rx = newRx(&sk, 500);
	int		i;

	/*	A restarted sender: same chunk numbers, new stream id.	*/

	encode(&a, 50, 10, 5, 6);
	encode(&b, 50, 10, 5, 7);
	for (i = 0; i < a.n; i++)
	{
		zclRxCarrier(rx, a.data[i], a.len[i], 0);
	}

	for (i = 0; i < b.n; i++)
	{
		zclRxCarrier(rx, b.data[i], b.len[i], 0);
	}

	CHECK(sk.count == 100, "both streams delivered");
	zclRxFree(rx);
	freeCarriers(&a);
	freeCarriers(&b);
}

static void	testLimits(void)
{
	Carriers	c;
	Sink		sk;
	ZclRxLimits	lim;
	ZclRx		*rx;
	ZclRxStats	st;
	int		i;

	memset(&sk, 0, sizeof sk);
	zclRxDefaults(&lim);
	lim.maxBundle = 500;		/*	some bundles are larger	*/
	rx = zclRxNew(&lim, sinkEmit, &sk);
	encode(&c, 40, 10, 2, 8);
	for (i = 0; i < c.n; i++)
	{
		zclRxCarrier(rx, c.data[i], c.len[i], 0);
	}

	zclRxGetStats(rx, &st);
	CHECK(st.chunksCorrupt >= 1, "oversized record refused");
	CHECK(sk.bad == 0, "nothing wrong delivered");
	zclRxFree(rx);

	freeCarriers(&c);

	/*	A full reorder buffer forces the gap without waiting
	 *	for the timeout.					*/

	memset(&sk, 0, sizeof sk);
	zclRxDefaults(&lim);
	lim.maxCarriers = 3;
	rx = zclRxNew(&lim, sinkEmit, &sk);
	encode(&c, 100, 10, 2, 9);	/*	10 carriers, 5 chunks	*/
	for (i = 0; i < c.n; i++)
	{
		if (i != 1)		/*	chunk 0, seq 1 lost	*/
		{
			zclRxCarrier(rx, c.data[i], c.len[i], 0);
		}
	}

	CHECK(sk.count == 90, "overflow skips the stuck chunk");
	zclRxFree(rx);
	freeCarriers(&c);
}

static void	testAbort(void)
{
	ZclEnc		enc;
	unsigned char	b[2048];
	unsigned char	*carrier;
	size_t		len;
	ZclHeader	h;

	CHECK(zclEncInit(&enc, 1, 0, 9) == 0, "init");
	CHECK(zclEncAdd(&enc, b, makeBundle(0, b, sizeof b)) == 0, "add");
	zclEncAbort(&enc);		/*	nothing sent: keep id	*/
	CHECK(zclEncAdd(&enc, b, makeBundle(1, b, sizeof b)) == 0, "add");
	CHECK(zclEncCut(&enc, 0, &carrier, &len) == 1, "cut");
	CHECK(zclHeaderGet(carrier, len, &h) == 0 && h.chunkId == 0
		&& h.seq == 0, "chunk 0 kept");
	free(carrier);
	zclEncAbort(&enc);		/*	partly sent: next id	*/
	CHECK(zclEncAdd(&enc, b, makeBundle(2, b, sizeof b)) == 0, "add");
	CHECK(zclEncCut(&enc, 1, &carrier, &len) == 1, "cut");
	CHECK(zclHeaderGet(carrier, len, &h) == 0 && h.chunkId == 1
		&& h.seq == 0 && h.flags == ZCL_FLAG_END, "chunk 1 started");
	free(carrier);

	/*	An idle chunk can be ended with nothing pending.	*/
	CHECK(zclEncAdd(&enc, b, makeBundle(3, b, sizeof b)) == 0, "add");
	CHECK(zclEncCut(&enc, 0, &carrier, &len) == 1, "cut");
	free(carrier);
	CHECK(zclEncCut(&enc, 0, &carrier, &len) == 0, "nothing pending");
	CHECK(zclEncCut(&enc, 1, &carrier, &len) == 1, "end idle chunk");
	CHECK(zclHeaderGet(carrier, len, &h) == 0 && h.seq == 1
		&& h.flags == ZCL_FLAG_END, "END carrier");
	free(carrier);
	zclEncFree(&enc);
}

int	main(void)
{
	testHeader();
	testRoundTrip();
	testReorder();
	testLoss();
	testQueuedGaps();
	testLostStart();
	testCorruptAndDup();
	testStreams();
	testLimits();
	testAbort();
	if (failures)
	{
		printf("%d failure(s)\n", failures);
		return 1;
	}

	printf("all zcl codec tests passed\n");
	return 0;
}
