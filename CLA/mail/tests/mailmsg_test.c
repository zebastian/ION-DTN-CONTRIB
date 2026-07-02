/*	mailmsg_test.c:	round-trip tests for the mail CLA core.	*/

#include "mailmsg.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

static int	failures;

#define CHECK(cond, msg)                                                  \
	do {                                                              \
		if (!(cond)) {                                            \
			printf("FAIL: %s\n", msg);                        \
			failures++;                                       \
		}                                                         \
	} while (0)

typedef struct
{
	unsigned char	blob[8][4096];
	size_t		len[8];
	int		count;
} Collector;

static int	collect(void *ctx, const unsigned char *bundle, size_t len)
{
	Collector *c = (Collector *) ctx;

	if (c->count >= 8 || len > sizeof(c->blob[0]))
	{
		return -1;
	}

	memcpy(c->blob[c->count], bundle, len);
	c->len[c->count] = len;
	c->count++;
	return 0;
}

static void	roundTrip(const char *label, int encoding,
		const MailBundle *in, size_t count)
{
	char	   *msg = NULL;
	size_t	    msgLen = 0;
	Collector   c;
	int	    n;
	size_t	    i;

	memset(&c, 0, sizeof(c));

	CHECK(mailBuildMessage("a@x", "b@y", NULL, encoding, in, count,
			&msg, &msgLen) == 0, label);
	if (msg == NULL)
	{
		return;
	}

	n = mailParseMessage(msg, msgLen, encoding, collect, &c);
	CHECK(n == (int) count, label);
	CHECK(c.count == (int) count, label);

	for (i = 0; i < count && i < (size_t) c.count; i++)
	{
		CHECK(c.len[i] == in[i].len, label);
		CHECK(c.len[i] == in[i].len
			&& memcmp(c.blob[i], in[i].bytes, in[i].len) == 0,
			label);
	}

	free(msg);
}

int	main(void)
{
	static const unsigned char b0[] = {
		0x9f, 0x00, 0x0d, 0x0a, 0xff, 0x2d, 0x2d, 0x42, 0xdb
	};
	static const unsigned char b1[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a
	};
	unsigned char	big[3000];
	MailBundle	one[1];
	MailBundle	two[2];
	MailBundle	bigb[1];
	unsigned char	dec[8];
	char		enc[32];
	size_t		declen;
	size_t		i;
	int		e;

	/*	base64 round-trip of a known value.			*/
	CHECK(mailB64Encode(b1, 3, enc, sizeof(enc)) == 0, "b64 enc");
	CHECK(strcmp(enc, "AQID") == 0, "b64 enc value");
	CHECK(mailB64Decode("AQID", 4, dec, sizeof(dec), &declen) == 0,
			"b64 dec");
	CHECK(declen == 3 && memcmp(dec, b1, 3) == 0, "b64 dec value");

	CHECK(mailEncodingFromName("attach") == MAIL_ENC_ATTACH, "name attach");
	CHECK(mailEncodingFromName("b64") == MAIL_ENC_B64, "name b64");
	CHECK(mailEncodingFromName("raw") == MAIL_ENC_RAW, "name raw");
	CHECK(mailEncodingFromName("bogus") == -1, "name bogus");

	for (i = 0; i < sizeof(big); i++)
	{
		big[i] = (unsigned char) (i * 7 + 1);
	}

	one[0].bytes = b0;	one[0].len = sizeof(b0);
	two[0].bytes = b0;	two[0].len = sizeof(b0);
	two[1].bytes = b1;	two[1].len = sizeof(b1);
	bigb[0].bytes = big;	bigb[0].len = sizeof(big);

	for (e = MAIL_ENC_ATTACH; e <= MAIL_ENC_RAW; e++)
	{
		roundTrip("single", e, one, 1);
		roundTrip("digest", e, two, 2);
		roundTrip("large", e, bigb, 1);
	}

	if (failures == 0)
	{
		printf("mailmsg_test: all checks passed\n");
		return 0;
	}

	printf("mailmsg_test: %d failure(s)\n", failures);
	return 1;
}
