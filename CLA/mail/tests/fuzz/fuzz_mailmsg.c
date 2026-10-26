/*
	fuzz_mailmsg.c:	fuzz target for the mail CLA's message codec.

	Mail is the most exposed input any CLA here takes: anyone who can
	send the node's mailbox a message can put it in front of the
	parser.  So the input is first parsed as a received message, under
	every encoding, and each bundle the parser hands back is read end
	to end.  Then it is taken apart as up to three bundles, which are
	built into a message and parsed back: under every encoding that can
	carry them, the same bundles must come out.  Base64 is checked on
	its own as well - decoding anything, and decoding what was encoded.

	Built two ways: as a libFuzzer target (`make fuzz`), and against
	fuzz_replay.c to replay the checked-in corpus under `make check`.
									*/

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mailmsg.h"

#define MAX_BUNDLES 3

/*	Where bundle octets are summed, so that reading them is not
 *	optimized away before a sanitizer can see it.			*/

static volatile unsigned int sink;

typedef struct
{
	int		count;
	unsigned char  *bytes[MAX_BUNDLES + 1];
	size_t		len[MAX_BUNDLES + 1];
} Collected;

/*	Keeps the first few bundles, and reads every one, so that a
 *	sanitizer sees a bundle that runs past what the parser had.	*/

static int collect(void *ctx, const unsigned char *bundle, size_t len)
{
	Collected *c = ctx;
	size_t	   i;

	for (i = 0; i < len; i++)
	{
		sink += bundle[i];
	}

	if (c->count <= MAX_BUNDLES)
	{
		c->bytes[c->count] = malloc(len > 0 ? len : 1);
		assert(c->bytes[c->count] != NULL);
		memcpy(c->bytes[c->count], bundle, len);
		c->len[c->count] = len;
	}

	c->count++;
	return 0;
}

static void release(Collected *c)
{
	int i;

	for (i = 0; i < c->count && i <= MAX_BUNDLES; i++)
	{
		free(c->bytes[i]);
	}

	memset(c, 0, sizeof(*c));
}

/*	RAW frames bundles with a separator line and strips the CRLFs
 *	around it, so it can only carry a bundle that holds neither.	*/

static int rawCarries(const MailBundle *b)
{
	size_t sepLen = strlen(MAIL_SEPARATOR);
	size_t i;

	if (b->len == 0)
	{
		return 0;
	}

	if (b->len >= 2 && ((b->bytes[0] == '\r' && b->bytes[1] == '\n')
			|| (b->bytes[b->len - 2] == '\r'
				&& b->bytes[b->len - 1] == '\n')))
	{
		return 0;
	}

	for (i = 0; i + sepLen <= b->len; i++)
	{
		if (memcmp(b->bytes + i, MAIL_SEPARATOR, sepLen) == 0)
		{
			return 0;
		}
	}

	return 1;
}

static void roundTrip(const MailBundle *bundles, size_t count)
{
	static const int encodings[] = {MAIL_ENC_ATTACH, MAIL_ENC_B64,
			MAIL_ENC_RAW};
	Collected	 c;
	char		*msg;
	size_t		 msgLen;
	size_t		 i;
	size_t		 e;
	int		 carried;
	int		 rc;

	for (e = 0; e < sizeof(encodings) / sizeof(encodings[0]); e++)
	{
		carried = 1;
		for (i = 0; i < count; i++)
		{
			if (bundles[i].len == 0
				|| (encodings[e] == MAIL_ENC_RAW
					&& !rawCarries(&bundles[i])))
			{
				carried = 0;
			}
		}

		if (!carried)
		{
			continue;
		}

		assert(mailBuildMessage("a@example.org", "b@example.org", NULL,
				encodings[e], bundles, count, &msg, &msgLen)
				== 0);
		memset(&c, 0, sizeof(c));
		rc = mailParseMessage(msg, msgLen, encodings[e], collect, &c);
		assert(rc == (int) count && c.count == (int) count);
		for (i = 0; i < count; i++)
		{
			assert(c.len[i] == bundles[i].len);
			assert(memcmp(c.bytes[i], bundles[i].bytes,
					bundles[i].len) == 0);
		}

		release(&c);
		free(msg);
	}
}

static void base64(const uint8_t *data, size_t len)
{
	unsigned char *raw = malloc(len + 1);
	char	      *text;
	size_t	       textCap = mailB64EncodedLen(len) + 1;
	size_t	       rawLen;

	assert(raw != NULL);

	/*	Decoding anything must stay inside the output it was given.	*/

	if (mailB64Decode((const char *) data, len, raw, len + 1, &rawLen)
			== 0)
	{
		assert(rawLen <= len + 1);
	}

	/*	Decoding what was encoded gives it back.		*/

	text = malloc(textCap);
	assert(text != NULL);
	assert(mailB64Encode(data, len, text, textCap) >= 0);
	assert(mailB64Decode(text, strlen(text), raw, len + 1, &rawLen) == 0);
	assert(rawLen == len && memcmp(raw, data, len) == 0);

	free(text);
	free(raw);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len)
{
	MailBundle bundles[MAX_BUNDLES];
	Collected  c;
	char	  *msg;
	size_t	   count;
	size_t	   off;
	size_t	   n;
	int	   e;

	/*	The input as a received message, with no terminating NUL,
	 *	so that a parser reading past its end is seen.		*/

	msg = malloc(len > 0 ? len : 1);
	assert(msg != NULL);
	memcpy(msg, data, len);
	for (e = MAIL_ENC_ATTACH; e <= MAIL_ENC_RAW; e++)
	{
		memset(&c, 0, sizeof(c));
		(void) mailParseMessage(msg, len, e, collect, &c);
		release(&c);
	}

	free(msg);

	/*	The input as bundles: the first octet says how many, and
	 *	each but the last is preceded by its length.		*/

	if (len > 0)
	{
		count = (data[0] % MAX_BUNDLES) + 1;
		off = 1;
		for (n = 0; n < count; n++)
		{
			size_t take = len - off;

			if (n + 1 < count && off < len)
			{
				take = data[off++];
				if (take > len - off)
				{
					take = len - off;
				}
			}

			bundles[n].bytes = data + off;
			bundles[n].len = take;
			off += take;
		}

		roundTrip(bundles, count);
	}

	base64(data, len);
	return 0;
}
