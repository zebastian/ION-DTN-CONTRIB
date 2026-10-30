/*
	fuzz_rules.c:	libFuzzer target for the quota rules.

	The first byte picks what the rest is fed to:

	  0  pattern '\n' EID	an EID pattern, then an EID to match:
				what a bundle's sender controls
	  1  line		a state file line
	  2  words		the arguments of "a rule"
	  3  script		token bucket operations: 9-byte records
				of op, then a 64-bit big-endian value

	Whatever parses must format and parse back to the same thing,
	and a bucket must stay within its bounds.
									*/

#include "quotarules.h"

#include <stdlib.h>
#include <string.h>

#define MAX_INPUT	2048

static void	fuzzPattern(const char *text, size_t len)
{
	QuotaPattern	pattern;
	char		buf[MAX_INPUT + 1];
	char		*eid;

	memcpy(buf, text, len);
	buf[len] = '\0';
	eid = strchr(buf, '\n');
	if (eid)
	{
		*eid++ = '\0';
	}

	if (quotaPatternParse(buf, &pattern) < 0)
	{
		return;
	}

	if (pattern.type == QuotaPatAny && eid
	&& !quotaPatternMatch(&pattern, eid))
	{
		abort();		/*	"*" missed an EID.	*/
	}

	(void) quotaPatternMatch(&pattern, eid);
	(void) quotaPatternMatch(&pattern, buf);
}

static void	fuzzStateLine(const char *text, size_t len)
{
	QuotaStateLine	line;
	QuotaStateLine	again;
	char		buf[MAX_INPUT + 1];
	char		out[1100];

	memcpy(buf, text, len);
	buf[len] = '\0';
	if (quotaParseStateLine(buf, &line) < 0 || line.type == QuotaLineOther)
	{
		return;
	}

	if (quotaFormatStateLine(&line, out, sizeof out) < 0)
	{
		abort();
	}

	out[strcspn(out, "\n")] = '\0';
	if (quotaParseStateLine(out, &again) < 0
	|| memcmp(&line, &again, sizeof line) != 0)
	{
		abort();		/*	Round trip changed it.	*/
	}
}

static int	splitWords(char *buf, char **argv, int max)
{
	int	argc = 0;
	char	*save = NULL;
	char	*token;

	for (token = strtok_r(buf, " ", &save); token && argc < max;
			token = strtok_r(NULL, " ", &save))
	{
		argv[argc++] = token;
	}

	return argc;
}

static void	fuzzRule(const char *text, size_t len)
{
	QuotaRule	rule;
	QuotaRule	again;
	const char	*why;
	char		buf[MAX_INPUT + 1];
	char		out[4096];
	char		*argv[64];
	int		argc;

	memcpy(buf, text, len);
	buf[len] = '\0';
	argc = splitWords(buf, argv, 64);
	memset(&rule, 0, sizeof rule);
	if (quotaParseRule(argc, argv, &rule, &why) < 0)
	{
		if (why == NULL)
		{
			abort();	/*	Failure without a reason.	*/
		}

		return;
	}

	quotaFormatRule(&rule, out, sizeof out);
	argc = splitWords(out, argv, 64);
	memset(&again, 0, sizeof again);
	if (quotaParseRule(argc, argv, &again, &why) < 0
	|| memcmp(&rule, &again, sizeof rule) != 0)
	{
		abort();
	}
}

static uint64_t	readValue(const unsigned char *p)
{
	uint64_t	v = 0;
	int		i;

	for (i = 0; i < 8; i++)
	{
		v = (v << 8) | p[i];
	}

	return v;
}

static void	fuzzBucket(const unsigned char *data, size_t len)
{
	QuotaBucket	bucket;
	uint64_t	nowMs = 0;
	size_t		i;

	quotaBucketInit(&bucket, 1000, 1000, 0);
	for (i = 0; i + 9 <= len; i += 9)
	{
		uint64_t	v = readValue(data + i + 1);

		switch (data[i] % 6)
		{
		case 0:
			nowMs += v % (1ULL << 50);
			quotaBucketRefill(&bucket, nowMs);
			break;

		case 1:
			if (quotaBucketFits(&bucket, v))
			{
				quotaBucketCharge(&bucket, v);
			}

			break;

		case 2:
			quotaBucketCharge(&bucket, v);
			break;

		case 3:
			if (quotaBucketWaitMs(&bucket, v) == 0
			&& !quotaBucketFits(&bucket, v))
			{
				abort();	/*	No wait, no fit.	*/
			}

			break;

		case 4:
			quotaBucketResize(&bucket, v % QUOTA_MAX_COUNT + 1,
				(v >> 20) % ((uint64_t) QUOTA_MAX_PERIOD_S
					* 1000) + 1);
			break;

		default:
			nowMs = v % (1ULL << 50);	/*	May go back.	*/
			quotaBucketRefill(&bucket, nowMs);
		}

		if (bucket.level > (int64_t) bucket.count
		|| bucket.frac >= bucket.periodMs
		|| bucket.level < INT64_MIN / 2)
		{
			abort();
		}
	}
}

int	LLVMFuzzerTestOneInput(const uint8_t *data, size_t len)
{
	if (len < 1 || len > MAX_INPUT)
	{
		return 0;
	}

	switch (data[0])
	{
	case 0:
		fuzzPattern((const char *) data + 1, len - 1);
		break;

	case 1:
		fuzzStateLine((const char *) data + 1, len - 1);
		break;

	case 2:
		fuzzRule((const char *) data + 1, len - 1);
		break;

	case 3:
		fuzzBucket(data + 1, len - 1);
		break;

	default:
		break;
	}

	return 0;
}
