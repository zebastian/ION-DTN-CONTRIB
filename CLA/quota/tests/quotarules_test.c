/*	quotarules_test.c:	unit tests for the quota rules (no ION).	*/

#include "quotarules.h"

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

/*	*	*	Numbers	*	*	*	*	*	*/

static int	countIs(const char *text, uint64_t want)
{
	uint64_t	v = 0;

	return quotaParseCount(text, &v) == 0 && v == want;
}

static int	countBad(const char *text)
{
	uint64_t	v;

	return quotaParseCount(text, &v) < 0;
}

static int	periodIs(const char *text, uint32_t want)
{
	uint32_t	v = 0;

	return quotaParsePeriod(text, &v) == 0 && v == want;
}

static int	periodBad(const char *text)
{
	uint32_t	v;

	return quotaParsePeriod(text, &v) < 0;
}

static void	testNumbers(void)
{
	uint64_t	count;
	uint32_t	period;
	char		buf[32];

	CHECK(countIs("0", 0), "0");
	CHECK(countIs("1500", 1500), "plain");
	CHECK(countIs("10k", 10000), "k");
	CHECK(countIs("1M", 1000000), "M");
	CHECK(countIs("2G", 2000000000ULL), "G");
	CHECK(countIs("1000G", QUOTA_MAX_COUNT), "max");
	CHECK(countBad("1001G"), "over max");
	CHECK(countBad("1000000000001"), "over max, plain");
	CHECK(countBad("99999999999999999999999"), "overflow");
	CHECK(countBad("1.5M"), "fraction");
	CHECK(countBad("1K"), "binary-looking K");
	CHECK(countBad("1m"), "minutes are not a count");
	CHECK(countBad("1Mi"), "trailing text");
	CHECK(countBad(""), "empty");
	CHECK(countBad("M"), "suffix only");
	CHECK(countBad("-1"), "negative");
	CHECK(countBad(" 1"), "leading space");

	CHECK(periodIs("1", 1), "bare seconds");
	CHECK(periodIs("30s", 30), "s");
	CHECK(periodIs("2m", 120), "m");
	CHECK(periodIs("1h", 3600), "h");
	CHECK(periodIs("1d", 86400), "d");
	CHECK(periodIs("366d", QUOTA_MAX_PERIOD_S), "max");
	CHECK(periodBad("367d"), "over max");
	CHECK(periodBad("0s"), "zero");
	CHECK(periodBad("1w"), "weeks");
	CHECK(periodBad("s"), "suffix only");

	CHECK(quotaParseRate("1M/1s", &count, &period) == 0
			&& count == 1000000 && period == 1, "rate");
	CHECK(quotaParseRate("50000/1d", &count, &period) == 0
			&& count == 50000 && period == 86400, "daily rate");
	CHECK(quotaParseRate("0/1s", &count, &period) < 0, "zero count");
	CHECK(quotaParseRate("1M", &count, &period) < 0, "no timeframe");
	CHECK(quotaParseRate("/1s", &count, &period) < 0, "no count");
	CHECK(quotaParseRate("1M/", &count, &period) < 0, "empty timeframe");
	CHECK(quotaParseRate("1M/1s/1s", &count, &period) < 0, "two slashes");

	quotaFormatCount(1000000, buf, sizeof buf);
	CHECK(strcmp(buf, "1M") == 0, "format M");
	quotaFormatCount(1500, buf, sizeof buf);
	CHECK(strcmp(buf, "1500") == 0, "format plain");
	quotaFormatCount(25000, buf, sizeof buf);
	CHECK(strcmp(buf, "25k") == 0, "format k");
	quotaFormatCount(0, buf, sizeof buf);
	CHECK(strcmp(buf, "0") == 0, "format 0");
	quotaFormatPeriod(86400 * 30, buf, sizeof buf);
	CHECK(strcmp(buf, "30d") == 0, "format d");
	quotaFormatPeriod(90, buf, sizeof buf);
	CHECK(strcmp(buf, "90s") == 0, "format s");
	quotaFormatPeriod(120, buf, sizeof buf);
	CHECK(strcmp(buf, "2m") == 0, "format m");
}

/*	*	*	Patterns	*	*	*	*	*/

static int	matches(const char *pattern, const char *eid)
{
	QuotaPattern	p;

	if (quotaPatternParse(pattern, &p) < 0)
	{
		printf("  pattern '%s' did not parse\n", pattern);
		return -1;
	}

	return quotaPatternMatch(&p, eid);
}

static int	patternBad(const char *text)
{
	QuotaPattern	p;

	return quotaPatternParse(text, &p) < 0;
}

static void	testPatterns(void)
{
	char	longText[QUOTA_PATTERN_LEN + 2];

	CHECK(matches("*", "ipn:7.1") == 1, "* matches ipn");
	CHECK(matches("*", "dtn://a/b") == 1, "* matches dtn");
	CHECK(matches("*", NULL) == 0, "nothing matches no EID");

	CHECK(matches("ipn:7.1", "ipn:7.1") == 1, "exact ipn");
	CHECK(matches("ipn:7.1", "ipn:7.2") == 0, "other service");
	CHECK(matches("ipn:7.*", "ipn:7.0") == 1, "any service");
	CHECK(matches("ipn:7.*", "ipn:8.1") == 0, "other node");
	CHECK(matches("ipn:7.*", "ipn:70.1") == 0, "no prefix match");
	CHECK(matches("ipn:7.*", "ipn:7") == 0, "malformed EID");
	CHECK(matches("ipn:7.*", "ipn:7.1x") == 0, "trailing junk");
	CHECK(matches("ipn:7.*", "dtn://7.1") == 0, "other scheme");
	CHECK(matches("ipn:7-9.1", "ipn:8.1") == 1, "in range");
	CHECK(matches("ipn:7-9.1", "ipn:9.1") == 1, "range top");
	CHECK(matches("ipn:7-9.1", "ipn:10.1") == 0, "above range");
	CHECK(matches("ipn:7-9.1", "ipn:8.2") == 0, "range, other service");
	CHECK(matches("ipn:*.5", "ipn:123.5") == 1, "any node");
	CHECK(matches("ipn:*.*", "ipn:1.2.3") == 1, "3-element, any");
	CHECK(matches("ipn:2.*", "ipn:1.2.3") == 0, "3-element, node");
	CHECK(matches("ipn:18446744073709551615.*",
			"ipn:18446744073709551615.0") == 1, "max node");

	CHECK(matches("dtn://host/*", "dtn://host/app") == 1, "prefix");
	CHECK(matches("dtn://host/*", "dtn://hostile/app") == 0,
			"prefix boundary");
	CHECK(matches("dtn://a/b", "dtn://a/b") == 1, "exact dtn");
	CHECK(matches("dtn://a/b", "dtn://a/bc") == 0, "exact, longer");

	CHECK(patternBad(""), "empty");
	CHECK(patternBad("ipn:7"), "no service");
	CHECK(patternBad("ipn:*"), "ipn star alone");
	CHECK(patternBad("ipn:9-7.*"), "inverted range");
	CHECK(patternBad("ipn:7-.*"), "open range");
	CHECK(patternBad("ipn:x.1"), "non-numeric node");
	CHECK(patternBad("ipn:1.2.3"), "3-element pattern");
	CHECK(patternBad("ipn:18446744073709551616.1"), "node overflow");
	CHECK(patternBad("dtn://*/x"), "inner star");
	CHECK(patternBad("a b"), "space");
	CHECK(patternBad("a\tb"), "tab");
	memset(longText, 'a', sizeof longText - 1);
	longText[sizeof longText - 1] = '\0';
	CHECK(patternBad(longText), "too long");
}

/*	*	*	Rules	*	*	*	*	*	*/

static int	parse(const char *line, QuotaRule *rule, const char **why)
{
	char	buf[1024];
	char	*argv[32];
	char	*save = NULL;
	char	*token;
	int	argc = 0;

	snprintf(buf, sizeof buf, "%s", line);
	for (token = strtok_r(buf, " ", &save); token && argc < 32;
			token = strtok_r(NULL, " ", &save))
	{
		argv[argc++] = token;
	}

	return quotaParseRule(argc, argv, rule, why);
}

static void	testRules(void)
{
	QuotaRule	rule;
	QuotaRule	again;
	const char	*why;
	char		text[1024];

	memset(&rule, 0, sizeof rule);
	CHECK(parse("cam quota/20 src ipn:7.* dst ipn:20-29.* prev ipn:30.0 \
hold 10M stall", &rule, &why) == 0, "full rule");
	CHECK(strcmp(rule.name, "cam") == 0, "name");
	CHECK(strcmp(rule.duct, "20") == 0, "duct without prefix");
	CHECK(strcmp(rule.src, "ipn:7.*") == 0, "src");
	CHECK(strcmp(rule.dst, "ipn:20-29.*") == 0, "dst");
	CHECK(strcmp(rule.prev, "ipn:30.0") == 0, "prev");
	CHECK(rule.hasHold && rule.holdBytes == 10000000, "hold");
	CHECK(rule.action == QuotaStall, "action");

	quotaFormatRule(&rule, text, sizeof text);
	memset(&again, 0, sizeof again);
	CHECK(parse(text, &again, &why) == 0
			&& memcmp(&rule, &again, sizeof rule) == 0,
			"format and parse again");

	memset(&rule, 0, sizeof rule);
	CHECK(parse("all quota/udp/1 hold 0", &rule, &why) == 0,
			"duct with slash");
	CHECK(strcmp(rule.duct, "udp/1") == 0, "duct keeps slash");
	CHECK(rule.hasHold && rule.holdBytes == 0 && rule.action == QuotaDrop,
			"hold defaults to drop");
	CHECK(rule.src[0] == '\0', "no src");

	/*	A change keeps quotas and serial.			*/

	rule.quotaCount = 1;
	rule.quotas[0].kind = QuotaBytes;
	rule.quotas[0].count = 5;
	rule.quotas[0].periodS = 1;
	rule.serial = 77;
	CHECK(parse("all quota/9 src ipn:1.*", &rule, &why) == 0, "change");
	CHECK(rule.quotaCount == 1 && rule.quotas[0].count == 5
			&& rule.serial == 77, "change keeps quotas");
	CHECK(!rule.hasHold && strcmp(rule.duct, "9") == 0,
			"change replaces fields");
	CHECK(quotaFindSpec(&rule, QuotaBytes, 1) == 0, "find quota");
	CHECK(quotaFindSpec(&rule, QuotaBundles, 1) < 0, "other kind");
	CHECK(quotaFindSpec(&rule, QuotaBytes, 2) < 0, "other timeframe");

	memset(&rule, 0, sizeof rule);
	CHECK(parse("cam 20", &rule, &why) < 0, "duct without prefix");
	CHECK(parse("cam quota/", &rule, &why) < 0, "empty duct");
	CHECK(parse("cam", &rule, &why) < 0, "no duct");
	CHECK(parse("c:am quota/1", &rule, &why) < 0, "bad name");
	CHECK(parse("abcdefghijklmnopqrstuvwxyz0123456 quota/1", &rule, &why)
			< 0, "name too long");
	CHECK(parse("cam quota/1 src ipn:1.* src ipn:2.*", &rule, &why) < 0,
			"src twice");
	CHECK(parse("cam quota/1 src", &rule, &why) < 0, "missing value");
	CHECK(parse("cam quota/1 src ipn:7", &rule, &why) < 0, "bad pattern");
	CHECK(parse("cam quota/1 next ipn:7.*", &rule, &why) < 0,
			"no next field");
	CHECK(parse("cam quota/1 hold 1M drop hold 2M", &rule, &why) < 0,
			"hold twice");
	CHECK(parse("cam quota/1 hold 1X", &rule, &why) < 0, "bad hold");
	CHECK(parse("cam quota/1 hold 1M explode", &rule, &why) < 0,
			"bad action");
	CHECK(rule.name[0] == '\0', "failed parse leaves rule alone");
}

/*	*	*	Buckets	*	*	*	*	*	*/

static void	testBuckets(void)
{
	QuotaBucket	b;
	int		i;

	/*	1000 bytes per second, burst 1000.			*/

	quotaBucketInit(&b, 1000, 1000, 5000);
	CHECK(quotaBucketFits(&b, 1000), "starts full");
	quotaBucketCharge(&b, 600);
	CHECK(b.level == 400, "charge");
	CHECK(!quotaBucketFits(&b, 500), "short");
	CHECK(quotaBucketWaitMs(&b, 500) == 100, "wait for 100 tokens");
	quotaBucketRefill(&b, 5100);
	CHECK(b.level == 500 && quotaBucketFits(&b, 500), "refilled 100");
	quotaBucketRefill(&b, 99999);
	CHECK(b.level == 1000 && b.frac == 0, "capped at capacity");

	/*	A clock that went backwards accrues nothing.		*/

	quotaBucketCharge(&b, 1000);
	quotaBucketRefill(&b, 1000);
	CHECK(b.level == 0, "backwards: no accrual");
	quotaBucketRefill(&b, 1010);
	CHECK(b.level == 10, "accrues from the new stamp");

	/*	Fractions accumulate exactly: 1 token per 3 s, refilled
	 *	every millisecond.					*/

	quotaBucketInit(&b, 1, 3000, 0);
	quotaBucketCharge(&b, 1);
	for (i = 1; i < 3000; i++)
	{
		quotaBucketRefill(&b, (uint64_t) i);
	}

	CHECK(b.level == 0, "not yet");
	CHECK(quotaBucketWaitMs(&b, 1) == 1, "one ms to go");
	quotaBucketRefill(&b, 3000);
	CHECK(b.level == 1, "exactly one token after 3 s");

	/*	Oversize: passes once full, then debt.			*/

	quotaBucketInit(&b, 1000, 1000, 0);
	CHECK(quotaBucketFits(&b, 5000), "oversize passes when full");
	quotaBucketCharge(&b, 5000);
	CHECK(b.level == -4000, "debt");
	CHECK(!quotaBucketFits(&b, 1), "nothing while in debt");
	CHECK(quotaBucketWaitMs(&b, 1) == 4001, "wait out the debt");
	CHECK(quotaBucketWaitMs(&b, 5000) == 5000, "oversize waits for full");
	quotaBucketRefill(&b, 4001);
	CHECK(b.level == 1 && quotaBucketFits(&b, 1), "debt paid");
	quotaBucketCharge(&b, 1);
	quotaBucketRefill(&b, 4500);
	CHECK(!quotaBucketFits(&b, 5000), "oversize waits until full");

	/*	Large: 1000G per 366 d, and a long outage.		*/

	quotaBucketInit(&b, QUOTA_MAX_COUNT,
			(uint64_t) QUOTA_MAX_PERIOD_S * 1000, 0);
	quotaBucketCharge(&b, QUOTA_MAX_COUNT);
	quotaBucketRefill(&b, (uint64_t) QUOTA_MAX_PERIOD_S * 500);
	CHECK(b.level == (int64_t) (QUOTA_MAX_COUNT / 2), "half a year");
	CHECK(quotaBucketWaitMs(&b, QUOTA_MAX_COUNT)
			== (uint64_t) QUOTA_MAX_PERIOD_S * 500, "wait half");
	quotaBucketRefill(&b, UINT64_MAX / 2);
	CHECK(b.level == (int64_t) QUOTA_MAX_COUNT, "huge gap: full");

	quotaBucketInit(&b, 10, 1000, 0);
	quotaBucketCharge(&b, UINT64_MAX);
	CHECK(b.level < 0 && b.level > INT64_MIN / 2, "huge charge bounded");
	quotaBucketRefill(&b, UINT64_MAX);
	CHECK(b.level < 0, "deep debt refills partly");

	/*	Resize keeps the level, clipped.			*/

	quotaBucketInit(&b, 1000, 1000, 0);
	quotaBucketCharge(&b, 200);
	quotaBucketResize(&b, 2000, 1000);
	CHECK(b.level == 800 && b.count == 2000, "grow keeps level");
	quotaBucketResize(&b, 500, 1000);
	CHECK(b.level == 500, "shrink clips");
	quotaBucketCharge(&b, 500);
	quotaBucketRefill(&b, 1);
	CHECK(b.frac == 500, "fraction before resize");
	quotaBucketResize(&b, 500, 2000);
	CHECK(b.frac == 1000 && b.periodMs == 2000, "fraction rescaled");
}

/*	*	*	State file	*	*	*	*	*/

static void	testState(void)
{
	QuotaStateLine	in;
	QuotaStateLine	out;
	char		buf[1100];
	char		longLine[2000];

	memset(&in, 0, sizeof in);
	in.type = QuotaLineHeader;
	strcpy(in.name, "udp/1");
	in.unixTime = 1761800000;
	in.infoServed = 42;
	CHECK(quotaFormatStateLine(&in, buf, sizeof buf) > 0, "fmt header");
	buf[strcspn(buf, "\n")] = '\0';
	CHECK(quotaParseStateLine(buf, &out) == 0
			&& memcmp(&in, &out, sizeof in) == 0, "header round");

	memset(&in, 0, sizeof in);
	in.type = QuotaLineBucket;
	strcpy(in.name, "cam");
	in.kind = QuotaBundles;
	in.periodS = 86400;
	in.level = -12345;
	in.frac = 999;
	CHECK(quotaFormatStateLine(&in, buf, sizeof buf) > 0, "fmt bucket");
	buf[strcspn(buf, "\n")] = '\0';
	CHECK(quotaParseStateLine(buf, &out) == 0
			&& memcmp(&in, &out, sizeof in) == 0, "bucket round");

	memset(&in, 0, sizeof in);
	in.type = QuotaLineCounters;
	strcpy(in.name, "cam");
	in.counters.passed = 1;
	in.counters.passedBytes = UINT64_MAX;
	in.counters.held = 3;
	in.counters.heldBytes = 4;
	in.counters.dropped = 5;
	in.counters.droppedBytes = 6;
	in.counters.reforwarded = 7;
	in.counters.stalledMs = 8;
	CHECK(quotaFormatStateLine(&in, buf, sizeof buf) > 0, "fmt counters");
	buf[strcspn(buf, "\n")] = '\0';
	CHECK(quotaParseStateLine(buf, &out) == 0
			&& memcmp(&in, &out, sizeof in) == 0, "counters round");

	CHECK(quotaParseStateLine("", &out) == 0
			&& out.type == QuotaLineOther, "empty line");
	CHECK(quotaParseStateLine("x future line", &out) == 0
			&& out.type == QuotaLineOther, "unknown line");
	CHECK(quotaParseStateLine("quota-state 2 d 1 1", &out) < 0,
			"other version");
	CHECK(quotaParseStateLine("b cam bytes 0 1 0", &out) < 0,
			"zero period");
	CHECK(quotaParseStateLine("b cam bytes 1 1", &out) < 0, "short");
	CHECK(quotaParseStateLine("b cam litres 1 1 0", &out) < 0, "kind");
	CHECK(quotaParseStateLine("b c:m bytes 1 1 0", &out) < 0, "name");
	CHECK(quotaParseStateLine("b cam bytes 1 99999999999999999999 0",
			&out) < 0, "level overflow");
	CHECK(quotaParseStateLine("b cam bytes 1 -9223372036854775808 0",
			&out) == 0 && out.level == INT64_MIN, "level minimum");
	CHECK(quotaParseStateLine("c cam 1 2 3 4 5 6 7", &out) < 0,
			"counters short");
	CHECK(quotaParseStateLine("c cam 1 2 3 4 5 6 7 8 9", &out) < 0,
			"counters long");
	memset(longLine, 'b', sizeof longLine - 1);
	longLine[sizeof longLine - 1] = '\0';
	CHECK(quotaParseStateLine(longLine, &out) < 0, "long known line");
	longLine[0] = 'z';
	CHECK(quotaParseStateLine(longLine, &out) == 0
			&& out.type == QuotaLineOther, "long unknown line");
	CHECK(quotaFormatStateLine(&in, buf, 10) < 0, "buffer too small");
}

int	main(void)
{
	testNumbers();
	testPatterns();
	testRules();
	testBuckets();
	testState();
	if (failures)
	{
		printf("%d check(s) failed\n", failures);
		return 1;
	}

	printf("all quotarules checks passed\n");
	return 0;
}
