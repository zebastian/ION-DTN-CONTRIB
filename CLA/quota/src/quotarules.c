/*	quotarules.c:	rules, EID patterns, token buckets and the state
			file format of the quota CLA (see quotarules.h).
			Plain C, no ION.				*/

#include "quotarules.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*	*	*	Arithmetic	*	*	*	*	*/

/*	Token arithmetic multiplies counts of up to 10^12 by spans of
 *	up to 2^55 ms, which overflows 64 bits.  These do the 128-bit
 *	steps portably: no __int128 on 32-bit targets.		*/

static void	mul64(uint64_t a, uint64_t b, uint64_t *hi, uint64_t *lo)
{
	uint64_t	aLo = a & 0xffffffffU;
	uint64_t	aHi = a >> 32;
	uint64_t	bLo = b & 0xffffffffU;
	uint64_t	bHi = b >> 32;
	uint64_t	ll = aLo * bLo;
	uint64_t	lh = aLo * bHi;
	uint64_t	hl = aHi * bLo;
	uint64_t	hh = aHi * bHi;
	uint64_t	mid = (ll >> 32) + (lh & 0xffffffffU)
				+ (hl & 0xffffffffU);

	*lo = (mid << 32) | (ll & 0xffffffffU);
	*hi = hh + (lh >> 32) + (hl >> 32) + (mid >> 32);
}

static void	add128(uint64_t *hi, uint64_t *lo, uint64_t v)
{
	uint64_t	sum = *lo + v;

	if (sum < *lo)
	{
		(*hi)++;
	}

	*lo = sum;
}

static void	sub128(uint64_t *hi, uint64_t *lo, uint64_t v)
{
	if (*lo < v)
	{
		(*hi)--;
	}

	*lo -= v;
}

/*	(hi:lo) / d, saturating at UINT64_MAX when the quotient does not
 *	fit; the remainder goes to *rem (undefined when saturated).	*/
static uint64_t	div128(uint64_t hi, uint64_t lo, uint64_t d, uint64_t *rem)
{
	uint64_t	r = hi;
	uint64_t	q = 0;
	int		i;

	if (hi >= d)
	{
		*rem = 0;
		return UINT64_MAX;
	}

	for (i = 63; i >= 0; i--)
	{
		uint64_t	carry = r >> 63;

		r = (r << 1) | ((lo >> i) & 1U);
		q <<= 1;
		if (carry || r >= d)
		{
			r -= d;
			q |= 1U;
		}
	}

	*rem = r;
	return q;
}

/*	*	*	Numbers	*	*	*	*	*	*/

/*	Leading decimal digits of text, at least one; the rest is left
 *	in *end.  -1 on overflow of limit.				*/
static int	parseDigits(const char *text, uint64_t limit, uint64_t *value,
			const char **end)
{
	uint64_t	v = 0;
	const char	*cursor = text;

	if (*cursor < '0' || *cursor > '9')
	{
		return -1;
	}

	while (*cursor >= '0' && *cursor <= '9')
	{
		uint64_t	digit = (uint64_t) (*cursor - '0');

		if (v > (limit - digit) / 10)
		{
			return -1;
		}

		v = v * 10 + digit;
		cursor++;
	}

	*value = v;
	*end = cursor;
	return 0;
}

int	quotaParseCount(const char *text, uint64_t *value)
{
	uint64_t	v;
	uint64_t	scale = 1;
	const char	*end;

	if (text == NULL || parseDigits(text, QUOTA_MAX_COUNT, &v, &end) < 0)
	{
		return -1;
	}

	switch (*end)
	{
	case '\0':
		break;

	case 'k':
		scale = 1000;
		end++;
		break;

	case 'M':
		scale = 1000000;
		end++;
		break;

	case 'G':
		scale = 1000000000;
		end++;
		break;

	default:
		return -1;
	}

	if (*end != '\0' || v > QUOTA_MAX_COUNT / scale)
	{
		return -1;
	}

	*value = v * scale;
	return 0;
}

int	quotaParsePeriod(const char *text, uint32_t *seconds)
{
	uint64_t	v;
	uint64_t	scale = 1;
	const char	*end;

	if (text == NULL || parseDigits(text, QUOTA_MAX_PERIOD_S, &v, &end) < 0)
	{
		return -1;
	}

	switch (*end)
	{
	case '\0':
		break;

	case 's':
		end++;
		break;

	case 'm':
		scale = 60;
		end++;
		break;

	case 'h':
		scale = 3600;
		end++;
		break;

	case 'd':
		scale = 86400;
		end++;
		break;

	default:
		return -1;
	}

	if (*end != '\0' || v == 0 || v > QUOTA_MAX_PERIOD_S / scale)
	{
		return -1;
	}

	*seconds = (uint32_t) (v * scale);
	return 0;
}

int	quotaParseRate(const char *text, uint64_t *count, uint32_t *seconds)
{
	char		buf[64];
	const char	*slash;
	size_t		len;

	if (text == NULL || (slash = strchr(text, '/')) == NULL)
	{
		return -1;
	}

	len = (size_t) (slash - text);
	if (len == 0 || len >= sizeof buf)
	{
		return -1;
	}

	memcpy(buf, text, len);
	buf[len] = '\0';
	if (quotaParseCount(buf, count) < 0 || *count == 0
	|| quotaParsePeriod(slash + 1, seconds) < 0)
	{
		return -1;
	}

	return 0;
}

void	quotaFormatCount(uint64_t value, char *buf, size_t size)
{
	if (value != 0 && value % 1000000000U == 0)
	{
		snprintf(buf, size, "%lluG",
				(unsigned long long) (value / 1000000000U));
	}
	else if (value != 0 && value % 1000000U == 0)
	{
		snprintf(buf, size, "%lluM",
				(unsigned long long) (value / 1000000U));
	}
	else if (value != 0 && value % 1000U == 0)
	{
		snprintf(buf, size, "%lluk",
				(unsigned long long) (value / 1000U));
	}
	else
	{
		snprintf(buf, size, "%llu", (unsigned long long) value);
	}
}

void	quotaFormatPeriod(uint32_t seconds, char *buf, size_t size)
{
	if (seconds != 0 && seconds % 86400U == 0)
	{
		snprintf(buf, size, "%lud", (unsigned long) (seconds / 86400U));
	}
	else if (seconds != 0 && seconds % 3600U == 0)
	{
		snprintf(buf, size, "%luh", (unsigned long) (seconds / 3600U));
	}
	else if (seconds != 0 && seconds % 60U == 0)
	{
		snprintf(buf, size, "%lum", (unsigned long) (seconds / 60U));
	}
	else
	{
		snprintf(buf, size, "%lus", (unsigned long) seconds);
	}
}

int	quotaParseKind(const char *text, QuotaKind *kind)
{
	if (text != NULL && strcmp(text, "bytes") == 0)
	{
		*kind = QuotaBytes;
		return 0;
	}

	if (text != NULL && strcmp(text, "bundles") == 0)
	{
		*kind = QuotaBundles;
		return 0;
	}

	return -1;
}

const char	*quotaKindName(QuotaKind kind)
{
	return kind == QuotaBundles ? "bundles" : "bytes";
}

int	quotaParseAction(const char *text, QuotaAction *action)
{
	if (text == NULL)
	{
		return -1;
	}

	if (strcmp(text, "drop") == 0)
	{
		*action = QuotaDrop;
	}
	else if (strcmp(text, "stall") == 0)
	{
		*action = QuotaStall;
	}
	else if (strcmp(text, "reforward") == 0)
	{
		*action = QuotaReforward;
	}
	else
	{
		return -1;
	}

	return 0;
}

const char	*quotaActionName(QuotaAction action)
{
	switch (action)
	{
	case QuotaStall:
		return "stall";

	case QuotaReforward:
		return "reforward";

	default:
		return "drop";
	}
}

/*	*	*	EID patterns	*	*	*	*	*/

/*	A node or service number: digits only, at most 64 bits.	*/
static int	parseNumber(const char *text, size_t len, uint64_t *value)
{
	char		buf[24];
	const char	*end;

	if (len == 0 || len >= sizeof buf)
	{
		return -1;
	}

	memcpy(buf, text, len);
	buf[len] = '\0';
	if (parseDigits(buf, UINT64_MAX, value, &end) < 0 || *end != '\0')
	{
		return -1;
	}

	return 0;
}

static int	parseIpnPattern(const char *ssp, QuotaPattern *pattern)
{
	const char	*dot = strchr(ssp, '.');
	const char	*dash;
	const char	*service;
	size_t		nodeLen;

	if (dot == NULL)
	{
		return -1;
	}

	nodeLen = (size_t) (dot - ssp);
	service = dot + 1;
	if (nodeLen == 1 && ssp[0] == '*')
	{
		pattern->anyNode = 1;
	}
	else
	{
		dash = memchr(ssp, '-', nodeLen);
		if (dash == NULL)
		{
			if (parseNumber(ssp, nodeLen, &pattern->nodeLo) < 0)
			{
				return -1;
			}

			pattern->nodeHi = pattern->nodeLo;
		}
		else if (parseNumber(ssp, (size_t) (dash - ssp),
				&pattern->nodeLo) < 0
		|| parseNumber(dash + 1, nodeLen - (size_t) (dash - ssp) - 1,
				&pattern->nodeHi) < 0
		|| pattern->nodeLo > pattern->nodeHi)
		{
			return -1;
		}
	}

	if (strcmp(service, "*") == 0)
	{
		pattern->anyService = 1;
	}
	else if (parseNumber(service, strlen(service), &pattern->service) < 0)
	{
		return -1;
	}

	pattern->type = QuotaPatIpn;
	return 0;
}

int	quotaPatternParse(const char *text, QuotaPattern *pattern)
{
	size_t		len;
	size_t		i;
	const char	*star;

	if (text == NULL || pattern == NULL)
	{
		return -1;
	}

	memset(pattern, 0, sizeof *pattern);
	len = strlen(text);
	if (len == 0 || len > QUOTA_PATTERN_LEN)
	{
		return -1;
	}

	for (i = 0; i < len; i++)
	{
		unsigned char	c = (unsigned char) text[i];

		if (c <= ' ' || c >= 0x7f)
		{
			return -1;
		}
	}

	memcpy(pattern->text, text, len + 1);
	pattern->textLen = len;
	if (len == 1 && text[0] == '*')
	{
		pattern->type = QuotaPatAny;
		return 0;
	}

	if (strncmp(text, "ipn:", 4) == 0)
	{
		return parseIpnPattern(text + 4, pattern);
	}

	/*	Otherwise '*' may only end the pattern, so nobody writes
	 *	a glob that quietly means something else.		*/

	star = strchr(text, '*');
	if (star == NULL)
	{
		pattern->type = QuotaPatExact;
		return 0;
	}

	if (star != text + len - 1)
	{
		return -1;
	}

	pattern->type = QuotaPatPrefix;
	pattern->textLen = len - 1;
	pattern->text[len - 1] = '\0';
	return 0;
}

/*	Splits "ipn:N.S" or "ipn:A.N.S" into numbers; returns how many
 *	elements it found (2 or 3), or -1 if the EID is not ipn.	*/
static int	splitIpnEid(const char *eid, uint64_t elements[3])
{
	const char	*cursor;
	const char	*end;
	int		n = 0;

	if (strncmp(eid, "ipn:", 4) != 0)
	{
		return -1;
	}

	cursor = eid + 4;
	for (;;)
	{
		if (n == 3 || parseDigits(cursor, UINT64_MAX, &elements[n],
				&end) < 0)
		{
			return -1;
		}

		n++;
		if (*end == '\0')
		{
			break;
		}

		if (*end != '.')
		{
			return -1;
		}

		cursor = end + 1;
	}

	return n >= 2 ? n : -1;
}

int	quotaPatternMatch(const QuotaPattern *pattern, const char *eid)
{
	uint64_t	elements[3];
	int		n;

	if (pattern == NULL || eid == NULL)
	{
		return 0;
	}

	switch (pattern->type)
	{
	case QuotaPatAny:
		return 1;

	case QuotaPatExact:
		return strcmp(pattern->text, eid) == 0;

	case QuotaPatPrefix:
		return strncmp(pattern->text, eid, pattern->textLen) == 0;

	case QuotaPatIpn:
		n = splitIpnEid(eid, elements);
		if (n < 0)
		{
			return 0;
		}

		if (n == 3)
		{
			return pattern->anyNode && pattern->anyService;
		}

		if (!pattern->anyNode && (elements[0] < pattern->nodeLo
				|| elements[0] > pattern->nodeHi))
		{
			return 0;
		}

		return pattern->anyService || elements[1] == pattern->service;
	}

	return 0;
}

/*	*	*	Rules	*	*	*	*	*	*/

static int	printableWord(const char *word, size_t max);

int	quotaValidName(const char *name)
{
	size_t	len;
	size_t	i;

	if (name == NULL)
	{
		return 0;
	}

	len = strlen(name);
	if (len == 0 || len > QUOTA_NAME_LEN)
	{
		return 0;
	}

	for (i = 0; i < len; i++)
	{
		char	c = name[i];

		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
				|| (c >= '0' && c <= '9') || c == '_'
				|| c == '-' || c == '.'))
		{
			return 0;
		}
	}

	return 1;
}

static int	setPattern(char *field, const char *text, const char **why)
{
	QuotaPattern	pattern;

	if (field[0] != '\0')
	{
		*why = "field given twice";
		return -1;
	}

	if (quotaPatternParse(text, &pattern) < 0)
	{
		*why = "bad EID pattern";
		return -1;
	}

	strcpy(field, text);		/*	Length checked by parse.	*/
	return 0;
}

int	quotaParseRule(int argc, char **argv, QuotaRule *rule,
		const char **why)
{
	QuotaRule	r;
	const char	*duct;
	int		i;

	*why = NULL;
	if (argc < 2)
	{
		*why = "need a rule name and a quota duct";
		return -1;
	}

	if (!quotaValidName(argv[0]))
	{
		*why = "bad rule name";
		return -1;
	}

	if (strncmp(argv[1], "quota/", 6) != 0)
	{
		*why = "the duct must be given as quota/<duct name>";
		return -1;
	}

	duct = argv[1] + 6;
	if (!printableWord(duct, QUOTA_DUCT_LEN))
	{
		*why = "bad duct name";
		return -1;
	}

	memcpy(&r, rule, sizeof r);
	memset(r.name, 0, sizeof r.name);
	memset(r.duct, 0, sizeof r.duct);
	memset(r.src, 0, sizeof r.src);
	memset(r.dst, 0, sizeof r.dst);
	memset(r.prev, 0, sizeof r.prev);
	r.hasHold = 0;
	r.holdBytes = 0;
	r.action = QuotaDrop;
	strcpy(r.name, argv[0]);
	strcpy(r.duct, duct);
	for (i = 2; i < argc; i++)
	{
		const char	*key = argv[i];
		const char	*value = (i + 1 < argc) ? argv[i + 1] : NULL;
		char		*field = NULL;

		if (value == NULL)
		{
			*why = "missing value";
			return -1;
		}

		if (strcmp(key, "src") == 0)
		{
			field = r.src;
		}
		else if (strcmp(key, "dst") == 0)
		{
			field = r.dst;
		}
		else if (strcmp(key, "prev") == 0)
		{
			field = r.prev;
		}

		if (field != NULL)
		{
			if (setPattern(field, value, why) < 0)
			{
				return -1;
			}

			i++;
			continue;
		}

		if (strcmp(key, "hold") != 0 || r.hasHold)
		{
			*why = "unknown or repeated keyword";
			return -1;
		}

		if (quotaParseCount(value, &r.holdBytes) < 0)
		{
			*why = "bad hold size";
			return -1;
		}

		r.hasHold = 1;
		i++;
		if (i + 1 < argc && quotaParseAction(argv[i + 1], &r.action) == 0)
		{
			i++;
		}
	}

	memcpy(rule, &r, sizeof r);
	return 0;
}

int	quotaFindSpec(const QuotaRule *rule, QuotaKind kind, uint32_t periodS)
{
	int	i;

	for (i = 0; i < rule->quotaCount && i < QUOTA_MAX_QUOTAS; i++)
	{
		if (rule->quotas[i].kind == kind
		&& rule->quotas[i].periodS == periodS)
		{
			return i;
		}
	}

	return -1;
}

void	quotaFormatRule(const QuotaRule *rule, char *buf, size_t size)
{
	char	hold[32];
	size_t	len;

	snprintf(buf, size, "%s quota/%s", rule->name, rule->duct);
	if (rule->src[0])
	{
		len = strlen(buf);
		snprintf(buf + len, size - len, " src %s", rule->src);
	}

	if (rule->dst[0])
	{
		len = strlen(buf);
		snprintf(buf + len, size - len, " dst %s", rule->dst);
	}

	if (rule->prev[0])
	{
		len = strlen(buf);
		snprintf(buf + len, size - len, " prev %s", rule->prev);
	}

	if (rule->hasHold)
	{
		quotaFormatCount(rule->holdBytes, hold, sizeof hold);
		len = strlen(buf);
		snprintf(buf + len, size - len, " hold %s %s", hold,
				quotaActionName(rule->action));
	}
}

/*	*	*	Token buckets	*	*	*	*	*/

/*	Bound on the debt and on a single charge, far from overflow.	*/
#define	BUCKET_FLOOR	(INT64_MIN / 4)
#define	CHARGE_MAX	((uint64_t) (INT64_MAX / 4))

/*	Refill accrues at most 2^20 periods at once, so that what it
 *	adds, count * 2^20, stays inside int64.			*/
#define	MAX_ACCRUAL	(1U << 20)

void	quotaBucketInit(QuotaBucket *bucket, uint64_t count,
		uint64_t periodMs, uint64_t nowMs)
{
	bucket->count = count > 0 ? count : 1;
	bucket->periodMs = periodMs > 0 ? periodMs : 1;
	bucket->level = (int64_t) bucket->count;
	bucket->frac = 0;
	bucket->stampMs = nowMs;
}

static int	bucketFull(const QuotaBucket *bucket)
{
	return bucket->level >= (int64_t) bucket->count;
}

void	quotaBucketRefill(QuotaBucket *bucket, uint64_t nowMs)
{
	uint64_t	elapsed;
	uint64_t	hi;
	uint64_t	lo;
	uint64_t	add;

	if (nowMs <= bucket->stampMs)
	{
		bucket->stampMs = nowMs;
		return;
	}

	elapsed = nowMs - bucket->stampMs;
	bucket->stampMs = nowMs;
	if (bucketFull(bucket))
	{
		bucket->level = (int64_t) bucket->count;
		bucket->frac = 0;
		return;
	}

	if (elapsed > bucket->periodMs * MAX_ACCRUAL)
	{
		elapsed = bucket->periodMs * MAX_ACCRUAL;
	}

	mul64(bucket->count, elapsed, &hi, &lo);
	add128(&hi, &lo, bucket->frac);
	add = div128(hi, lo, bucket->periodMs, &bucket->frac);
	bucket->level += (int64_t) add;
	if (bucketFull(bucket))
	{
		bucket->level = (int64_t) bucket->count;
		bucket->frac = 0;
	}
}

int	quotaBucketFits(const QuotaBucket *bucket, uint64_t amount)
{
	if (amount > bucket->count)
	{
		return bucketFull(bucket);
	}

	return bucket->level >= (int64_t) amount;
}

void	quotaBucketCharge(QuotaBucket *bucket, uint64_t amount)
{
	if (amount > CHARGE_MAX)
	{
		amount = CHARGE_MAX;
	}

	bucket->level -= (int64_t) amount;
	if (bucket->level < BUCKET_FLOOR)
	{
		bucket->level = BUCKET_FLOOR;
		bucket->frac = 0;
	}
}

uint64_t	quotaBucketWaitMs(const QuotaBucket *bucket, uint64_t amount)
{
	uint64_t	target = amount > bucket->count ? bucket->count : amount;
	uint64_t	need;
	uint64_t	hi;
	uint64_t	lo;
	uint64_t	rem;

	if (bucket->level >= (int64_t) target)
	{
		return 0;
	}

	/*	Tokens short, in units of 1/periodMs, less the fraction
	 *	already accrued; then ceil(that / count) ms.		*/

	need = (uint64_t) ((int64_t) target - bucket->level);
	mul64(need, bucket->periodMs, &hi, &lo);
	sub128(&hi, &lo, bucket->frac);
	add128(&hi, &lo, bucket->count - 1);
	return div128(hi, lo, bucket->count, &rem);
}

void	quotaBucketResize(QuotaBucket *bucket, uint64_t count,
		uint64_t periodMs)
{
	uint64_t	hi;
	uint64_t	lo;
	uint64_t	rem;

	if (count == 0)
	{
		count = 1;
	}

	if (periodMs == 0)
	{
		periodMs = 1;
	}

	if (periodMs != bucket->periodMs)
	{
		mul64(bucket->frac, periodMs, &hi, &lo);
		bucket->frac = div128(hi, lo, bucket->periodMs, &rem);
		if (bucket->frac >= periodMs)
		{
			bucket->frac = 0;
		}

		bucket->periodMs = periodMs;
	}

	bucket->count = count;
	if (bucketFull(bucket))
	{
		bucket->level = (int64_t) count;
		bucket->frac = 0;
	}
}

/*	*	*	State file	*	*	*	*	*/

#define	STATE_LINE_MAX	1024
#define	STATE_MAX_TOKENS	12

static int	parseU64(const char *text, uint64_t *value)
{
	const char	*end;

	if (parseDigits(text, UINT64_MAX, value, &end) < 0 || *end != '\0')
	{
		return -1;
	}

	return 0;
}

static int	parseI64(const char *text, int64_t *value)
{
	uint64_t	magnitude;

	if (text[0] == '-')
	{
		if (parseU64(text + 1, &magnitude) < 0
		|| magnitude > (uint64_t) INT64_MAX + 1U)
		{
			return -1;
		}

		*value = magnitude == (uint64_t) INT64_MAX + 1U ? INT64_MIN
				: -(int64_t) magnitude;
		return 0;
	}

	if (parseU64(text, &magnitude) < 0 || magnitude > (uint64_t) INT64_MAX)
	{
		return -1;
	}

	*value = (int64_t) magnitude;
	return 0;
}

/*	1 to max visible ASCII characters, as duct names in the file.	*/
static int	printableWord(const char *word, size_t max)
{
	size_t	len = strlen(word);
	size_t	i;

	if (len == 0 || len > max)
	{
		return 0;
	}

	for (i = 0; i < len; i++)
	{
		unsigned char	c = (unsigned char) word[i];

		if (c <= ' ' || c >= 0x7f)
		{
			return 0;
		}
	}

	return 1;
}

int	quotaParseStateLine(const char *line, QuotaStateLine *out)
{
	char		buf[STATE_LINE_MAX];
	char		*tokens[STATE_MAX_TOKENS + 1];
	char		*save = NULL;
	char		*token;
	int		n = 0;
	size_t		len;
	uint64_t	u;
	uint64_t	*counters[8];
	int		i;

	memset(out, 0, sizeof *out);
	out->type = QuotaLineOther;
	if (line == NULL)
	{
		return -1;
	}

	len = strlen(line);
	if (len >= sizeof buf)
	{
		return (line[0] == 'b' || line[0] == 'c' || line[0] == 'q')
				? -1 : 0;
	}

	memcpy(buf, line, len + 1);
	for (token = strtok_r(buf, " \t", &save); token;
			token = strtok_r(NULL, " \t", &save))
	{
		if (n == STATE_MAX_TOKENS)
		{
			return -1;
		}

		tokens[n++] = token;
	}

	if (n == 0)
	{
		return 0;
	}

	if (strcmp(tokens[0], "quota-state") == 0)
	{
		out->type = QuotaLineHeader;
		if (n != 5 || strcmp(tokens[1], "1") != 0
		|| !printableWord(tokens[2], QUOTA_DUCT_LEN)
		|| parseI64(tokens[3], &out->unixTime) < 0
		|| parseU64(tokens[4], &u) < 0 || u > UINT32_MAX)
		{
			return -1;
		}

		strcpy(out->name, tokens[2]);
		out->infoServed = (uint32_t) u;
		return 0;
	}

	if (strcmp(tokens[0], "b") == 0)
	{
		out->type = QuotaLineBucket;
		if (n != 6 || !quotaValidName(tokens[1])
		|| quotaParseKind(tokens[2], &out->kind) < 0
		|| parseU64(tokens[3], &u) < 0 || u == 0
		|| u > QUOTA_MAX_PERIOD_S
		|| parseI64(tokens[4], &out->level) < 0
		|| parseU64(tokens[5], &out->frac) < 0)
		{
			return -1;
		}

		strcpy(out->name, tokens[1]);
		out->periodS = (uint32_t) u;
		return 0;
	}

	if (strcmp(tokens[0], "c") == 0)
	{
		out->type = QuotaLineCounters;
		if (n != 10 || !quotaValidName(tokens[1]))
		{
			return -1;
		}

		counters[0] = &out->counters.passed;
		counters[1] = &out->counters.passedBytes;
		counters[2] = &out->counters.held;
		counters[3] = &out->counters.heldBytes;
		counters[4] = &out->counters.dropped;
		counters[5] = &out->counters.droppedBytes;
		counters[6] = &out->counters.reforwarded;
		counters[7] = &out->counters.stalledMs;
		for (i = 0; i < 8; i++)
		{
			if (parseU64(tokens[2 + i], counters[i]) < 0)
			{
				return -1;
			}
		}

		strcpy(out->name, tokens[1]);
		return 0;
	}

	return 0;
}

int	quotaFormatStateLine(const QuotaStateLine *line, char *buf, size_t size)
{
	const QuotaCounters	*c = &line->counters;
	int			n;

	switch (line->type)
	{
	case QuotaLineHeader:
		n = snprintf(buf, size, "quota-state 1 %s %lld %lu\n",
				line->name, (long long) line->unixTime,
				(unsigned long) line->infoServed);
		break;

	case QuotaLineBucket:
		n = snprintf(buf, size, "b %s %s %lu %lld %llu\n", line->name,
				quotaKindName(line->kind),
				(unsigned long) line->periodS,
				(long long) line->level,
				(unsigned long long) line->frac);
		break;

	case QuotaLineCounters:
		n = snprintf(buf, size,
				"c %s %llu %llu %llu %llu %llu %llu %llu %llu\n",
				line->name,
				(unsigned long long) c->passed,
				(unsigned long long) c->passedBytes,
				(unsigned long long) c->held,
				(unsigned long long) c->heldBytes,
				(unsigned long long) c->dropped,
				(unsigned long long) c->droppedBytes,
				(unsigned long long) c->reforwarded,
				(unsigned long long) c->stalledMs);
		break;

	default:
		return -1;
	}

	if (n < 0 || (size_t) n >= size)
	{
		return -1;
	}

	return n;
}
