/*	quotarules.h:	rules, EID patterns, token buckets and the state
			file format of the quota CLA.  Plain C, no ION:
			quotaclo and quotaadmin build on it, and the unit
			tests and the fuzz target link it alone.	*/

#ifndef QUOTARULES_H
#define QUOTARULES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	QUOTA_NAME_LEN		31	/*	Rule name, bytes.	*/
#define	QUOTA_DUCT_LEN		255	/*	MAX_CL_DUCT_NAME_LEN	*/
#define	QUOTA_PATTERN_LEN	255
#define	QUOTA_MAX_QUOTAS	8	/*	Per rule.		*/

#define	QUOTA_MAX_COUNT		1000000000000ULL	/*	1000G	*/
#define	QUOTA_MAX_PERIOD_S	(366U * 86400U)

typedef enum
{
	QuotaBytes = 0,
	QuotaBundles = 1
} QuotaKind;

typedef enum
{
	QuotaDrop = 0,
	QuotaStall = 1,
	QuotaReforward = 2
} QuotaAction;

/*	*	*	Numbers	*	*	*	*	*	*/

/*	A decimal count with an optional k, M or G suffix (powers of
 *	ten).  0 on success, -1 if the text is not one or exceeds
 *	QUOTA_MAX_COUNT.						*/
extern int	quotaParseCount(const char *text, uint64_t *value);

/*	A timeframe: a decimal number with an optional s, m, h or d
 *	suffix (seconds if none), 1 s to QUOTA_MAX_PERIOD_S.		*/
extern int	quotaParsePeriod(const char *text, uint32_t *seconds);

/*	"<count>/<timeframe>", count at least 1.			*/
extern int	quotaParseRate(const char *text, uint64_t *count,
			uint32_t *seconds);

/*	The shortest exact form: 1000000 -> "1M", 1500 -> "1500".	*/
extern void	quotaFormatCount(uint64_t value, char *buf, size_t size);
extern void	quotaFormatPeriod(uint32_t seconds, char *buf, size_t size);

extern int	quotaParseKind(const char *text, QuotaKind *kind);
extern const char	*quotaKindName(QuotaKind kind);
extern int	quotaParseAction(const char *text, QuotaAction *action);
extern const char	*quotaActionName(QuotaAction action);

/*	*	*	EID patterns	*	*	*	*	*/

/*	"*"			any EID
 *	"ipn:N.S"		that endpoint
 *	"ipn:N.*"		any service on node N
 *	"ipn:A-B.*", "ipn:A-B.S"	nodes A to B inclusive
 *	"ipn:*.*", "ipn:*.S"	any node
 *	"<text>*"		any EID starting with <text>
 *	"<text>"		exactly that EID
 *
 *	ipn patterns match ipn EIDs in their two-element form only,
 *	except that "ipn:*.*" matches every ipn EID.			*/

typedef enum
{
	QuotaPatAny = 0,
	QuotaPatIpn,
	QuotaPatExact,
	QuotaPatPrefix
} QuotaPatType;

typedef struct
{
	QuotaPatType	type;
	uint64_t	nodeLo;
	uint64_t	nodeHi;
	int		anyNode;
	uint64_t	service;
	int		anyService;
	char		text[QUOTA_PATTERN_LEN + 1];
	size_t		textLen;
} QuotaPattern;

/*	0 on success, -1 if the text is not a pattern.			*/
extern int	quotaPatternParse(const char *text, QuotaPattern *pattern);

/*	1 if eid matches, 0 if not; a NULL eid never matches.		*/
extern int	quotaPatternMatch(const QuotaPattern *pattern,
			const char *eid);

/*	*	*	Rules	*	*	*	*	*	*/

typedef struct
{
	QuotaKind	kind;
	uint64_t	count;
	uint32_t	periodS;
} QuotaSpec;

/*	A rule as quotaadmin stores it.  An empty pattern field means
 *	the field is not matched.					*/
typedef struct
{
	char		name[QUOTA_NAME_LEN + 1];
	char		duct[QUOTA_DUCT_LEN + 1];	/*	no "quota/"	*/
	char		src[QUOTA_PATTERN_LEN + 1];
	char		dst[QUOTA_PATTERN_LEN + 1];
	char		prev[QUOTA_PATTERN_LEN + 1];
	int		hasHold;
	uint64_t	holdBytes;
	QuotaAction	action;
	int		quotaCount;
	QuotaSpec	quotas[QUOTA_MAX_QUOTAS];

	/*	Set anew when the rule is added or reset: quotaclo keeps
	 *	bucket levels only while it stays the same.		*/

	uint32_t	serial;
} QuotaRule;

/*	Rule names: 1 to QUOTA_NAME_LEN of [A-Za-z0-9_.-].		*/
extern int	quotaValidName(const char *name);

/*	Parses the arguments of "a rule" / "c rule":
 *
 *	  <name> quota/<duct> [src P] [dst P] [prev P]
 *	  [hold <bytes> [drop|stall|reforward]]
 *
 *	into rule, leaving its quotas alone.  0 on success; -1 with a
 *	reason in *why otherwise.					*/
extern int	quotaParseRule(int argc, char **argv, QuotaRule *rule,
			const char **why);

/*	The index of the quota of that kind and timeframe, or -1.	*/
extern int	quotaFindSpec(const QuotaRule *rule, QuotaKind kind,
			uint32_t periodS);

/*	The rule's arguments as "a rule" takes them.			*/
extern void	quotaFormatRule(const QuotaRule *rule, char *buf,
			size_t size);

/*	*	*	Token buckets	*	*	*	*	*/

/*	count tokens per periodMs, capacity count.  The level is
 *	level + frac / periodMs tokens; it goes negative when a bundle
 *	larger than the capacity is let through.			*/
typedef struct
{
	uint64_t	count;
	uint64_t	periodMs;
	int64_t		level;
	uint64_t	frac;		/*	< periodMs		*/
	uint64_t	stampMs;
} QuotaBucket;

extern void	quotaBucketInit(QuotaBucket *bucket, uint64_t count,
			uint64_t periodMs, uint64_t nowMs);

/*	Adds what has accrued since the last refill, up to capacity.
 *	A clock that went backwards accrues nothing.			*/
extern void	quotaBucketRefill(QuotaBucket *bucket, uint64_t nowMs);

/*	1 if amount may be charged now: the level covers it, or it
 *	exceeds the capacity and the bucket is full.			*/
extern int	quotaBucketFits(const QuotaBucket *bucket, uint64_t amount);

extern void	quotaBucketCharge(QuotaBucket *bucket, uint64_t amount);

/*	Milliseconds of refill until amount fits; 0 if it fits now.	*/
extern uint64_t	quotaBucketWaitMs(const QuotaBucket *bucket,
			uint64_t amount);

/*	A new count or timeframe: the level is kept, clipped to the new
 *	capacity.							*/
extern void	quotaBucketResize(QuotaBucket *bucket, uint64_t count,
			uint64_t periodMs);

/*	*	*	State file	*	*	*	*	*/

/*	quotaclo keeps its bucket levels and counters in one text file
 *	per duct.  Lines:
 *
 *	  quota-state 1 <duct> <unix time> <info request served>
 *	  b <rule> bytes|bundles <period s> <level> <frac>
 *	  c <rule> <passed> <passed bytes> <held> <held bytes>
 *	    <dropped> <dropped bytes> <reforwarded> <stalled ms>
 *
 *	(the "c" line is one line).  Unknown lines are ignored, so the
 *	format can grow.						*/

typedef struct
{
	uint64_t	passed;
	uint64_t	passedBytes;
	uint64_t	held;
	uint64_t	heldBytes;
	uint64_t	dropped;
	uint64_t	droppedBytes;
	uint64_t	reforwarded;
	uint64_t	stalledMs;
} QuotaCounters;

typedef enum
{
	QuotaLineOther = 0,
	QuotaLineHeader,
	QuotaLineBucket,
	QuotaLineCounters
} QuotaLineType;

typedef struct
{
	QuotaLineType	type;
	char		name[QUOTA_DUCT_LEN + 1];	/*	duct or rule	*/
	int64_t		unixTime;
	uint32_t	infoServed;
	QuotaKind	kind;
	uint32_t	periodS;
	int64_t		level;
	uint64_t	frac;
	QuotaCounters	counters;
} QuotaStateLine;

/*	Parses one line, without its newline.  0 on success, with
 *	QuotaLineOther for a line that is not one of the above; -1 for
 *	a line of a known type that is malformed.			*/
extern int	quotaParseStateLine(const char *line, QuotaStateLine *out);

/*	Formats one line, with its newline.  Returns the length, or -1
 *	if it does not fit.						*/
extern int	quotaFormatStateLine(const QuotaStateLine *line, char *buf,
			size_t size);

#ifdef __cplusplus
}
#endif

#endif /* QUOTARULES_H */
