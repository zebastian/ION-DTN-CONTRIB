/*	quotaclo.c:	quota convergence-layer output daemon.  Shapes the
			bundles bpclm queues on its outduct by the rules
			quotaadmin keeps, and moves those that pass,
			unchanged, onto the target duct named on its
			command line (see doc/design.md).		*/

#include "quotacl.h"

#include <pthread.h>
#include <stdio.h>

typedef struct
{
	QuotaRule	rule;
	QuotaPattern	src;
	QuotaPattern	dst;
	QuotaPattern	prev;
	QuotaBucket	buckets[QUOTA_MAX_QUOTAS];
	QuotaCounters	counters;	/*	held: as of the last pass	*/
	uint64_t	passHeldBytes;	/*	counted during a pass	*/
	uint64_t	passHeld;
	uint64_t	stallSinceMs;	/*	0 = not stalling	*/
} RuleState;

/*	Bucket levels and counters read from the state file at start,
 *	applied to the rules as they are first loaded.		*/
typedef struct
{
	QuotaStateLine	*lines;
	int		count;
	uint64_t	downMs;		/*	since the file was written	*/
} SavedState;

typedef struct
{
	char		*ductName;
	VOutduct	*vduct;
	VOutduct	*target;
	char		targetExpr[MAX_CL_PROTOCOL_NAME_LEN
				+ MAX_CL_DUCT_NAME_LEN + 2];

	RuleState	*rules;
	int		ruleCount;
	int		rulesLoaded;
	unsigned int	loadedChange;
	unsigned int	infoServed;
	int		noDbNoted;
	SavedState	saved;

	uint64_t	nextSnapshotMs;

	/*	The ticker gives the duct semaphore at wakeAtMs.	*/

	pthread_mutex_t	mtx;
	pthread_cond_t	cv;
	uint64_t	wakeAtMs;
	int		shutdown;

	uint64_t	passed;
	uint64_t	unmatched;
	uint64_t	dropped;
	uint64_t	reforwarded;
} CloState;

static sm_SemId		quotacloSemaphore(sm_SemId *semid)
{
	static sm_SemId	semaphore = -1;

	if (semid)
	{
		semaphore = *semid;
	}

	return semaphore;
}

static void	shutDownClo(int signum)
{
	(void) signum;

	sm_SemEnd(quotacloSemaphore(NULL));
}

/*	*	*	State file	*	*	*	*	*/

static void	loadSavedState(CloState *st)
{
	char		path[MAXPATHLEN];
	char		line[1100];
	FILE		*f;
	QuotaStateLine	parsed;
	int		cap = 0;
	time_t		now = time(NULL);

	quotaclStatePath(st->ductName, path, sizeof path);
	f = fopen(path, "r");
	if (f == NULL)
	{
		return;
	}

	while (fgets(line, sizeof line, f))
	{
		line[strcspn(line, "\r\n")] = '\0';
		if (quotaParseStateLine(line, &parsed) < 0)
		{
			writeMemoNote("[?] quotaclo: bad line in state file",
					path);
			continue;
		}

		if (parsed.type == QuotaLineHeader)
		{
			if (strcmp(parsed.name, st->ductName) != 0)
			{
				writeMemoNote("[?] quotaclo: state file is for \
another duct, ignored", path);
				st->saved.count = 0;
				break;
			}

			st->infoServed = parsed.infoServed;
			st->saved.downMs = (parsed.unixTime > 0
					&& now > parsed.unixTime)
				? (uint64_t) (now - parsed.unixTime) * 1000 : 0;
			continue;
		}

		if (parsed.type == QuotaLineOther)
		{
			continue;
		}

		if (st->saved.count == cap)
		{
			QuotaStateLine	*bigger;

			cap = cap ? cap * 2 : 16;
			bigger = realloc(st->saved.lines,
					(size_t) cap * sizeof *bigger);
			if (bigger == NULL)
			{
				break;
			}

			st->saved.lines = bigger;
		}

		st->saved.lines[st->saved.count++] = parsed;
	}

	fclose(f);
}

/*	Applies what the state file holds for this rule, once.	*/
static void	applySavedState(CloState *st, RuleState *rs, uint64_t nowMs)
{
	int		i;
	int		q;
	QuotaStateLine	*line;

	for (i = 0; i < st->saved.count; i++)
	{
		line = &st->saved.lines[i];
		if (strcmp(line->name, rs->rule.name) != 0)
		{
			continue;
		}

		if (line->type == QuotaLineCounters)
		{
			rs->counters = line->counters;
			rs->counters.held = 0;
			rs->counters.heldBytes = 0;
			continue;
		}

		q = quotaFindSpec(&rs->rule, line->kind, line->periodS);
		if (q < 0)
		{
			continue;
		}

		/*	The level as saved, then what accrued while
		 *	quotaclo was down.				*/

		rs->buckets[q].level = line->level;
		rs->buckets[q].frac = line->frac < rs->buckets[q].periodMs
				? line->frac : 0;
		rs->buckets[q].stampMs = 0;
		quotaBucketRefill(&rs->buckets[q], st->saved.downMs);
		rs->buckets[q].stampMs = nowMs;
		if (rs->buckets[q].level > (int64_t) rs->buckets[q].count)
		{
			rs->buckets[q].level = (int64_t) rs->buckets[q].count;
		}
	}
}

/*	Writes the state file to a temporary name and renames it.	*/
static void	writeState(CloState *st)
{
	char		path[MAXPATHLEN];
	char		tmp[MAXPATHLEN + 8];
	char		line[1100];
	FILE		*f;
	QuotaStateLine	out;
	int		i;
	int		q;
	int		ok = 1;

	quotaclStatePath(st->ductName, path, sizeof path);
	isprintf(tmp, sizeof tmp, "%s.tmp", path);
	f = fopen(tmp, "w");
	if (f == NULL)
	{
		putSysErrmsg("quotaclo can't write state file", tmp);
		return;
	}

	memset(&out, 0, sizeof out);
	out.type = QuotaLineHeader;
	istrcpy(out.name, st->ductName, sizeof out.name);
	out.unixTime = (int64_t) time(NULL);
	out.infoServed = st->infoServed;
	if (quotaFormatStateLine(&out, line, sizeof line) < 0
	|| fputs(line, f) == EOF)
	{
		ok = 0;
	}

	for (i = 0; ok && i < st->ruleCount; i++)
	{
		RuleState	*rs = &st->rules[i];

		for (q = 0; ok && q < rs->rule.quotaCount; q++)
		{
			memset(&out, 0, sizeof out);
			out.type = QuotaLineBucket;
			istrcpy(out.name, rs->rule.name, sizeof out.name);
			out.kind = rs->rule.quotas[q].kind;
			out.periodS = rs->rule.quotas[q].periodS;
			out.level = rs->buckets[q].level;
			out.frac = rs->buckets[q].frac;
			if (quotaFormatStateLine(&out, line, sizeof line) < 0
			|| fputs(line, f) == EOF)
			{
				ok = 0;
			}
		}

		memset(&out, 0, sizeof out);
		out.type = QuotaLineCounters;
		istrcpy(out.name, rs->rule.name, sizeof out.name);
		out.counters = rs->counters;
		if (rs->stallSinceMs)
		{
			out.counters.stalledMs += quotaclNowMs()
					- rs->stallSinceMs;
		}

		if (ok && (quotaFormatStateLine(&out, line, sizeof line) < 0
				|| fputs(line, f) == EOF))
		{
			ok = 0;
		}
	}

	if (fclose(f) != 0)
	{
		ok = 0;
	}

	if (!ok || rename(tmp, path) != 0)
	{
		putSysErrmsg("quotaclo can't write state file", path);
		unlink(tmp);
	}
}

/*	*	*	Rules	*	*	*	*	*	*/

static int	compileRule(RuleState *rs)
{
	const QuotaRule	*r = &rs->rule;

	if ((r->src[0] && quotaPatternParse(r->src, &rs->src) < 0)
	|| (r->dst[0] && quotaPatternParse(r->dst, &rs->dst) < 0)
	|| (r->prev[0] && quotaPatternParse(r->prev, &rs->prev) < 0)
	|| r->quotaCount < 0 || r->quotaCount > QUOTA_MAX_QUOTAS)
	{
		return -1;
	}

	return 0;
}

/*	Builds the rules of this duct from the SDR, keeping the bucket
 *	levels and counters of rules that carry over.  Called inside
 *	a transaction.						*/
static int	reloadRules(CloState *st, QuotaClDb *db, uint64_t nowMs)
{
	Sdr		sdr = getIonsdr();
	Object		elt;
	RuleState	*fresh;
	int		count = 0;
	int		cap;
	int		i;
	int		q;

	cap = (int) sdr_list_length(sdr, db->rules);
	fresh = (RuleState *) calloc(cap > 0 ? (size_t) cap : 1,
			sizeof *fresh);
	if (fresh == NULL)
	{
		putErrmsg("quotaclo can't allocate rules.", itoa(cap));
		return -1;
	}

	for (elt = sdr_list_first(sdr, db->rules); elt && count < cap;
			elt = sdr_list_next(sdr, elt))
	{
		RuleState	*rs = &fresh[count];
		RuleState	*old = NULL;

		sdr_read(sdr, (char *) &rs->rule, sdr_list_data(sdr, elt),
				sizeof(QuotaRule));
		rs->rule.name[QUOTA_NAME_LEN] = '\0';
		rs->rule.duct[QUOTA_DUCT_LEN] = '\0';
		if (strcmp(rs->rule.duct, st->ductName) != 0)
		{
			continue;
		}

		if (compileRule(rs) < 0)
		{
			writeMemoNote("[?] quotaclo: unusable rule skipped",
					rs->rule.name);
			continue;
		}

		for (i = 0; i < st->ruleCount; i++)
		{
			if (strcmp(st->rules[i].rule.name, rs->rule.name) == 0)
			{
				old = &st->rules[i];
				break;
			}
		}

		for (q = 0; q < rs->rule.quotaCount; q++)
		{
			const QuotaSpec	*spec = &rs->rule.quotas[q];
			int		oq = -1;

			if (old && old->rule.serial == rs->rule.serial)
			{
				oq = quotaFindSpec(&old->rule, spec->kind,
						spec->periodS);
			}

			if (oq >= 0)
			{
				rs->buckets[q] = old->buckets[oq];
				quotaBucketResize(&rs->buckets[q], spec->count,
					(uint64_t) spec->periodS * 1000);
			}
			else
			{
				quotaBucketInit(&rs->buckets[q], spec->count,
					(uint64_t) spec->periodS * 1000, nowMs);
			}
		}

		if (old)
		{
			rs->counters = old->counters;
			rs->stallSinceMs = old->stallSinceMs;
		}
		else if (!st->rulesLoaded)
		{
			applySavedState(st, rs, nowMs);
		}

		count++;
	}

	free(st->rules);
	st->rules = fresh;
	st->ruleCount = count;
	st->loadedChange = db->changeCount;
	if (!st->rulesLoaded)
	{
		st->rulesLoaded = 1;
		free(st->saved.lines);
		st->saved.lines = NULL;
		st->saved.count = 0;
	}

	{
		char	memoBuf[256];

		isprintf(memoBuf, sizeof memoBuf,
				"[i] quotaclo: %d rule(s) for duct '%s'.",
				count, st->ductName);
		writeMemo(memoBuf);
	}

	return 0;
}

/*	Reads the rules root; 0 if quotaadmin never initialized it.	*/
static Object	findDb(QuotaClDb *db)
{
	Sdr	sdr = getIonsdr();
	Object	dbObj;
	int	type;

	dbObj = sdr_find(sdr, QUOTACL_DB_NAME, &type);
	if (dbObj == 0)
	{
		return 0;
	}

	sdr_read(sdr, (char *) db, dbObj, sizeof(QuotaClDb));
	if (db->version != QUOTACL_DB_VERSION)
	{
		return 0;
	}

	return dbObj;
}

/*	*	*	Matching	*	*	*	*	*/

/*	The EIDs of one bundle, read only when some rule needs them.	*/
typedef struct
{
	Bundle	*bundle;
	char	*src;
	char	*dst;
	char	*prev;
	int	haveSrc;
	int	haveDst;
	int	havePrev;
} BundleEids;

static const char	*eidOf(BundleEids *e, char field)
{
	switch (field)
	{
	case 's':
		if (!e->haveSrc)
		{
			readEid(&e->bundle->id.source, &e->src);
			e->haveSrc = 1;
		}

		return e->src;

	case 'd':
		if (!e->haveDst)
		{
			readEid(&e->bundle->destination, &e->dst);
			e->haveDst = 1;
		}

		return e->dst;

	default:
		if (!e->havePrev)
		{
			/*	A bundle produced here has no sender.	*/

			if (e->bundle->clDossier.senderEid.schemeCodeNbr
					!= unknown)
			{
				readEid(&e->bundle->clDossier.senderEid,
						&e->prev);
			}

			e->havePrev = 1;
		}

		return e->prev;
	}
}

static void	releaseEids(BundleEids *e)
{
	if (e->src)
	{
		MRELEASE(e->src);
	}

	if (e->dst)
	{
		MRELEASE(e->dst);
	}

	if (e->prev)
	{
		MRELEASE(e->prev);
	}
}

static int	ruleMatches(const RuleState *rs, BundleEids *e)
{
	if (rs->rule.src[0] && !quotaPatternMatch(&rs->src, eidOf(e, 's')))
	{
		return 0;
	}

	if (rs->rule.dst[0] && !quotaPatternMatch(&rs->dst, eidOf(e, 'd')))
	{
		return 0;
	}

	if (rs->rule.prev[0] && !quotaPatternMatch(&rs->prev, eidOf(e, 'p')))
	{
		return 0;
	}

	return 1;
}

static uint64_t	amountOf(const QuotaSpec *spec, uint64_t bytes)
{
	return spec->kind == QuotaBundles ? 1 : bytes;
}

/*	*	*	The pass	*	*	*	*	*/

typedef enum
{
	Kept = 0,
	Moved,
	Removed,
	Stalled
} Disposition;

/*	Moves a bundle from this duct's buffer to the target's, as
 *	bpclm does when it hands a bundle to a duct.		*/
static void	handOff(Sdr sdr, Object elt, Object bundleObj, Bundle *bundle,
			Object targetBuffer)
{
	sdr_list_delete(sdr, elt, NULL, NULL);
	bundle->ductXmitElt = sdr_list_insert_last(sdr, targetBuffer,
			bundleObj);
	sdr_write(sdr, bundleObj, (char *) bundle, sizeof(Bundle));
}

/*	Applies the overflow action of the rule that holds a bundle
 *	beyond its bound.						*/
static int	overflow(CloState *st, RuleState *blocker, Object elt,
			Object bundleObj, Bundle *bundle, uint64_t bytes,
			uint64_t nowMs, Disposition *result)
{
	Sdr	sdr = getIonsdr();

	switch (blocker->rule.action)
	{
	case QuotaStall:
		if (blocker->stallSinceMs == 0)
		{
			blocker->stallSinceMs = nowMs;
		}

		*result = Stalled;
		return 0;

	case QuotaReforward:
		if (bpReforwardBundle(bundleObj) < 0)
		{
			putErrmsg("quotaclo can't reforward bundle.", NULL);
			return -1;
		}

		blocker->counters.reforwarded++;
		st->reforwarded++;
		*result = Removed;
		return 0;

	default:
		sdr_list_delete(sdr, elt, NULL, NULL);
		bundle->ductXmitElt = 0;
		if (bpAbandon(bundleObj, bundle, BP_REASON_TRAFFIC_PARED) < 0)
		{
			putErrmsg("quotaclo can't drop bundle.", NULL);
			return -1;
		}

		blocker->counters.dropped++;
		blocker->counters.droppedBytes += bytes;
		st->dropped++;
		*result = Removed;
		return 0;
	}
}

/*	Decides one bundle.  *waitMs is lowered to when a held bundle
 *	could pass.							*/
static int	decide(CloState *st, Object elt, Object bundleObj,
			Bundle *bundle, Object targetBuffer, uint64_t nowMs,
			uint64_t *waitMs, Disposition *result)
{
	Sdr		sdr = getIonsdr();
	BundleEids	eids;
	RuleState	*blocker = NULL;
	uint64_t	bytes;
	uint64_t	wait = 0;
	int		matched = 0;
	int		i;
	int		q;
	int		rc = 0;

	bytes = bundle->payload.length > 0 ? (uint64_t) bundle->payload.length
			: 0;
	memset(&eids, 0, sizeof eids);
	eids.bundle = bundle;
	*result = Kept;

	/*	Every quota of every matching rule must have room.	*/

	for (i = 0; i < st->ruleCount; i++)
	{
		RuleState	*rs = &st->rules[i];

		if (!ruleMatches(rs, &eids))
		{
			continue;
		}

		matched = 1;
		for (q = 0; q < rs->rule.quotaCount; q++)
		{
			uint64_t	amount = amountOf(&rs->rule.quotas[q],
						bytes);
			uint64_t	w;

			quotaBucketRefill(&rs->buckets[q], nowMs);
			if (quotaBucketFits(&rs->buckets[q], amount))
			{
				continue;
			}

			if (blocker == NULL)
			{
				blocker = rs;
			}

			w = quotaBucketWaitMs(&rs->buckets[q], amount);
			if (w > wait)
			{
				wait = w;
			}
		}
	}

	if (blocker == NULL)
	{
		for (i = 0; matched && i < st->ruleCount; i++)
		{
			RuleState	*rs = &st->rules[i];

			if (!ruleMatches(rs, &eids))
			{
				continue;
			}

			for (q = 0; q < rs->rule.quotaCount; q++)
			{
				quotaBucketCharge(&rs->buckets[q],
					amountOf(&rs->rule.quotas[q], bytes));
			}

			rs->counters.passed++;
			rs->counters.passedBytes += bytes;
			if (rs->stallSinceMs)
			{
				rs->counters.stalledMs += nowMs
						- rs->stallSinceMs;
				rs->stallSinceMs = 0;
			}
		}

		if (matched)
		{
			st->passed++;
		}
		else
		{
			st->unmatched++;
		}

		handOff(sdr, elt, bundleObj, bundle, targetBuffer);
		*result = Moved;
		releaseEids(&eids);
		return 0;
	}

	/*	Held, and counted against the first rule that blocks it.	*/

	if (blocker->rule.hasHold
	&& blocker->passHeldBytes + bytes > blocker->rule.holdBytes)
	{
		rc = overflow(st, blocker, elt, bundleObj, bundle, bytes,
				nowMs, result);
	}

	if (rc == 0 && *result != Removed)
	{
		blocker->passHeld++;
		blocker->passHeldBytes += bytes;
		if (wait < *waitMs)
		{
			*waitMs = wait;
		}
	}

	releaseEids(&eids);
	return rc;
}

/*	One walk over this duct's buffer.  Returns how long until a
 *	held bundle could pass (UINT64_MAX if none is held), or -1 on
 *	failure through *failed.					*/
static uint64_t	runPass(CloState *st, int *failed, int *infoDue)
{
	Sdr		sdr = getIonsdr();
	QuotaClDb	db;
	Outduct		own;
	Outduct		target;
	Object		dbObj;
	Object		elt;
	Object		nextElt;
	Object		bundleObj;
	Bundle		bundle;
	uint64_t	nowMs = quotaclNowMs();
	uint64_t	waitMs = UINT64_MAX;
	int		moved = 0;
	int		i;

	*failed = 0;
	*infoDue = 0;
	if (sdr_begin_xn(sdr) == 0)
	{
		*failed = 1;
		return UINT64_MAX;
	}

	dbObj = findDb(&db);
	if (dbObj == 0)
	{
		if (!st->noDbNoted)
		{
			writeMemo("[i] quotaclo: no rules (quotaadmin not \
initialized); every bundle passes.");
			st->noDbNoted = 1;
		}

		/*	Saved state waits for the rules to appear.	*/

		free(st->rules);
		st->rules = NULL;
		st->ruleCount = 0;
	}
	else
	{
		st->noDbNoted = 0;
		if (!st->rulesLoaded || db.changeCount != st->loadedChange)
		{
			if (reloadRules(st, &db, nowMs) < 0)
			{
				sdr_cancel_xn(sdr);
				*failed = 1;
				return UINT64_MAX;
			}
		}

		if (db.infoRequest != st->infoServed)
		{
			st->infoServed = db.infoRequest;
			*infoDue = 1;
		}
	}

	for (i = 0; i < st->ruleCount; i++)
	{
		st->rules[i].passHeld = 0;
		st->rules[i].passHeldBytes = 0;
	}

	sdr_read(sdr, (char *) &own, sdr_list_data(sdr,
			st->vduct->outductElt), sizeof(Outduct));
	sdr_read(sdr, (char *) &target, sdr_list_data(sdr,
			st->target->outductElt), sizeof(Outduct));
	for (elt = sdr_list_first(sdr, own.xmitBuffer); elt; elt = nextElt)
	{
		Disposition	result;

		nextElt = sdr_list_next(sdr, elt);
		bundleObj = sdr_list_data(sdr, elt);
		if (bundleObj == 0)
		{
			continue;
		}

		sdr_stage(sdr, (char *) &bundle, bundleObj, sizeof(Bundle));
		if (bundle.ductXmitElt != elt)
		{
			writeMemo("[?] quotaclo: bundle not linked to its \
duct entry, skipped.");
			continue;
		}

		if (decide(st, elt, bundleObj, &bundle, target.xmitBuffer,
				nowMs, &waitMs, &result) < 0)
		{
			sdr_cancel_xn(sdr);
			*failed = 1;
			return UINT64_MAX;
		}

		if (result == Moved)
		{
			moved++;
		}

		if (result == Stalled)
		{
			break;		/*	Nothing more leaves.	*/
		}
	}

	for (i = 0; i < st->ruleCount; i++)
	{
		st->rules[i].counters.held = st->rules[i].passHeld;
		st->rules[i].counters.heldBytes = st->rules[i].passHeldBytes;
	}

	if (sdr_end_xn(sdr) < 0)
	{
		putErrmsg("quotaclo can't end pass.", st->ductName);
		*failed = 1;
		return UINT64_MAX;
	}

	if (moved)
	{
		st->target->timeOfLastXmit = getCtime();
		sm_SemGive(st->target->semaphore);
	}

	return waitMs;
}

/*	*	*	Ticker	*	*	*	*	*	*/

static void	setWake(CloState *st, uint64_t atMs)
{
	pthread_mutex_lock(&st->mtx);
	st->wakeAtMs = atMs;
	pthread_cond_signal(&st->cv);
	pthread_mutex_unlock(&st->mtx);
}

/*	Gives the duct semaphore when a held bundle could pass or the
 *	state file is due.						*/
static void	*tickerThread(void *arg)
{
	CloState	*st = (CloState *) arg;
	struct timespec	ts;
	uint64_t	nowMs;
	uint64_t	atMs;

	pthread_mutex_lock(&st->mtx);
	while (!st->shutdown)
	{
		nowMs = quotaclNowMs();
		if (st->wakeAtMs <= nowMs)
		{
			st->wakeAtMs = UINT64_MAX;
			pthread_mutex_unlock(&st->mtx);
			sm_SemGive(st->vduct->semaphore);
			pthread_mutex_lock(&st->mtx);
			continue;
		}

		/*	Re-check at least once a second, in case the
		 *	semaphore was ended under us.		*/

		atMs = st->wakeAtMs;
		if (atMs > nowMs + 1000)
		{
			atMs = nowMs + 1000;
		}

		clock_gettime(CLOCK_MONOTONIC, &ts);
		ts.tv_sec += (time_t) ((atMs - nowMs) / 1000);
		ts.tv_nsec += (long) ((atMs - nowMs) % 1000) * 1000000L;
		if (ts.tv_nsec >= 1000000000L)
		{
			ts.tv_sec++;
			ts.tv_nsec -= 1000000000L;
		}

		oK(pthread_cond_timedwait(&st->cv, &st->mtx, &ts));
		if (sm_SemEnded(st->vduct->semaphore))
		{
			break;
		}
	}

	pthread_mutex_unlock(&st->mtx);
	return NULL;
}

/*	*	*	Start-up checks	*	*	*	*	*/

static int	findTarget(CloState *st, const char *expr)
{
	Sdr		sdr = getIonsdr();
	char		protocol[MAX_CL_PROTOCOL_NAME_LEN + 1];
	char		cloCmd[SDRSTRING_BUFSZ];
	const char	*slash = strchr(expr, '/');
	const char	*name;
	PsmAddress	elt;
	Outduct		own;
	Outduct		target;
	size_t		len;

	if (slash == NULL || slash == expr || slash[1] == '\0'
	|| (len = (size_t) (slash - expr)) > MAX_CL_PROTOCOL_NAME_LEN
	|| strlen(slash + 1) > MAX_CL_DUCT_NAME_LEN)
	{
		putErrmsg("quotaclo: target must be <protocol>/<duct>.", expr);
		return -1;
	}

	memcpy(protocol, expr, len);
	protocol[len] = '\0';
	name = slash + 1;
	istrcpy(st->targetExpr, expr, sizeof st->targetExpr);
	if (strcmp(protocol, QUOTACL_PROTOCOL) == 0)
	{
		putErrmsg("quotaclo: target is another quota duct.", expr);
		return -1;
	}

	findOutduct(protocol, (char *) name, &st->target, &elt);
	if (elt == 0)
	{
		putErrmsg("quotaclo: no such target duct.", expr);
		return -1;
	}

	CHKERR(sdr_begin_xn(sdr));
	sdr_read(sdr, (char *) &own, sdr_list_data(sdr,
			st->vduct->outductElt), sizeof(Outduct));
	sdr_read(sdr, (char *) &target, sdr_list_data(sdr,
			st->target->outductElt), sizeof(Outduct));
	cloCmd[0] = '\0';
	if (own.cloCmd)
	{
		oK(sdr_string_read(sdr, cloCmd, own.cloCmd));
	}

	sdr_exit_xn(sdr);

	/*	bpclm could hand bundles to a planned target directly,
	 *	past the shaper.					*/

	if (target.planDuctListElt != 0)
	{
		putErrmsg("quotaclo: target duct is attached to a plan; \
detach it, or bundles bypass the quota.", expr);
		return -1;
	}

	/*	bpclm fragments against this duct's limit, not the
	 *	target's, so this duct takes the target's when it has
	 *	none or a larger one.  updateOutduct replaces the CLO
	 *	command too: it gets back the one it has.		*/

	if (target.maxPayloadLen > 0
	&& (own.maxPayloadLen == 0 || own.maxPayloadLen > target.maxPayloadLen))
	{
		if (updateOutduct(QUOTACL_PROTOCOL, st->ductName, cloCmd,
				target.maxPayloadLen) <= 0)
		{
			putErrmsg("quotaclo can't take the target's max \
payload length.", itoa((int) target.maxPayloadLen));
			return -1;
		}

		writeMemoNote("[i] quotaclo: max payload length set to the \
target's", itoa((int) target.maxPayloadLen));
	}

	return 0;
}

/*	*	*	Main thread	*	*	*	*	*/

#if defined (ION_LWT)
int	quotaclo(saddr a1, saddr a2, saddr a3, saddr a4, saddr a5,
		saddr a6, saddr a7, saddr a8, saddr a9, saddr a10)
{
	char	*targetExpr = (char *) a1;
	char	*ductName = (char *) a2;
#else
int	main(int argc, char *argv[])
{
	char	*targetExpr = (argc > 2 ? argv[1] : NULL);
	char	*ductName = (argc > 2 ? argv[argc - 1] : NULL);
#endif
	PsmAddress		vductElt;
	CloState		st;
	pthread_condattr_t	cattr;
	pthread_t		ticker;
	uint64_t		waitMs;
	int			failed;
	int			infoDue;

	if (ductName == NULL || targetExpr == NULL || targetExpr[0] == '-')
	{
		PUTS("Usage: quotaclo <target protocol>/<target duct>");
		PUTS("       (bpadmin appends this duct's name)");
		return 0;
	}

	if (bpAttach() < 0)
	{
		putErrmsg("quotaclo can't attach to BP.", NULL);
		return -1;
	}

	memset(&st, 0, sizeof st);
	st.ductName = ductName;
	findOutduct(QUOTACL_PROTOCOL, ductName, &st.vduct, &vductElt);
	if (vductElt == 0)
	{
		putErrmsg("No such quota duct.", ductName);
		return -1;
	}

	if (st.vduct->cloPid != ERROR && st.vduct->cloPid != sm_TaskIdSelf())
	{
		putErrmsg("CLO task is already started for this duct.",
				itoa(st.vduct->cloPid));
		return -1;
	}

	if (findTarget(&st, targetExpr) < 0)
	{
		writeErrmsgMemos();
		ionDetach();
		return -1;
	}

	loadSavedState(&st);
	pthread_mutex_init(&st.mtx, NULL);
	pthread_condattr_init(&cattr);
	pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
	pthread_cond_init(&st.cv, &cattr);
	pthread_condattr_destroy(&cattr);
	st.wakeAtMs = UINT64_MAX;
	st.nextSnapshotMs = quotaclNowMs() + QUOTACL_SNAPSHOT_S * 1000;

	oK(quotacloSemaphore(&(st.vduct->semaphore)));
	isignal(SIGTERM, shutDownClo);
	if (pthread_begin(&ticker, NULL, tickerThread, &st))
	{
		putSysErrmsg("quotaclo can't create ticker thread", NULL);
		ionDetach();
		return -1;
	}

	{
		char	memoBuf[512];

		isprintf(memoBuf, sizeof memoBuf,
				"[i] quotaclo is running, duct '%s', target \
'%s'.", ductName, st.targetExpr);
		writeMemo(memoBuf);
	}

	while (!(sm_SemEnded(st.vduct->semaphore)))
	{
		uint64_t	nowMs;

		waitMs = runPass(&st, &failed, &infoDue);
		if (failed)
		{
			putErrmsg("quotaclo pass failed.", ductName);
			break;
		}

		nowMs = quotaclNowMs();
		if (infoDue || nowMs >= st.nextSnapshotMs)
		{
			writeState(&st);
			st.nextSnapshotMs = nowMs + QUOTACL_SNAPSHOT_S * 1000;
		}

		/*	A held bundle is looked at again when it could
		 *	pass, the state file when it is due.		*/

		if (waitMs != UINT64_MAX && waitMs < st.nextSnapshotMs - nowMs)
		{
			setWake(&st, nowMs + (waitMs > 0 ? waitMs : 1));
		}
		else
		{
			setWake(&st, st.nextSnapshotMs);
		}

		if (sm_SemTake(st.vduct->semaphore) < 0)
		{
			putErrmsg("quotaclo can't take duct semaphore.",
					ductName);
			break;
		}
	}

	pthread_mutex_lock(&st.mtx);
	st.shutdown = 1;
	pthread_cond_signal(&st.cv);
	pthread_mutex_unlock(&st.mtx);
	pthread_join(ticker, NULL);
	writeState(&st);

	{
		char	memoBuf[512];

		isprintf(memoBuf, sizeof memoBuf,
			"[i] quotaclo stats: %llu passed, %llu unmatched, \
%llu dropped, %llu reforwarded.",
			(unsigned long long) st.passed,
			(unsigned long long) st.unmatched,
			(unsigned long long) st.dropped,
			(unsigned long long) st.reforwarded);
		writeMemo(memoBuf);
	}

	free(st.rules);
	free(st.saved.lines);
	pthread_mutex_destroy(&st.mtx);
	pthread_cond_destroy(&st.cv);
	writeErrmsgMemos();
	writeMemo("[i] quotaclo duct has ended.");
	ionDetach();
	return 0;
}
