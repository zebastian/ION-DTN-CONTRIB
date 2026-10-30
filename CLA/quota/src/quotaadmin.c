/*	quotaadmin.c:	administration of the quota CLA's rules, in the
			manner of ION's other admin programs: commands
			from a file or typed at the prompt.		*/

#include "quotacl.h"

#include <stdio.h>
#include <unistd.h>

#define	MAX_TOKENS	32
#define	LINE_LEN	1024

static int	echo = 0;

static void	printUsage(void)
{
	PUTS("Valid commands are:");
	PUTS("\tq\tQuit");
	PUTS("\th\tHelp");
	PUTS("\t?\tHelp");
	PUTS("\tv\tPrint version of quotaadmin");
	PUTS("\t1\tInitialize");
	PUTS("\t   1");
	PUTS("\ta\tAdd");
	PUTS("\t   a rule <name> quota/<duct> [src <EID pattern>] \
[dst <EID pattern>] [prev <EID pattern>] [hold <bytes> \
[drop|stall|reforward]]");
	PUTS("\t   a quota <rule> bytes|bundles <count>/<timeframe>");
	PUTS("\tc\tChange");
	PUTS("\t   c rule <name> quota/<duct> [src ...] [dst ...] \
[prev ...] [hold ...]");
	PUTS("\t   c quota <rule> bytes|bundles <count>/<timeframe>");
	PUTS("\td\tDelete");
	PUTS("\t   d rule <name>");
	PUTS("\t   d quota <rule> bytes|bundles <timeframe>");
	PUTS("\ti\tInfo: quota levels and counters, from quotaclo");
	PUTS("\t   i rule <name>");
	PUTS("\tl\tList, as commands that recreate the rules");
	PUTS("\t   l rule [quota/<duct>]");
	PUTS("\tr\tReset: every quota of the rule back to full");
	PUTS("\t   r rule <name>");
	PUTS("\te\tEnable or disable echo of printed output to log file");
	PUTS("\t   e { 0 | 1 }");
	PUTS("\t#\tComment");
	PUTS("\t   # <comment text>");
	PUTS("Counts take k, M, G (powers of ten); timeframes s, m, h, d.");
	PUTS("EID patterns: ipn:N.S, ipn:N.*, ipn:A-B.*, ipn:*.*, \
<prefix>*, *, or an exact EID.");
}

static void	printText(char *text)
{
	if (echo)
	{
		writeMemo(text);
	}

	PUTS(text);
}

static void	note(const char *what, const char *detail)
{
	char	buf[LINE_LEN];

	if (detail)
	{
		isprintf(buf, sizeof buf, "quotaadmin: %s (%s)", what, detail);
	}
	else
	{
		isprintf(buf, sizeof buf, "quotaadmin: %s", what);
	}

	printText(buf);
}

/*	*	*	The rules database	*	*	*	*/

/*	Locks the SDR and reads the root; 0 (with the SDR unlocked) if
 *	there is none.							*/
static Object	beginDb(QuotaClDb *db)
{
	Sdr	sdr = getIonsdr();
	Object	dbObj;
	int	type;

	if (sdr_begin_xn(sdr) == 0)
	{
		return 0;
	}

	dbObj = sdr_find(sdr, QUOTACL_DB_NAME, &type);
	if (dbObj == 0)
	{
		sdr_exit_xn(sdr);
		note("not initialized; use '1' first", NULL);
		return 0;
	}

	sdr_read(sdr, (char *) db, dbObj, sizeof(QuotaClDb));
	if (db->version != QUOTACL_DB_VERSION)
	{
		sdr_exit_xn(sdr);
		note("rules database has an unknown version",
				itoa(db->version));
		return 0;
	}

	return dbObj;
}

static Object	findRule(QuotaClDb *db, const char *name, QuotaRule *rule,
			Object *ruleElt)
{
	Sdr	sdr = getIonsdr();
	Object	elt;
	Object	obj;

	for (elt = sdr_list_first(sdr, db->rules); elt;
			elt = sdr_list_next(sdr, elt))
	{
		obj = sdr_list_data(sdr, elt);
		sdr_read(sdr, (char *) rule, obj, sizeof(QuotaRule));
		rule->name[QUOTA_NAME_LEN] = '\0';
		rule->duct[QUOTA_DUCT_LEN] = '\0';
		if (strcmp(rule->name, name) == 0)
		{
			if (ruleElt)
			{
				*ruleElt = elt;
			}

			return obj;
		}
	}

	return 0;
}

/*	Gives the semaphore of a quota duct, so that its quotaclo sees
 *	a change at once.						*/
static void	wakeDuct(char *duct)
{
	VOutduct	*vduct;
	PsmAddress	elt;

	findOutduct(QUOTACL_PROTOCOL, duct, &vduct, &elt);
	if (elt && vduct->semaphore != SM_SEM_NONE)
	{
		sm_SemGive(vduct->semaphore);
	}
}

/*	Records a change and commits; wakes the ducts concerned.	*/
static int	commitChange(Object dbObj, QuotaClDb *db, char *duct1,
			char *duct2)
{
	Sdr	sdr = getIonsdr();

	db->changeCount++;
	sdr_write(sdr, dbObj, (char *) db, sizeof(QuotaClDb));
	if (sdr_end_xn(sdr) < 0)
	{
		note("can't commit the change", NULL);
		return -1;
	}

	if (duct1)
	{
		wakeDuct(duct1);
	}

	if (duct2 && (duct1 == NULL || strcmp(duct1, duct2) != 0))
	{
		wakeDuct(duct2);
	}

	return 0;
}

static int	initialize(void)
{
	Sdr		sdr = getIonsdr();
	QuotaClDb	db;
	Object		dbObj;
	int		type;

	CHKERR(sdr_begin_xn(sdr));
	if (sdr_find(sdr, QUOTACL_DB_NAME, &type) != 0)
	{
		sdr_exit_xn(sdr);
		note("already initialized", NULL);
		return 0;
	}

	memset(&db, 0, sizeof db);
	db.version = QUOTACL_DB_VERSION;
	db.rules = sdr_list_create(sdr);
	dbObj = sdr_malloc(sdr, sizeof(QuotaClDb));
	if (dbObj)
	{
		sdr_write(sdr, dbObj, (char *) &db, sizeof(QuotaClDb));
		sdr_catlg(sdr, QUOTACL_DB_NAME, 0, dbObj);
	}

	if (sdr_end_xn(sdr) < 0 || dbObj == 0)
	{
		note("can't initialize the rules database", NULL);
		return -1;
	}

	return 0;
}

/*	*	*	Rules	*	*	*	*	*	*/

static int	addRule(int argc, char **argv)
{
	Sdr		sdr = getIonsdr();
	QuotaClDb	db;
	QuotaRule	rule;
	QuotaRule	existing;
	Object		dbObj;
	Object		ruleObj;
	const char	*why;

	memset(&rule, 0, sizeof rule);
	if (quotaParseRule(argc, argv, &rule, &why) < 0)
	{
		note(why, argc > 0 ? argv[0] : NULL);
		return -1;
	}

	if ((dbObj = beginDb(&db)) == 0)
	{
		return -1;
	}

	if (findRule(&db, rule.name, &existing, NULL))
	{
		sdr_exit_xn(sdr);
		note("rule exists already; use 'c rule'", rule.name);
		return -1;
	}

	ruleObj = sdr_malloc(sdr, sizeof(QuotaRule));
	if (ruleObj == 0)
	{
		sdr_cancel_xn(sdr);
		note("no space for rule", rule.name);
		return -1;
	}

	rule.serial = db.changeCount + 1;	/*	New: starts full.	*/
	sdr_write(sdr, ruleObj, (char *) &rule, sizeof(QuotaRule));
	oK(sdr_list_insert_last(sdr, db.rules, ruleObj));
	return commitChange(dbObj, &db, rule.duct, NULL);
}

static int	changeRule(int argc, char **argv)
{
	Sdr		sdr = getIonsdr();
	QuotaClDb	db;
	QuotaRule	rule;
	char		oldDuct[QUOTA_DUCT_LEN + 1];
	Object		dbObj;
	Object		ruleObj;
	const char	*why;

	if (argc < 1)
	{
		note("need a rule name", NULL);
		return -1;
	}

	if ((dbObj = beginDb(&db)) == 0)
	{
		return -1;
	}

	ruleObj = findRule(&db, argv[0], &rule, NULL);
	if (ruleObj == 0)
	{
		sdr_exit_xn(sdr);
		note("no such rule", argv[0]);
		return -1;
	}

	/*	Match fields and hold are replaced; quotas stay.	*/

	istrcpy(oldDuct, rule.duct, sizeof oldDuct);
	if (quotaParseRule(argc, argv, &rule, &why) < 0)
	{
		sdr_exit_xn(sdr);
		note(why, argv[0]);
		return -1;
	}

	sdr_write(sdr, ruleObj, (char *) &rule, sizeof(QuotaRule));
	return commitChange(dbObj, &db, oldDuct, rule.duct);
}

static int	deleteRule(int argc, char **argv)
{
	Sdr		sdr = getIonsdr();
	QuotaClDb	db;
	QuotaRule	rule;
	Object		dbObj;
	Object		ruleObj;
	Object		ruleElt;

	if (argc != 1)
	{
		note("usage: d rule <name>", NULL);
		return -1;
	}

	if ((dbObj = beginDb(&db)) == 0)
	{
		return -1;
	}

	ruleObj = findRule(&db, argv[0], &rule, &ruleElt);
	if (ruleObj == 0)
	{
		sdr_exit_xn(sdr);
		note("no such rule", argv[0]);
		return -1;
	}

	sdr_list_delete(sdr, ruleElt, NULL, NULL);
	sdr_free(sdr, ruleObj);
	return commitChange(dbObj, &db, rule.duct, NULL);
}

/*	A new serial makes quotaclo start the rule's buckets full; its
 *	counters, kept by name, carry on.				*/
static int	resetRule(int argc, char **argv)
{
	Sdr		sdr = getIonsdr();
	QuotaClDb	db;
	QuotaRule	rule;
	Object		dbObj;
	Object		ruleObj;

	if (argc != 1)
	{
		note("usage: r rule <name>", NULL);
		return -1;
	}

	if ((dbObj = beginDb(&db)) == 0)
	{
		return -1;
	}

	ruleObj = findRule(&db, argv[0], &rule, NULL);
	if (ruleObj == 0)
	{
		sdr_exit_xn(sdr);
		note("no such rule", argv[0]);
		return -1;
	}

	rule.serial = db.changeCount + 1;
	sdr_write(sdr, ruleObj, (char *) &rule, sizeof(QuotaRule));
	return commitChange(dbObj, &db, rule.duct, NULL);
}

static void	printRule(QuotaRule *rule)
{
	char	buf[LINE_LEN * 2];
	char	count[32];
	char	period[32];
	int	q;

	quotaFormatRule(rule, buf + 7, sizeof buf - 7);
	memcpy(buf, "a rule ", 7);
	printText(buf);
	for (q = 0; q < rule->quotaCount && q < QUOTA_MAX_QUOTAS; q++)
	{
		quotaFormatCount(rule->quotas[q].count, count, sizeof count);
		quotaFormatPeriod(rule->quotas[q].periodS, period,
				sizeof period);
		isprintf(buf, sizeof buf, "a quota %s %s %s/%s", rule->name,
				quotaKindName(rule->quotas[q].kind), count,
				period);
		printText(buf);
	}
}

static int	listRules(int argc, char **argv)
{
	Sdr		sdr = getIonsdr();
	QuotaClDb	db;
	QuotaRule	rule;
	Object		elt;
	const char	*duct = NULL;

	if (argc > 1 || (argc == 1 && strncmp(argv[0], "quota/", 6) != 0))
	{
		note("usage: l rule [quota/<duct>]", NULL);
		return -1;
	}

	if (argc == 1)
	{
		duct = argv[0] + 6;
	}

	if (beginDb(&db) == 0)
	{
		return -1;
	}

	for (elt = sdr_list_first(sdr, db.rules); elt;
			elt = sdr_list_next(sdr, elt))
	{
		sdr_read(sdr, (char *) &rule, sdr_list_data(sdr, elt),
				sizeof(QuotaRule));
		rule.name[QUOTA_NAME_LEN] = '\0';
		rule.duct[QUOTA_DUCT_LEN] = '\0';
		if (duct == NULL || strcmp(duct, rule.duct) == 0)
		{
			printRule(&rule);
		}
	}

	sdr_exit_xn(sdr);
	return 0;
}

/*	*	*	Quotas	*	*	*	*	*	*/

/*	'a': adds, 'c': changes, 'd': deletes the quota.		*/
static int	editQuota(char op, int argc, char **argv)
{
	Sdr		sdr = getIonsdr();
	QuotaClDb	db;
	QuotaRule	rule;
	QuotaSpec	spec;
	Object		dbObj;
	Object		ruleObj;
	int		q;

	if (argc != 3 || quotaParseKind(argv[1], &spec.kind) < 0)
	{
		note(op == 'd' ? "usage: d quota <rule> bytes|bundles \
<timeframe>" : "usage: a|c quota <rule> bytes|bundles <count>/<timeframe>",
				NULL);
		return -1;
	}

	if (op == 'd')
	{
		spec.count = 0;
		if (quotaParsePeriod(argv[2], &spec.periodS) < 0)
		{
			note("bad timeframe", argv[2]);
			return -1;
		}
	}
	else if (quotaParseRate(argv[2], &spec.count, &spec.periodS) < 0)
	{
		note("bad <count>/<timeframe>", argv[2]);
		return -1;
	}

	if ((dbObj = beginDb(&db)) == 0)
	{
		return -1;
	}

	ruleObj = findRule(&db, argv[0], &rule, NULL);
	if (ruleObj == 0)
	{
		sdr_exit_xn(sdr);
		note("no such rule", argv[0]);
		return -1;
	}

	q = quotaFindSpec(&rule, spec.kind, spec.periodS);
	switch (op)
	{
	case 'a':
		if (q >= 0)
		{
			sdr_exit_xn(sdr);
			note("rule has that quota already; use 'c quota'",
					argv[2]);
			return -1;
		}

		if (rule.quotaCount >= QUOTA_MAX_QUOTAS)
		{
			sdr_exit_xn(sdr);
			note("rule has the most quotas it can",
					itoa(QUOTA_MAX_QUOTAS));
			return -1;
		}

		rule.quotas[rule.quotaCount++] = spec;
		break;

	case 'c':
		if (q < 0)
		{
			sdr_exit_xn(sdr);
			note("rule has no quota of that kind and timeframe",
					argv[2]);
			return -1;
		}

		rule.quotas[q] = spec;
		break;

	default:
		if (q < 0)
		{
			sdr_exit_xn(sdr);
			note("rule has no quota of that kind and timeframe",
					argv[2]);
			return -1;
		}

		rule.quotaCount--;
		memmove(&rule.quotas[q], &rule.quotas[q + 1],
				(size_t) (rule.quotaCount - q)
				* sizeof(QuotaSpec));
	}

	sdr_write(sdr, ruleObj, (char *) &rule, sizeof(QuotaRule));
	return commitChange(dbObj, &db, rule.duct, NULL);
}

/*	*	*	Info	*	*	*	*	*	*/

/*	Reads the duct's state file for the rule.  Returns 1 if the
 *	file answered request (or any if request is 0), 0 if it is
 *	older, -1 if there is none.					*/
static int	readState(const char *duct, const char *name,
			unsigned int request, QuotaRule *rule,
			QuotaBucket *buckets, int *haveBucket,
			QuotaCounters *counters, int *haveCounters,
			int64_t *asOf)
{
	char		path[MAXPATHLEN];
	char		line[1100];
	FILE		*f;
	QuotaStateLine	parsed;
	int		answered = 0;
	int		q;

	quotaclStatePath(duct, path, sizeof path);
	f = fopen(path, "r");
	if (f == NULL)
	{
		return -1;
	}

	*haveCounters = 0;
	memset(haveBucket, 0, QUOTA_MAX_QUOTAS * sizeof *haveBucket);
	while (fgets(line, sizeof line, f))
	{
		line[strcspn(line, "\r\n")] = '\0';
		if (quotaParseStateLine(line, &parsed) < 0)
		{
			continue;
		}

		switch (parsed.type)
		{
		case QuotaLineHeader:
			*asOf = parsed.unixTime;
			answered = request == 0
				|| (int) (parsed.infoServed - request) >= 0;
			break;

		case QuotaLineBucket:
			if (strcmp(parsed.name, name) != 0)
			{
				break;
			}

			q = quotaFindSpec(rule, parsed.kind, parsed.periodS);
			if (q >= 0)
			{
				buckets[q].level = parsed.level;
				haveBucket[q] = 1;
			}

			break;

		case QuotaLineCounters:
			if (strcmp(parsed.name, name) == 0)
			{
				*counters = parsed.counters;
				*haveCounters = 1;
			}

			break;

		default:
			break;
		}
	}

	fclose(f);
	return answered;
}

static int	infoRule(int argc, char **argv)
{
	Sdr		sdr = getIonsdr();
	QuotaClDb	db;
	QuotaRule	rule;
	QuotaBucket	buckets[QUOTA_MAX_QUOTAS];
	int		haveBucket[QUOTA_MAX_QUOTAS];
	QuotaCounters	counters;
	int		haveCounters = 0;
	int64_t		asOf = 0;
	char		buf[LINE_LEN * 2];
	char		count[32];
	char		period[32];
	Object		dbObj;
	unsigned int	request;
	int		answered = -1;
	int		i;
	int		q;

	if (argc != 1)
	{
		note("usage: i rule <name>", NULL);
		return -1;
	}

	if ((dbObj = beginDb(&db)) == 0)
	{
		return -1;
	}

	if (findRule(&db, argv[0], &rule, NULL) == 0)
	{
		sdr_exit_xn(sdr);
		note("no such rule", argv[0]);
		return -1;
	}

	/*	Ask quotaclo for a fresh state file, and wait up to 3 s.	*/

	request = ++db.infoRequest;
	if (request == 0)
	{
		request = ++db.infoRequest;
	}

	sdr_write(sdr, dbObj, (char *) &db, sizeof(QuotaClDb));
	if (sdr_end_xn(sdr) < 0)
	{
		note("can't request info", NULL);
		return -1;
	}

	wakeDuct(rule.duct);
	memset(buckets, 0, sizeof buckets);
	memset(&counters, 0, sizeof counters);
	for (i = 0; i < 30; i++)
	{
		answered = readState(rule.duct, rule.name, request, &rule,
				buckets, haveBucket, &counters, &haveCounters,
				&asOf);
		if (answered == 1)
		{
			break;
		}

		microsnooze(100000);
	}

	printRule(&rule);
	if (answered < 0)
	{
		printText("  no state yet: quotaclo has not run for this duct");
		return 0;
	}

	if (answered == 0)
	{
		char	when[32];
		time_t	t = (time_t) asOf;

		strftime(when, sizeof when, "%Y-%m-%d %H:%M:%S",
				localtime(&t));
		isprintf(buf, sizeof buf, "  quotaclo not answering; state \
as of %s", when);
		printText(buf);
	}

	for (q = 0; q < rule.quotaCount && q < QUOTA_MAX_QUOTAS; q++)
	{
		quotaFormatCount(rule.quotas[q].count, count, sizeof count);
		quotaFormatPeriod(rule.quotas[q].periodS, period,
				sizeof period);
		if (haveBucket[q])
		{
			isprintf(buf, sizeof buf, "  %s %s/%s: level %lld \
of %llu", quotaKindName(rule.quotas[q].kind), count, period,
				(long long) buckets[q].level,
				(unsigned long long) rule.quotas[q].count);
		}
		else
		{
			isprintf(buf, sizeof buf, "  %s %s/%s: full",
				quotaKindName(rule.quotas[q].kind), count,
				period);
		}

		printText(buf);
	}

	if (haveCounters)
	{
		isprintf(buf, sizeof buf, "  passed %llu (%llu bytes), held \
%llu (%llu bytes), dropped %llu (%llu bytes), reforwarded %llu, stalled \
%llu ms",
			(unsigned long long) counters.passed,
			(unsigned long long) counters.passedBytes,
			(unsigned long long) counters.held,
			(unsigned long long) counters.heldBytes,
			(unsigned long long) counters.dropped,
			(unsigned long long) counters.droppedBytes,
			(unsigned long long) counters.reforwarded,
			(unsigned long long) counters.stalledMs);
		printText(buf);
	}

	return 0;
}

/*	*	*	Command processing	*	*	*	*/

static int	splitLine(char *line, char **tokens)
{
	int	n = 0;
	char	*save = NULL;
	char	*token;

	for (token = strtok_r(line, " \t\r\n", &save); token;
			token = strtok_r(NULL, " \t\r\n", &save))
	{
		if (n == MAX_TOKENS)
		{
			return -1;
		}

		tokens[n++] = token;
	}

	return n;
}

/*	Returns 1 to quit, 0 when done, -1 on a failed command.	*/
static int	processLine(char *line)
{
	char	*tokens[MAX_TOKENS];
	int	n;
	int	rc;

	n = splitLine(line, tokens);
	if (n < 0)
	{
		note("too many tokens", NULL);
		return -1;
	}

	if (n == 0 || tokens[0][0] == '#')
	{
		return 0;
	}

	if (strlen(tokens[0]) != 1)
	{
		note("unknown command; 'h' for help", tokens[0]);
		return -1;
	}

	switch (tokens[0][0])
	{
	case 'q':
		return 1;

	case 'h':
	case '?':
		printUsage();
		return 0;

	case 'v':
		printText("quotaadmin: quota CLA rules, database version 1");
		return 0;

	case 'e':
		if (n != 2 || (strcmp(tokens[1], "0") != 0
				&& strcmp(tokens[1], "1") != 0))
		{
			note("usage: e { 0 | 1 }", NULL);
			return -1;
		}

		echo = tokens[1][0] == '1';
		return 0;

	case '1':
		return initialize();

	default:
		break;
	}

	if (n < 2 || (strcmp(tokens[1], "rule") != 0
			&& strcmp(tokens[1], "quota") != 0))
	{
		note("expected 'rule' or 'quota'; 'h' for help", NULL);
		return -1;
	}

	if (strcmp(tokens[1], "quota") == 0)
	{
		if (strchr("acd", tokens[0][0]) == NULL)
		{
			note("quotas take a, c and d", tokens[0]);
			return -1;
		}

		return editQuota(tokens[0][0], n - 2, tokens + 2);
	}

	switch (tokens[0][0])
	{
	case 'a':
		rc = addRule(n - 2, tokens + 2);
		break;

	case 'c':
		rc = changeRule(n - 2, tokens + 2);
		break;

	case 'd':
		rc = deleteRule(n - 2, tokens + 2);
		break;

	case 'i':
		rc = infoRule(n - 2, tokens + 2);
		break;

	case 'l':
		rc = listRules(n - 2, tokens + 2);
		break;

	case 'r':
		rc = resetRule(n - 2, tokens + 2);
		break;

	default:
		note("unknown command; 'h' for help", tokens[0]);
		rc = -1;
	}

	return rc;
}

#if defined (ION_LWT)
int	quotaadmin(saddr a1, saddr a2, saddr a3, saddr a4, saddr a5,
		saddr a6, saddr a7, saddr a8, saddr a9, saddr a10)
{
	char	*cmdFileName = (char *) a1;
#else
int	main(int argc, char **argv)
{
	char	*cmdFileName = (argc > 1 ? argv[1] : NULL);
#endif
	char	line[LINE_LEN];
	FILE	*f = stdin;
	int	interactive = 1;
	int	failures = 0;
	int	rc;

	if (bpAttach() < 0)
	{
		putErrmsg("quotaadmin can't attach to BP.", NULL);
		return 1;
	}

	if (cmdFileName && strcmp(cmdFileName, ".") != 0)
	{
		f = fopen(cmdFileName, "r");
		if (f == NULL)
		{
			putSysErrmsg("Can't open command file", cmdFileName);
			writeErrmsgMemos();
			ionDetach();
			return 1;
		}

		interactive = 0;
	}
	else if (!isatty(fileno(stdin)))
	{
		interactive = 0;
	}

	for (;;)
	{
		if (interactive)
		{
			printf(": ");
			fflush(stdout);
		}

		if (fgets(line, sizeof line, f) == NULL)
		{
			break;
		}

		rc = processLine(line);
		if (rc == 1)
		{
			break;
		}

		if (rc < 0)
		{
			failures++;
		}
	}

	if (f != stdin)
	{
		fclose(f);
	}

	writeErrmsgMemos();
	ionDetach();
	return (!interactive && failures > 0) ? 1 : 0;
}
