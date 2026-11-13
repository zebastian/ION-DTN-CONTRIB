/*	bpdemuxadmin.c:	administration of bpdemux's rules, in the manner
			of ION's other admin programs: commands from a
			file or typed at the prompt.			*/

#include "bpdemux.h"

#include <stdio.h>
#include <unistd.h>

#define	MAX_TOKENS	16
#define	LINE_LEN	1024

static int	echo = 0;
static DmxRule	rules[DMX_MAX_RULES];

static void	printUsage(void)
{
	PUTS("Valid commands are:");
	PUTS("\tq\tQuit");
	PUTS("\th\tHelp");
	PUTS("\t?\tHelp");
	PUTS("\tv\tPrint version of bpdemuxadmin");
	PUTS("\t1\tInitialize, for the demux endpoint and its default");
	PUTS("\t   1 ipn:<node>.<service> [<default service>]");
	PUTS("\ta\tAdd a rule: bundles with this data label go to this \
service");
	PUTS("\t   a label <label> <service> [<name>]");
	PUTS("\tc\tChange a rule's service, and its name if one is given");
	PUTS("\t   c label <label | name> <service> [<name>]");
	PUTS("\td\tDelete a rule");
	PUTS("\t   d label <label | name>");
	PUTS("\ti\tInfo: the demux endpoint, or one rule and its target");
	PUTS("\t   i");
	PUTS("\t   i label <label | name>");
	PUTS("\tl\tList, as commands that recreate the rules");
	PUTS("\t   l");
	PUTS("\ts\tSet the default service (0: none, abandon instead)");
	PUTS("\t   s default <service | 0>");
	PUTS("\te\tEnable or disable echo of printed output to log file");
	PUTS("\t   e { 0 | 1 }");
	PUTS("\t#\tComment");
	PUTS("\t   # <comment text>");
	PUTS("Labels are ION data labels, 1 to 4294967295; names are \
optional and for display only.");
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
		isprintf(buf, sizeof buf, "bpdemuxadmin: %s (%s)", what,
				detail);
	}
	else
	{
		isprintf(buf, sizeof buf, "bpdemuxadmin: %s", what);
	}

	printText(buf);
}

/*	*	*	The rules database	*	*	*	*/

/*	Locks the SDR and reads the root and the rules; 0 (with the
 *	SDR unlocked) if there is none.					*/
static Object	beginDb(DmxDb *db, int *count)
{
	Sdr	sdr = getIonsdr();
	Object	dbObj;
	Object	elt;
	int	type;
	int	n = 0;

	if (sdr_begin_xn(sdr) == 0)
	{
		return 0;
	}

	dbObj = sdr_find(sdr, BPDEMUX_DB_NAME, &type);
	if (dbObj == 0)
	{
		sdr_exit_xn(sdr);
		note("not initialized; use '1' first", NULL);
		return 0;
	}

	/*	Staged, not just read: every change writes the root back
	 *	(commitChange), and ION's default SDR configuration
	 *	(SDR_BOUNDED) lets a transaction write only objects it
	 *	allocated or staged.					*/

	sdr_stage(sdr, (char *) db, dbObj, sizeof(DmxDb));
	if (db->version != BPDEMUX_DB_VERSION)
	{
		sdr_exit_xn(sdr);
		note("rules database has an unknown version",
				itoa(db->version));
		return 0;
	}

	for (elt = sdr_list_first(sdr, db->rules); elt && n < DMX_MAX_RULES;
			elt = sdr_list_next(sdr, elt))
	{
		sdr_read(sdr, (char *) &rules[n], sdr_list_data(sdr, elt),
				sizeof(DmxRule));
		rules[n].name[DMX_NAME_LEN] = '\0';
		n++;
	}

	*count = n;
	return dbObj;
}

/*	The SDR list element of rule number i, in list order.		*/
static Object	ruleElt(DmxDb *db, int i)
{
	Sdr	sdr = getIonsdr();
	Object	elt;

	for (elt = sdr_list_first(sdr, db->rules); elt && i > 0;
			elt = sdr_list_next(sdr, elt))
	{
		i--;
	}

	return elt;
}

static int	commitChange(Object dbObj, DmxDb *db)
{
	Sdr	sdr = getIonsdr();

	db->changeCount++;
	sdr_write(sdr, dbObj, (char *) db, sizeof(DmxDb));
	if (sdr_end_xn(sdr) < 0)
	{
		note("can't commit the change", NULL);
		return -1;
	}

	return 0;
}

static int	checkService(const char *text, uvast ownSvc, int zeroOk,
			uvast *svc)
{
	uint64_t	v;

	if (zeroOk && strcmp(text, "0") == 0)
	{
		*svc = 0;
		return 0;
	}

	if (dmxParseService(text, &v) < 0 || !dmxServiceFits(v))
	{
		note("not a service number", text);
		return -1;
	}

	if (v == ownSvc)
	{
		note("that is the demux endpoint itself", text);
		return -1;
	}

	*svc = v;
	return 0;
}

static int	initialize(int argc, char **argv)
{
	Sdr		sdr = getIonsdr();
	DmxDb		db;
	Object		dbObj;
	uint64_t	node;
	uint64_t	svc;
	int		type;

	if (argc < 1 || argc > 2 || dmxParseIpnEid(argv[0], &node, &svc) < 0
			|| !dmxServiceFits(svc))
	{
		note("usage: 1 ipn:<node>.<service> [<default service>]",
				NULL);
		return -1;
	}

	if (node != (uint64_t) getOwnFqnn())
	{
		note("endpoint is not on this node", argv[0]);
		return -1;
	}

	memset(&db, 0, sizeof db);
	db.version = BPDEMUX_DB_VERSION;
	db.ownNode = node;
	db.ownSvc = svc;
	if (argc == 2 && checkService(argv[1], db.ownSvc, 1,
			&db.defaultSvc) < 0)
	{
		return -1;
	}

	CHKERR(sdr_begin_xn(sdr));
	if (sdr_find(sdr, BPDEMUX_DB_NAME, &type) != 0)
	{
		sdr_exit_xn(sdr);
		note("already initialized", NULL);
		return 0;
	}

	db.rules = sdr_list_create(sdr);
	dbObj = sdr_malloc(sdr, sizeof(DmxDb));
	if (dbObj)
	{
		sdr_write(sdr, dbObj, (char *) &db, sizeof(DmxDb));
		sdr_catlg(sdr, BPDEMUX_DB_NAME, 0, dbObj);
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
	DmxDb		db;
	DmxRule		rule;
	Object		dbObj;
	Object		ruleObj;
	const char	*why;
	int		count;

	if (dmxParseRule(argc, argv, &rule, &why) < 0)
	{
		note(why, argc > 0 ? argv[0] : NULL);
		return -1;
	}

	if (!dmxServiceFits(rule.svc))
	{
		note("service number too large for this ION", argv[1]);
		return -1;
	}

	if ((dbObj = beginDb(&db, &count)) == 0)
	{
		return -1;
	}

	if (dmxCheckRule(rules, count, -1, &rule, db.ownSvc, &why) < 0)
	{
		sdr_exit_xn(sdr);
		note(why, argv[0]);
		return -1;
	}

	ruleObj = sdr_malloc(sdr, sizeof(DmxRule));
	if (ruleObj == 0)
	{
		sdr_cancel_xn(sdr);
		note("no space for rule", argv[0]);
		return -1;
	}

	sdr_write(sdr, ruleObj, (char *) &rule, sizeof(DmxRule));
	oK(sdr_list_insert_last(sdr, db.rules, ruleObj));
	return commitChange(dbObj, &db);
}

static int	changeRule(int argc, char **argv)
{
	Sdr		sdr = getIonsdr();
	DmxDb		db;
	DmxRule		rule;
	Object		dbObj;
	Object		ruleObj;
	const char	*why;
	uvast		svc;
	int		count;
	int		i;

	if (argc < 2 || argc > 3)
	{
		note("usage: c label <label | name> <service> [<name>]",
				NULL);
		return -1;
	}

	if ((dbObj = beginDb(&db, &count)) == 0)
	{
		return -1;
	}

	i = dmxFindRef(rules, count, argv[0]);
	if (i < 0)
	{
		sdr_exit_xn(sdr);
		note("no such rule", argv[0]);
		return -1;
	}

	rule = rules[i];
	if (checkService(argv[1], db.ownSvc, 0, &svc) < 0)
	{
		sdr_exit_xn(sdr);
		return -1;
	}

	rule.svc = svc;

	if (argc == 3 && dmxParseName(argv[2], rule.name) < 0)
	{
		sdr_exit_xn(sdr);
		note("name: up to 31 of A-Z a-z 0-9 _ . -, not all digits",
				argv[2]);
		return -1;
	}

	if (dmxCheckRule(rules, count, i, &rule, db.ownSvc, &why) < 0)
	{
		sdr_exit_xn(sdr);
		note(why, argv[0]);
		return -1;
	}

	ruleObj = sdr_list_data(sdr, ruleElt(&db, i));
	sdr_stage(sdr, NULL, ruleObj, 0);
	sdr_write(sdr, ruleObj, (char *) &rule, sizeof(DmxRule));
	return commitChange(dbObj, &db);
}

static int	deleteRule(int argc, char **argv)
{
	Sdr	sdr = getIonsdr();
	DmxDb	db;
	Object	dbObj;
	Object	elt;
	Object	ruleObj;
	int	count;
	int	i;

	if (argc != 1)
	{
		note("usage: d label <label | name>", NULL);
		return -1;
	}

	if ((dbObj = beginDb(&db, &count)) == 0)
	{
		return -1;
	}

	i = dmxFindRef(rules, count, argv[0]);
	if (i < 0)
	{
		sdr_exit_xn(sdr);
		note("no such rule", argv[0]);
		return -1;
	}

	elt = ruleElt(&db, i);
	ruleObj = sdr_list_data(sdr, elt);
	sdr_list_delete(sdr, elt, NULL, NULL);
	sdr_free(sdr, ruleObj);
	return commitChange(dbObj, &db);
}

static int	setDefault(int argc, char **argv)
{
	Sdr	sdr = getIonsdr();
	DmxDb	db;
	Object	dbObj;
	int	count;
	uvast	svc;

	if (argc != 2 || strcmp(argv[0], "default") != 0)
	{
		note("usage: s default <service | 0>", NULL);
		return -1;
	}

	if ((dbObj = beginDb(&db, &count)) == 0)
	{
		return -1;
	}

	if (checkService(argv[1], db.ownSvc, 1, &svc) < 0)
	{
		sdr_exit_xn(sdr);
		return -1;
	}

	db.defaultSvc = svc;
	return commitChange(dbObj, &db);
}

/*	*	*	Info	*	*	*	*	*	*/

/*	"ipn:N.S: defined, open by pid P, Q bundles queued", or that
 *	the node has no such endpoint; in a transaction.		*/
static void	describeEndpoint(DmxDb *db, uvast svc, char *buf, size_t size)
{
	Sdr		sdr = getIonsdr();
	EndpointId	eid;
	VScheme		*vscheme;
	VEndpoint	*vpoint = NULL;
		OBJ_POINTER(Endpoint, endpoint);

	memset(&eid, 0, sizeof eid);
	eid.schemeCodeNbr = ipn;
	eid.ssp.ipn.fqnn = db->ownNode;
	eid.ssp.ipn.serviceNbr = (unsigned long) svc;
	lookUpEidScheme(&eid, &vscheme);
	if (vscheme)
	{
		lookUpEndpoint(&eid, vscheme, &vpoint);
	}

	if (vpoint == NULL)
	{
		isprintf(buf, (int) size, "ipn:" UVAST_FIELDSPEC "."
				UVAST_FIELDSPEC ": no such endpoint on this node",
				db->ownNode, svc);
		return;
	}

	GET_OBJ_POINTER(sdr, Endpoint, endpoint, sdr_list_data(sdr,
			vpoint->endpointElt));
	isprintf(buf, (int) size, "ipn:" UVAST_FIELDSPEC "." UVAST_FIELDSPEC
			": %s, %ld bundles queued, unopened bundles %s",
			db->ownNode, svc,
			vpoint->appPid == ERROR ? "not open" : "open",
			(long) sdr_list_length(sdr, endpoint->deliveryQueue),
			endpoint->recvRule == DiscardBundle ? "discarded"
			: "queued");
}

static void	printRule(DmxRule *rule)
{
	char	buf[LINE_LEN];

	memcpy(buf, "a label ", 8);
	dmxFormatRule(rule, buf + 8, sizeof buf - 8);
	printText(buf);
}

static int	info(int argc, char **argv)
{
	Sdr	sdr = getIonsdr();
	DmxDb	db;
	char	buf[LINE_LEN];
	int	count;
	int	i;

	if (argc != 0 && (argc != 2 || strcmp(argv[0], "label") != 0))
	{
		note("usage: i | i label <label | name>", NULL);
		return -1;
	}

	if (beginDb(&db, &count) == 0)
	{
		return -1;
	}

	if (argc == 0)
	{
		isprintf(buf, sizeof buf, "demux endpoint: ");
		describeEndpoint(&db, db.ownSvc, buf + 16, sizeof buf - 16);
		printText(buf);
		if (db.defaultSvc)
		{
			isprintf(buf, sizeof buf, "default: ");
			describeEndpoint(&db, db.defaultSvc, buf + 9,
					sizeof buf - 9);
		}
		else
		{
			isprintf(buf, sizeof buf, "default: none (bundles \
without a rule are abandoned)");
		}

		printText(buf);
		isprintf(buf, sizeof buf, "%d rules", count);
		printText(buf);
		sdr_exit_xn(sdr);
		return 0;
	}

	i = dmxFindRef(rules, count, argv[1]);
	if (i < 0)
	{
		sdr_exit_xn(sdr);
		note("no such rule", argv[1]);
		return -1;
	}

	printRule(&rules[i]);
	isprintf(buf, sizeof buf, "  ");
	describeEndpoint(&db, rules[i].svc, buf + 2, sizeof buf - 2);
	printText(buf);
	sdr_exit_xn(sdr);
	return 0;
}

static int	listRules(int argc, char **argv)
{
	Sdr	sdr = getIonsdr();
	DmxDb	db;
	char	buf[LINE_LEN];
	int	count;
	int	i;

	(void) argv;
	if (argc != 0)
	{
		note("usage: l", NULL);
		return -1;
	}

	if (beginDb(&db, &count) == 0)
	{
		return -1;
	}

	sdr_exit_xn(sdr);
	isprintf(buf, sizeof buf, "1 ipn:" UVAST_FIELDSPEC "." UVAST_FIELDSPEC
			" " UVAST_FIELDSPEC, db.ownNode, db.ownSvc,
			db.defaultSvc);
	printText(buf);
	for (i = 0; i < count; i++)
	{
		printRule(&rules[i]);
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
		printText("bpdemuxadmin: data-label demux, database version 1");
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
		return initialize(n - 1, tokens + 1);

	case 'i':
		return info(n - 1, tokens + 1);

	case 'l':
		return listRules(n - 1, tokens + 1);

	case 's':
		return setDefault(n - 1, tokens + 1);

	default:
		break;
	}

	if (n < 2 || strcmp(tokens[1], "label") != 0)
	{
		note("expected 'label'; 'h' for help", NULL);
		return -1;
	}

	switch (tokens[0][0])
	{
	case 'a':
		return addRule(n - 2, tokens + 2);

	case 'c':
		return changeRule(n - 2, tokens + 2);

	case 'd':
		return deleteRule(n - 2, tokens + 2);

	default:
		note("unknown command; 'h' for help", tokens[0]);
		return -1;
	}
}

#if defined (ION_LWT)
int	bpdemuxadmin(saddr a1, saddr a2, saddr a3, saddr a4, saddr a5,
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
		putErrmsg("bpdemuxadmin can't attach to BP.", NULL);
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
