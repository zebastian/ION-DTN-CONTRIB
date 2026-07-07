/*
	bpcmdd.c:	a Bundle Protocol command daemon.

	Listens on a BP endpoint.  Each delivered bundle's payload IS a
	command line: bpcmdd tokenises it on whitespace and, if the
	resulting command is permitted by a whitelist, forks and execs it
	directly (no shell), returning the command's standard output to the
	bundle's source EID as a reply bundle.

	Because the command is exec'd directly from the tokenised payload,
	shell metacharacters (; | $() ``) are inert: they become literal
	arguments and can do nothing unless a whitelist rule explicitly
	permits a shell.

	The set of runnable commands is fixed by a whitelist file, not by
	bpcmdd's own arguments.  Each whitelist rule is one of:

		exact  <command line>      literal, whole-line match
		glob   <pattern>           shell wildcards * and ?
		regex  <ERE>               POSIX extended regex

	The mode keyword is optional; a bare rule is treated as a regex.
	Every rule is anchored: it must match the entire normalised command
	line (argv joined by single spaces), so a rule for "gpio" can never
	authorise "gpionuke".

	Built against an installed ION-DTN; uses only ION's public bp.h API.

	Author: Sebastian Jennen
									*/

#include <bp.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#ifndef LOGIN_NAME_MAX
#define LOGIN_NAME_MAX 256
#endif

typedef enum
{
	MatchExact,
	MatchGlob,
	MatchRegex
} MatchMode;

typedef struct
{
	MatchMode mode;
	char	 *pattern; /*	Original text (exact/glob/logging).	*/
	regex_t	  re;	   /*	Compiled iff mode == MatchRegex.	*/
} Rule;

static BpSAP sap;
static Sdr   sdr;
static int   running = 1;
static Rule *rules;
static int   numRules;

/*	Optional source-EID allowlist: when active, only bundles whose source
 *	EID matches one of these glob patterns are acted on.		*/
static char **allowedEids;
static int    numAllowedEids;
static int    allowlistActive;

/*	Optional unprivileged identity each command is exec'd under
 *	(configured via -u).						*/
static int   runAsSet;
static uid_t runAsUid;
static gid_t runAsGid;
static char  runAsName[LOGIN_NAME_MAX + 1];
static char  runAsHome[PATH_MAX];

static const char usage[] =
		"Usage: bpcmdd [-n] [-t ttl] [-a eidlist] <own endpoint ID> "
		"<whitelist file>\n\n"
		"Each delivered bundle's payload is a command line: bpcmdd "
		"splits it on\nwhitespace and, if the whitelist permits it, "
		"execs it directly (no\nshell) and returns its stdout to the "
		"bundle source as a reply bundle.\n\n"
		"  -n        do not send the command's stdout back to the "
		"source\n"
		"  -t ttl    reply bundle lifetime in seconds (default 86400)\n"
		"  -a list   comma-separated source-EID glob patterns; only "
		"matching\n            sources are served (e.g. "
		"'ipn:1.*,ipn:2.3')\n"
		"  -u user   run every command as this unprivileged user "
		"(the daemon\n            must start with privilege)\n\n"
		"Whitelist file: one rule per line; '#' comments and blank "
		"lines are\nignored.  Each rule is\n"
		"  exact <command line>   literal whole-line match\n"
		"  glob  <pattern>        shell wildcards * and ?\n"
		"  regex <ERE>            POSIX extended regex (assumed when "
		"the mode\n"
		"                         keyword is omitted)\n"
		"Rules are anchored to the whole normalised command line.\n"
		"The command sees BP_SOURCE_EID and BP_DEST_EID in its "
		"environment.\n";

static void handleQuit(int signum)
{
	/*	Tell the compiler that we are not using 'signum'.	*/
	(void) signum;

	isignal(SIGINT, handleQuit);
	PUTS("BP reception interrupted.");
	fflush(NULL);
	running = 0;
	bp_interrupt(sap);
}

/*	Strips trailing whitespace (including the newline) in place.	*/

static void rstrip(char *s)
{
	size_t n = strlen(s);

	while (n > 0 && isspace((unsigned char) s[n - 1]))
	{
		s[--n] = '\0';
	}
}

/*	Appends one rule to the global table.  Returns 0, or -1 on error
 *	(allocation failure or a malformed regex).			*/

static int addRule(MatchMode mode, const char *pattern)
{
	Rule *bigger;
	Rule *r;

	bigger = realloc(rules, (numRules + 1) * sizeof(Rule));
	if (bigger == NULL)
	{
		return -1;
	}

	rules = bigger;
	r = &rules[numRules];
	r->mode = mode;
	r->pattern = strdup(pattern);
	if (r->pattern == NULL)
	{
		return -1;
	}

	if (mode == MatchRegex)
	{
		char *anchored;
		int   code;

		/*	Anchor to the whole command line: ^( ... )$	*/

		anchored = malloc(strlen(pattern) + 5);
		if (anchored == NULL)
		{
			free(r->pattern);
			return -1;
		}

		isprintf(anchored, (int) strlen(pattern) + 5, "^(%s)$",
				pattern);
		code = regcomp(&r->re, anchored, REG_EXTENDED | REG_NOSUB);
		free(anchored);
		if (code != 0)
		{
			char errbuf[256];

			regerror(code, &r->re, errbuf, sizeof errbuf);
			writeMemoNote("[?] bpcmdd bad whitelist regex", errbuf);
			free(r->pattern);
			return -1;
		}
	}

	numRules++;
	return 0;
}

/*	Loads the whitelist file into the global rule table.  Returns 0,
 *	or -1 if the file cannot be read or contains a bad rule.	*/

static int loadWhitelist(const char *path)
{
	FILE *f;
	char  line[4096];
	int   lineno = 0;

	f = fopen(path, "r");
	if (f == NULL)
	{
		putSysErrmsg("bpcmdd can't open whitelist file.", path);
		return -1;
	}

	while (fgets(line, sizeof line, f) != NULL)
	{
		MatchMode mode;
		char	 *p;
		char	 *pattern;

		lineno++;
		rstrip(line);
		p = line;
		while (*p == ' ' || *p == '\t')
		{
			p++;
		}

		if (*p == '\0' || *p == '#')
		{
			continue; /*	Blank line or comment.	*/
		}

		/*	Optional leading mode keyword.	*/

		mode = MatchRegex;
		pattern = p;
		if (strncmp(p, "exact", 5) == 0
				&& isspace((unsigned char) p[5]))
		{
			mode = MatchExact;
			pattern = p + 5;
		}
		else if (strncmp(p, "glob", 4) == 0
				&& isspace((unsigned char) p[4]))
		{
			mode = MatchGlob;
			pattern = p + 4;
		}
		else if (strncmp(p, "regex", 5) == 0
				&& isspace((unsigned char) p[5]))
		{
			mode = MatchRegex;
			pattern = p + 5;
		}

		while (*pattern == ' ' || *pattern == '\t')
		{
			pattern++;
		}

		if (*pattern == '\0')
		{
			char note[32];

			isprintf(note, sizeof note, "line %d", lineno);
			writeMemoNote("[?] bpcmdd whitelist: empty pattern "
					"ignored", note);
			continue;
		}

		if (addRule(mode, pattern) < 0)
		{
			fclose(f);
			return -1;
		}
	}

	fclose(f);
	if (numRules == 0)
	{
		writeMemo("[?] bpcmdd whitelist has no rules; all commands "
				"will be denied.");
	}

	return 0;
}

/*	Returns 1 if the normalised command line is permitted by any rule,
 *	0 otherwise.							*/

static int commandAllowed(const char *cmdline)
{
	int i;

	for (i = 0; i < numRules; i++)
	{
		Rule *r = &rules[i];

		switch (r->mode)
		{
		case MatchExact:
			if (strcmp(r->pattern, cmdline) == 0)
			{
				return 1;
			}

			break;

		case MatchGlob:
			if (fnmatch(r->pattern, cmdline, 0) == 0)
			{
				return 1;
			}

			break;

		case MatchRegex:
			if (regexec(&r->re, cmdline, 0, NULL, 0) == 0)
			{
				return 1;
			}

			break;
		}
	}

	return 0;
}

/*	Parses a comma-separated list of source-EID glob patterns (from the
 *	-a option) into the allowlist.  Empty items are skipped.  Returns 0,
 *	or -1 on allocation failure.					*/

static int parseAllowedEids(const char *arg)
{
	char *copy;
	char *tok;

	copy = strdup(arg);
	if (copy == NULL)
	{
		return -1;
	}

	for (tok = strtok(copy, ","); tok != NULL; tok = strtok(NULL, ","))
	{
		char **bigger;
		char  *pat;

		while (*tok == ' ' || *tok == '\t')
		{
			tok++;
		}

		if (*tok == '\0')
		{
			continue;
		}

		bigger = realloc(allowedEids,
				(numAllowedEids + 1) * sizeof(char *));
		if (bigger == NULL)
		{
			free(copy);
			return -1;
		}

		allowedEids = bigger;
		pat = strdup(tok);
		if (pat == NULL)
		{
			free(copy);
			return -1;
		}

		allowedEids[numAllowedEids++] = pat;
	}

	free(copy);
	allowlistActive = 1;
	return 0;
}

/*	Returns 1 if the allowlist is inactive or 'srcEid' matches one of its
 *	glob patterns, 0 otherwise.					*/

static int sourceAllowed(const char *srcEid)
{
	int i;

	if (!allowlistActive)
	{
		return 1;
	}

	if (srcEid == NULL)
	{
		return 0;
	}

	for (i = 0; i < numAllowedEids; i++)
	{
		if (fnmatch(allowedEids[i], srcEid, 0) == 0)
		{
			return 1;
		}
	}

	return 0;
}

/*	Resolves the -u argument (a login name or numeric uid) into the
 *	identity every command will be exec'd under.  Returns 0, or -1 if the
 *	user is unknown.						*/

static int configureRunAs(const char *runAsUser)
{
	struct passwd *pw;

	pw = getpwnam(runAsUser);
	if (pw == NULL)
	{
		char *end;
		long  uid = strtol(runAsUser, &end, 10);

		if (*runAsUser != '\0' && *end == '\0')
		{
			pw = getpwuid((uid_t) uid);
		}
	}

	if (pw == NULL)
	{
		fprintf(stderr, "bpcmdd: unknown user '%s'.\n", runAsUser);
		return -1;
	}

	runAsUid = pw->pw_uid;
	runAsGid = pw->pw_gid;
	istrcpy(runAsName, pw->pw_name, sizeof runAsName);
	istrcpy(runAsHome, pw->pw_dir ? pw->pw_dir : "", sizeof runAsHome);
	runAsSet = 1;
	return 0;
}

/*	Child-side privilege drop: supplementary groups, gid, then uid (gid
 *	before uid, since dropping uid first would forfeit the privilege
 *	needed to change gid).  Returns 0, or -1 on any failure -- in which
 *	case the caller must not exec.					*/

static int dropPrivileges(void)
{
	if (!runAsSet)
	{
		return 0;
	}

	if (initgroups(runAsName, runAsGid) < 0 || setgid(runAsGid) < 0
			|| setuid(runAsUid) < 0)
	{
		return -1;
	}

	if (runAsHome[0] != '\0')
	{
		setenv("HOME", runAsHome, 1);
	}

	setenv("USER", runAsName, 1);
	setenv("LOGNAME", runAsName, 1);
	return 0;
}

/*	Reads the entire payload of a delivered bundle into a freshly
 *	malloc'd buffer.  Returns the buffer (caller frees) and sets
 *	*length, or NULL on failure.  A zero-length payload yields a
 *	1-byte buffer and *length == 0.				*/

static char *readPayload(Object adu, int *length)
{
	ZcoReader reader;
	vast	  contentLength;
	char	 *buffer;
	int	  len;

	CHKNULL(sdr_begin_xn(sdr));
	contentLength = zco_source_data_length(sdr, adu);
	sdr_exit_xn(sdr);
	if (contentLength < 0)
	{
		putErrmsg("bpcmdd can't get payload length.", NULL);
		return NULL;
	}

	buffer = MTAKE(contentLength == 0 ? 1 : (size_t) contentLength);
	if (buffer == NULL)
	{
		putErrmsg("bpcmdd can't allocate payload buffer.", NULL);
		return NULL;
	}

	if (contentLength > 0)
	{
		zco_start_receiving(adu, &reader);
		CHKNULL(sdr_begin_xn(sdr));
		len = zco_receive_source(sdr, &reader, contentLength, buffer);
		if (sdr_end_xn(sdr) < 0 || len < 0)
		{
			putErrmsg("bpcmdd can't read payload.", NULL);
			MRELEASE(buffer);
			return NULL;
		}
	}

	*length = (int) contentLength;
	return buffer;
}

/*	Splits a NUL-terminated, mutable command line into a NULL-
 *	terminated argv whose entries point into 'line'.  Returns the argv
 *	(caller frees the array, not the strings) and sets *argc, or NULL
 *	on allocation failure.  *argc may be 0 for a blank command line.*/

static char **tokenize(char *line, int *argc)
{
	static const char ws[] = " \t\n\r\f\v";
	char		**argv;
	char		 *tok;
	int		  cap = 8;
	int		  n = 0;

	argv = malloc(cap * sizeof(char *));
	if (argv == NULL)
	{
		return NULL;
	}

	for (tok = strtok(line, ws); tok != NULL; tok = strtok(NULL, ws))
	{
		if (n + 1 >= cap) /*	Keep room for the NULL.	*/
		{
			char **bigger;

			cap *= 2;
			bigger = realloc(argv, cap * sizeof(char *));
			if (bigger == NULL)
			{
				free(argv);
				return NULL;
			}

			argv = bigger;
		}

		argv[n++] = tok;
	}

	argv[n] = NULL;
	*argc = n;
	return argv;
}

/*	Rejoins argv into a single normalised command line (one space
 *	between tokens) for whitelist matching.  Caller frees.		*/

static char *joinArgv(char **argv, int argc)
{
	size_t total = 1; /*	Terminating NUL.	*/
	char  *s;
	char  *p;
	int    i;

	for (i = 0; i < argc; i++)
	{
		total += strlen(argv[i]) + 1; /*	Token + space/NUL.*/
	}

	s = malloc(total);
	if (s == NULL)
	{
		return NULL;
	}

	p = s;
	for (i = 0; i < argc; i++)
	{
		if (i > 0)
		{
			*p++ = ' ';
		}

		p = stpcpy(p, argv[i]);
	}

	*p = '\0';
	return s;
}

/*	Forks the (already tokenised) command with an empty stdin and
 *	collects its stdout into a malloc'd buffer.  Returns the command's
 *	exit code (or -1 if it could not be run); *replyBuf / *replyLen
 *	receive the captured stdout (caller frees *replyBuf).		*/

static int runCommand(char **cmdArgv, char *srcEid, char *ownEid,
		char **replyBuf, int *replyLen)
{
	int    outPipe[2];
	pid_t  cmdPid;
	size_t cap = 4096;
	size_t len = 0;
	char  *buffer;
	int    status;

	*replyBuf = NULL;
	*replyLen = 0;

	if (pipe(outPipe) < 0)
	{
		putSysErrmsg("bpcmdd can't create stdout pipe.", NULL);
		return -1;
	}

	cmdPid = fork();
	if (cmdPid == 0) /*	Command child.	*/
	{
		int nullfd = open("/dev/null", O_RDONLY);

		if (nullfd >= 0)
		{
			dup2(nullfd, STDIN_FILENO);
			close(nullfd);
		}

		dup2(outPipe[1], STDOUT_FILENO);
		close(outPipe[0]);
		close(outPipe[1]);
		if (srcEid)
		{
			setenv("BP_SOURCE_EID", srcEid, 1);
		}

		setenv("BP_DEST_EID", ownEid, 1);
		if (dropPrivileges() < 0)
		{
			_exit(127);
		}

		execvp(cmdArgv[0], cmdArgv);
		_exit(127); /*	exec failed.	*/
	}

	if (cmdPid < 0)
	{
		putSysErrmsg("bpcmdd can't fork command.", cmdArgv[0]);
		close(outPipe[0]);
		close(outPipe[1]);
		return -1;
	}

	close(outPipe[1]);

	buffer = malloc(cap);
	if (buffer == NULL)
	{
		putErrmsg("bpcmdd can't allocate stdout buffer.", NULL);
		close(outPipe[0]);
	}
	else
	{
		for (;;)
		{
			ssize_t n;

			if (len == cap)
			{
				char *bigger;

				cap *= 2;
				bigger = realloc(buffer, cap);
				if (bigger == NULL)
				{
					putErrmsg("bpcmdd out of memory for "
						  "stdout.",
							NULL);
					free(buffer);
					buffer = NULL;
					break;
				}

				buffer = bigger;
			}

			n = read(outPipe[0], buffer + len, cap - len);
			if (n < 0)
			{
				if (errno == EINTR)
				{
					continue;
				}

				break;
			}

			if (n == 0)
			{
				break; /*	EOF.		*/
			}

			len += n;
		}

		close(outPipe[0]);
	}

	while (waitpid(cmdPid, &status, 0) < 0 && errno == EINTR)
	{
		continue;
	}

	*replyBuf = buffer;
	*replyLen = (int) len;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/*	Sends 'data' back to the bundle source as a reply bundle.	*/

static void sendReply(char *destEid, char *data, int dataLen, int replyTtl)
{
	Object payload;
	Object zco;
	Object newBundle;

	CHKVOID(sdr_begin_xn(sdr));
	payload = sdr_malloc(sdr, dataLen);
	if (payload)
	{
		sdr_write(sdr, payload, data, dataLen);
	}

	if (sdr_end_xn(sdr) < 0 || payload == 0)
	{
		putErrmsg("bpcmdd can't allocate reply payload.", NULL);
		return;
	}

	zco = ionCreateZco(ZcoSdrSource, payload, 0, dataLen, BP_STD_PRIORITY,
			0, ZcoOutbound, NULL);
	if (zco == 0 || zco == (Object) ERROR)
	{
		putErrmsg("bpcmdd can't create reply ZCO.", NULL);
		return;
	}

	if (bp_send(sap, destEid, NULL, replyTtl, BP_STD_PRIORITY,
			    NoCustodyRequested, 0, 0, NULL, zco, &newBundle) <= 0)
	{
		putErrmsg("bpcmdd can't send reply bundle.", destEid);
		CHKVOID(sdr_begin_xn(sdr));
		zco_destroy(sdr, zco);
		if (sdr_end_xn(sdr) < 0)
		{
			putErrmsg("bpcmdd can't destroy reply ZCO.", NULL);
		}
	}
}

/*	True if a reply should be sent to this bundle source.		*/

static int replyable(int reply, char *srcEid)
{
	return reply && srcEid && strcmp(srcEid, "dtn:none") != 0;
}

int main(int argc, char **argv)
{
	int	   reply = 1;
	int	   replyTtl = 86400;
	char	  *ownEid;
	char	  *whitelistPath;
	char	  *allowArg = NULL;
	char	  *runAsUser = NULL;
	BpDelivery dlv;
	int	   c;

	while ((c = getopt(argc, argv, "nt:a:u:")) != -1)
	{
		switch (c)
		{
		case 'n':
			reply = 0;
			break;

		case 't':
			replyTtl = atoi(optarg);
			if (replyTtl <= 0)
			{
				PUTS("bpcmdd: ttl must be a positive integer.");
				return 1;
			}

			break;

		case 'a':
			allowArg = optarg;
			break;

		case 'u':
			runAsUser = optarg;
			break;

		default:
			PUTS(usage);
			return 1;
		}
	}

	if (optind + 2 != argc) /*	Need EID + whitelist file.	*/
	{
		PUTS(usage);
		return 1;
	}

	ownEid = argv[optind];
	whitelistPath = argv[optind + 1];

	setlinebuf(stdout);
	isignal(SIGPIPE, SIG_IGN);

	if (bp_attach() < 0)
	{
		putErrmsg("bpcmdd can't attach to BP.", NULL);
		return 1;
	}

	if (loadWhitelist(whitelistPath) < 0)
	{
		putErrmsg("bpcmdd can't load whitelist.", whitelistPath);
		bp_detach();
		return 1;
	}

	if (allowArg != NULL && parseAllowedEids(allowArg) < 0)
	{
		putErrmsg("bpcmdd can't parse allowed-EID list.", allowArg);
		bp_detach();
		return 1;
	}

	if (runAsUser != NULL && configureRunAs(runAsUser) < 0)
	{
		bp_detach();
		return 1;
	}

	if (bp_open(ownEid, &sap) < 0)
	{
		putErrmsg("bpcmdd can't open own endpoint.", ownEid);
		bp_detach();
		return 1;
	}

	sdr = bp_get_sdr();
	isignal(SIGINT, handleQuit);

	while (running)
	{
		char  *payload;
		int    payloadLen = 0;
		char  *cmdline;
		char **cmdArgv;
		int    cmdArgc = 0;
		char  *candidate;
		char  *replyBuf;
		int    replyLen;

		if (bp_receive(sap, &dlv, BP_BLOCKING) < 0)
		{
			putErrmsg("bpcmdd bundle reception failed.", NULL);
			running = 0;
			continue;
		}

		if (dlv.result == BpReceptionInterrupted || dlv.adu == 0)
		{
			bp_release_delivery(&dlv, 1);
			continue;
		}

		if (dlv.result == BpEndpointStopped)
		{
			bp_release_delivery(&dlv, 1);
			break;
		}

		if (dlv.result != BpPayloadPresent)
		{
			bp_release_delivery(&dlv, 1);
			continue;
		}

		if (!sourceAllowed(dlv.bundleSourceEid))
		{
			writeMemoNote("[?] bpcmdd denied source",
					dlv.bundleSourceEid ? dlv.bundleSourceEid
							    : "(anonymous)");
			bp_release_delivery(&dlv, 1);
			continue;
		}

		payload = readPayload(dlv.adu, &payloadLen);
		if (payload == NULL)
		{
			bp_release_delivery(&dlv, 1);
			continue;
		}

		/*	NUL-terminated mutable copy for tokenising.	*/

		cmdline = malloc((size_t) payloadLen + 1);
		if (cmdline == NULL)
		{
			putErrmsg("bpcmdd out of memory.", NULL);
			MRELEASE(payload);
			bp_release_delivery(&dlv, 1);
			continue;
		}

		memcpy(cmdline, payload, payloadLen);
		cmdline[payloadLen] = '\0';
		MRELEASE(payload);

		cmdArgv = tokenize(cmdline, &cmdArgc);
		if (cmdArgv == NULL || cmdArgc == 0)
		{
			free(cmdArgv);
			free(cmdline);
			bp_release_delivery(&dlv, 1);
			continue;
		}

		candidate = joinArgv(cmdArgv, cmdArgc);
		if (candidate == NULL)
		{
			putErrmsg("bpcmdd out of memory.", NULL);
			free(cmdArgv);
			free(cmdline);
			bp_release_delivery(&dlv, 1);
			continue;
		}

		if (!commandAllowed(candidate))
		{
			writeMemoNote("[?] bpcmdd denied command", candidate);
			if (replyable(reply, dlv.bundleSourceEid))
			{
				char msg[] =
					"bpcmdd: command not permitted\n";

				sendReply(dlv.bundleSourceEid, msg,
						(int) strlen(msg), replyTtl);
			}

			free(candidate);
			free(cmdArgv);
			free(cmdline);
			bp_release_delivery(&dlv, 1);
			continue;
		}

		oK(runCommand(cmdArgv, dlv.bundleSourceEid, ownEid, &replyBuf,
				&replyLen));

		if (replyable(reply, dlv.bundleSourceEid) && replyBuf
				&& replyLen > 0)
		{
			sendReply(dlv.bundleSourceEid, replyBuf, replyLen,
					replyTtl);
		}

		if (replyBuf)
		{
			free(replyBuf);
		}

		free(candidate);
		free(cmdArgv);
		free(cmdline);
		bp_release_delivery(&dlv, 1);
	}

	bp_close(sap);
	writeErrmsgMemos();
	PUTS("Stopping bpcmdd.");
	fflush(NULL);
	bp_detach();
	return 0;
}
