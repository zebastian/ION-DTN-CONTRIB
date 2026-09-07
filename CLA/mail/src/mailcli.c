/*	mailcli.c:	BP mail (POP3) convergence-layer input daemon.
			Polls a mailbox, extracts bundles from each
			message and injects them into ION.		*/

#include "mailcurl.h"

typedef struct
{
	VInduct		*vduct;
	AcqWorkArea	*work;
	MailCliConfig	*cfg;
	int		 running;
} ReceiverThreadParms;

/*	The receiver thread reads this flag for as long as it runs, and
 *	the main thread clears it at shutdown, so both go through a relaxed
 *	atomic access: the reader acts on a whole poll cycle rather than on
 *	the instant of the write, and the join that follows is what orders
 *	everything else.					*/

#define MAIL_GET(field)	__atomic_load_n(&(field), __ATOMIC_RELAXED)
#define MAIL_SET(field, v)	__atomic_store_n(&(field), (v), \
				__ATOMIC_RELAXED)

typedef struct
{
	AcqWorkArea	*work;
	int		 injected;
} InjectCtx;

static void	interruptThread(int signum)
{
	(void) signum;

	isignal(SIGTERM, interruptThread);
	ionKillMainThread("mailcli");
}

static int	parseCliArgs(int argc, char *argv[], MailCliConfig *cfg)
{
	int	i;

	memset(cfg, 0, sizeof(MailCliConfig));
	cfg->server.verifyPeer = 1;
	cfg->encoding = MAIL_ENC_ATTACH;
	cfg->pollSecs = MAIL_DEFAULT_POLL;

	/*	argv[argc - 1] is the duct name appended by ION.	*/
	for (i = 1; i < argc - 1; i++)
	{
		if (strcmp(argv[i], "-S") == 0 && i + 1 < argc)
		{
			if (mailParseServerSpec(argv[++i], cfg->server.host,
					&cfg->server.port,
					cfg->server.username,
					cfg->server.password) < 0)
			{
				return -1;
			}
		}
		else if (strcmp(argv[i], "-u") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->server.username, argv[++i], MAIL_MAX_CRED);
		}
		else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->server.password, argv[++i], MAIL_MAX_CRED);
		}
		else if (strcmp(argv[i], "-s") == 0)
		{
			cfg->server.useSsl = 1;
		}
		else if (strcmp(argv[i], "-t") == 0)
		{
			cfg->server.useTls = 1;
		}
		else if (strcmp(argv[i], "-C") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->server.caFile, argv[++i], MAIL_MAX_PATH);
		}
		else if (strcmp(argv[i], "-n") == 0)
		{
			cfg->server.verifyPeer = 0;
		}
		else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc)
		{
			cfg->encoding = mailEncodingFromName(argv[++i]);
			if (cfg->encoding < 0)
			{
				return -1;
			}
		}
		else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc)
		{
			cfg->pollSecs = atoi(argv[++i]);
		}
		else
		{
			putErrmsg("mailcli: unknown argument.", argv[i]);
			return -1;
		}
	}

	if (cfg->server.host[0] == '\0')
	{
		putErrmsg("mailcli: -S <server> required.", NULL);
		return -1;
	}

	if (cfg->server.port == 0)
	{
		cfg->server.port = cfg->server.useSsl ? 995 : 110;
	}

	if (cfg->pollSecs <= 0)
	{
		cfg->pollSecs = MAIL_DEFAULT_POLL;
	}

	return 0;
}

static int	injectBundle(void *ctx, const unsigned char *bundle, size_t len)
{
	InjectCtx	*ic = (InjectCtx *) ctx;

	if (len == 0)
	{
		return 0;
	}

	if (bpBeginAcq(ic->work, 0, NULL) < 0
	|| bpContinueAcq(ic->work, (char *) bundle, len, 0, 0) < 0
	|| bpEndAcq(ic->work) < 0)
	{
		putErrmsg("mailcli can't acquire bundle from mail.", NULL);
		return -1;
	}

	ic->injected++;
	return 0;
}

/*	Delete a message once at least one bundle has been injected;
 *	preserve messages that carry no recoverable bundle.		*/
static int	onMessage(void *ctx, const char *msg, size_t len)
{
	ReceiverThreadParms	*rtp = (ReceiverThreadParms *) ctx;
	InjectCtx		 ic;

	ic.work = rtp->work;
	ic.injected = 0;

	if (mailParseMessage(msg, len, rtp->cfg->encoding, injectBundle, &ic)
			< 0)
	{
		return -1;
	}

	return ic.injected > 0 ? 1 : 0;
}

static void	*receiveBundles(void *parm)
{
	ReceiverThreadParms	*rtp = (ReceiverThreadParms *) parm;
	char			 err[256];

	snooze(1);	/*	Let main thread become interruptible.	*/

	while (MAIL_GET(rtp->running))
	{
		int	slept;

		err[0] = '\0';
		if (mailPop3Poll(&rtp->cfg->server, onMessage, rtp, err,
				sizeof(err)) < 0)
		{
			char	memoBuf[512];

			isprintf(memoBuf, sizeof(memoBuf),
					"[?] mailcli: POP3 poll failed: %s", err);
			writeMemo(memoBuf);
		}

		for (slept = 0; slept < rtp->cfg->pollSecs
				&& MAIL_GET(rtp->running);
				slept++)
		{
			snooze(1);
		}
	}

	writeErrmsgMemos();
	writeMemo("[i] mailcli receiver thread has ended.");
	return NULL;
}

/*	*	*	Main thread	*	*	*	*	*/

#if defined (ION_LWT)
int	mailcli(saddr a1, saddr a2, saddr a3, saddr a4, saddr a5,
		saddr a6, saddr a7, saddr a8, saddr a9, saddr a10)
{
	char	*ductName = (char *) a1;
	int	largc = 2;
	char	*largv[2];

	largv[0] = "mailcli";
	largv[1] = ductName;
#else
int	main(int argc, char *argv[])
{
	char	*ductName = (argc > 1 ? argv[argc - 1] : NULL);
	int	largc = argc;
	char	**largv = argv;
#endif
	VInduct			*vduct;
	PsmAddress		 vductElt;
	MailCliConfig		 cfg;
	ReceiverThreadParms	 rtp;
	pthread_t		 receiverThread;

	if (ductName == NULL)
	{
		PUTS("Usage: mailcli -S [user:pass@]host[:port] "
			"[-u user] [-p pass] [-s] [-t] [-C cafile] [-n] "
			"[-e attach|b64|raw] [-i pollsecs] <mailbox>");
		return 0;
	}

	if (parseCliArgs(largc, largv, &cfg) < 0)
	{
		putErrmsg("mailcli: invalid arguments.", NULL);
		return -1;
	}

	if (bpAttach() < 0)
	{
		putErrmsg("mailcli can't attach to BP.", NULL);
		return -1;
	}

	findInduct("mail", ductName, &vduct, &vductElt);
	if (vductElt == 0)
	{
		putErrmsg("No such mail duct.", ductName);
		return -1;
	}

	if (vduct->cliPid != ERROR && vduct->cliPid != sm_TaskIdSelf())
	{
		putErrmsg("CLI task is already started for this duct.",
				itoa(vduct->cliPid));
		return -1;
	}

	if (mailCurlGlobalInit() < 0)
	{
		putErrmsg("mailcli can't initialize libcurl.", NULL);
		return -1;
	}

	memset(&rtp, 0, sizeof(rtp));
	rtp.vduct = vduct;
	rtp.cfg = &cfg;
	rtp.work = bpGetAcqArea(vduct);
	if (rtp.work == NULL)
	{
		putErrmsg("mailcli can't get acquisition work area.", NULL);
		mailCurlGlobalCleanup();
		return -1;
	}

	ionNoteMainThread("mailcli");
	isignal(SIGTERM, interruptThread);

	MAIL_SET(rtp.running, 1);
	if (pthread_begin(&receiverThread, NULL, receiveBundles, &rtp))
	{
		putSysErrmsg("mailcli can't create receiver thread", NULL);
		bpReleaseAcqArea(rtp.work);
		mailCurlGlobalCleanup();
		return -1;
	}

	{
		char	memoBuf[1024];

		isprintf(memoBuf, sizeof(memoBuf),
			"[i] mailcli is running, duct '%s', server '%s:%d', "
			"encoding '%s', poll %ds.", ductName, cfg.server.host,
			cfg.server.port, mailEncodingName(cfg.encoding),
			cfg.pollSecs);
		writeMemo(memoBuf);
	}

	ionPauseMainThread(-1);

	MAIL_SET(rtp.running, 0);
	pthread_join(receiverThread, NULL);
	bpReleaseAcqArea(rtp.work);
	mailCurlGlobalCleanup();
	writeErrmsgMemos();
	writeMemo("[i] mailcli duct has ended.");
	ionDetach();
	return 0;
}
