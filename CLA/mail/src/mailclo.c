/*	mailclo.c:	BP mail (SMTP) convergence-layer output daemon.
			Sends each outbound bundle to a peer mailbox; an
			optional digest interval batches several bundles
			into a single message.				*/

#include "mailcurl.h"
#include <time.h>

static sm_SemId		mailcloSemaphore(sm_SemId *semid)
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

	sm_SemEnd(mailcloSemaphore(NULL));
}

/*	*	*	Argument parsing	*	*	*	*/

static int	parseCloArgs(int argc, char *argv[], MailCloConfig *cfg)
{
	int	i;

	memset(cfg, 0, sizeof(MailCloConfig));
	cfg->server.verifyPeer = 1;
	cfg->encoding = MAIL_ENC_ATTACH;
	cfg->maxBundles = MAIL_DEFAULT_DIGEST_MAX;

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
		else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->sender, argv[++i], MAIL_MAX_ADDR);
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
		else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc)
		{
			cfg->digestSecs = atoi(argv[++i]);
		}
		else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc)
		{
			cfg->maxBundles = atoi(argv[++i]);
		}
		else if (strcmp(argv[i], "-M") == 0 && i + 1 < argc)
		{
			cfg->maxBytes = atol(argv[++i]);
		}
		else
		{
			putErrmsg("mailclo: unknown argument.", argv[i]);
			return -1;
		}
	}

	if (cfg->server.host[0] == '\0' || cfg->sender[0] == '\0')
	{
		putErrmsg("mailclo: -S <server> and -f <sender> required.", NULL);
		return -1;
	}

	if (cfg->server.port == 0)
	{
		cfg->server.port = cfg->server.useSsl ? 465
				: (cfg->server.useTls ? 587 : 25);
	}

	if (cfg->maxBundles <= 0)
	{
		cfg->maxBundles = MAIL_DEFAULT_DIGEST_MAX;
	}

	return 0;
}

/*	*	*	Batching state	*	*	*	*	*/

typedef struct pend
{
	Object		 zco;
	unsigned char	*bytes;
	size_t		 len;
	struct pend	*next;
} Pend;

typedef struct
{
	MailCloConfig	*cfg;
	const char	*recipient;
	Pend		*head;
	Pend		*tail;
	int		 count;
	long		 bytes;
	time_t		 firstAt;
	int		 shutdown;
	pthread_mutex_t	 mtx;
	pthread_cond_t	 cv;
} CloState;

/*	Send a batch of bundles as one message and settle each with ION.
 *	The caller retains ownership of the buffers.			*/
static void	sendAndAck(MailCloConfig *cfg, const char *recipient,
		Object *zcos, MailBundle *arr, int n)
{
	char	*msg = NULL;
	size_t	 msgLen = 0;
	char	 err[256];
	int	 sent;
	int	 i;

	if (mailBuildMessage(cfg->sender, recipient, NULL, cfg->encoding,
			arr, n, &msg, &msgLen) < 0)
	{
		writeMemo("[?] mailclo: can't build message; requeuing.");
		sent = -1;
	}
	else
	{
		err[0] = '\0';
		sent = mailSmtpSend(&cfg->server, cfg->sender, recipient,
				msg, msgLen, err, sizeof(err));
		if (sent < 0)
		{
			char	memoBuf[512];

			isprintf(memoBuf, sizeof(memoBuf),
					"[?] mailclo: SMTP send failed: %s", err);
			writeMemo(memoBuf);
		}
	}

	free(msg);

	for (i = 0; i < n; i++)
	{
		if (sent < 0)
		{
			if (bpHandleXmitFailure(zcos[i]) < 0)
			{
				putErrmsg("Can't handle xmit failure.", NULL);
			}
		}
		else
		{
			if (bpHandleXmitSuccess(zcos[i]) < 0)
			{
				putErrmsg("Can't handle xmit success.", NULL);
			}
		}
	}
}

static void	flushPending(CloState *st, Pend *batch, int n)
{
	Object		*zcos = MTAKE(n * sizeof(Object));
	MailBundle	*arr = MTAKE(n * sizeof(MailBundle));
	Pend		*p;
	Pend		*next;
	int		 i = 0;

	if (zcos == NULL || arr == NULL)
	{
		putErrmsg("No memory to flush mail digest.", NULL);
	}
	else
	{
		for (p = batch; p != NULL; p = p->next)
		{
			zcos[i] = p->zco;
			arr[i].bytes = p->bytes;
			arr[i].len = p->len;
			i++;
		}

		sendAndAck(st->cfg, st->recipient, zcos, arr, n);
	}

	if (zcos)
	{
		MRELEASE(zcos);
	}

	if (arr)
	{
		MRELEASE(arr);
	}

	for (p = batch; p != NULL; p = next)
	{
		next = p->next;
		free(p->bytes);
		free(p);
	}
}

static void	*flushThread(void *parm)
{
	CloState	*st = (CloState *) parm;

	pthread_mutex_lock(&st->mtx);
	while (1)
	{
		while (st->count == 0 && !st->shutdown)
		{
			pthread_cond_wait(&st->cv, &st->mtx);
		}

		if (st->count == 0 && st->shutdown)
		{
			break;
		}

		if (st->count > 0)
		{
			time_t	now = time(NULL);
			time_t	deadline = st->firstAt + st->cfg->digestSecs;
			int	capHit = st->count >= st->cfg->maxBundles
				|| (st->cfg->maxBytes > 0
					&& st->bytes >= st->cfg->maxBytes);

			if (!st->shutdown && !capHit && now < deadline)
			{
				struct timespec	ts;

				ts.tv_sec = deadline;
				ts.tv_nsec = 0;
				pthread_cond_timedwait(&st->cv, &st->mtx, &ts);
				continue;
			}

			{
				Pend	*batch = st->head;
				int	 n = st->count;

				st->head = st->tail = NULL;
				st->count = 0;
				st->bytes = 0;

				pthread_mutex_unlock(&st->mtx);
				flushPending(st, batch, n);
				pthread_mutex_lock(&st->mtx);
			}
		}
	}

	pthread_mutex_unlock(&st->mtx);
	return NULL;
}

/*	Read a dequeued bundle's bytes into a fresh buffer.		*/
static unsigned char	*extractBundle(Sdr sdr, Object bundleZco, size_t *len)
{
	unsigned int	bundleLength;
	unsigned char  *buf;
	ZcoReader	reader;
	int		bytesToSend;

	CHKNULL(sdr_begin_xn(sdr));
	bundleLength = zco_length(sdr, bundleZco);
	sdr_exit_xn(sdr);

	buf = malloc(bundleLength);
	if (buf == NULL)
	{
		putErrmsg("No memory for bundle in mailclo.", itoa(bundleLength));
		return NULL;
	}

	zco_start_transmitting(bundleZco, &reader);
	zco_track_file_offset(&reader);
	CHKNULL(sdr_begin_xn(sdr));
	bytesToSend = zco_transmit(sdr, &reader, bundleLength, (char *) buf);
	if (sdr_end_xn(sdr) < 0 || bytesToSend < 0)
	{
		putErrmsg("Can't issue from ZCO.", NULL);
		free(buf);
		return NULL;
	}

	*len = bytesToSend;
	return buf;
}

/*	*	*	Main thread	*	*	*	*	*/

#if defined (ION_LWT)
int	mailclo(saddr a1, saddr a2, saddr a3, saddr a4, saddr a5,
		saddr a6, saddr a7, saddr a8, saddr a9, saddr a10)
{
	char	*ductName = (char *) a1;
	int	largc = 2;
	char	*largv[2];

	largv[0] = "mailclo";
	largv[1] = ductName;
#else
int	main(int argc, char *argv[])
{
	char	*ductName = (argc > 1 ? argv[argc - 1] : NULL);
	int	largc = argc;
	char	**largv = argv;
#endif
	VOutduct	*vduct;
	PsmAddress	 vductElt;
	Sdr		 sdr;
	Object		 bundleZco;
	BpAncillaryData	 ancillaryData;
	MailCloConfig	 cfg;
	CloState	 st;
	pthread_t	 flusher;
	int		 haveFlusher = 0;

	if (ductName == NULL)
	{
		PUTS("Usage: mailclo -S [user:pass@]host[:port] -f sender "
			"[-u user] [-p pass] [-s] [-t] [-C cafile] [-n] "
			"[-e attach|b64|raw] [-d secs] [-m maxbundles] "
			"[-M maxbytes] <recipient>");
		return 0;
	}

	if (parseCloArgs(largc, largv, &cfg) < 0)
	{
		putErrmsg("mailclo: invalid arguments.", NULL);
		return -1;
	}

	if (bpAttach() < 0)
	{
		putErrmsg("mailclo can't attach to BP.", NULL);
		return -1;
	}

	findOutduct("mail", ductName, &vduct, &vductElt);
	if (vductElt == 0)
	{
		putErrmsg("No such mail duct.", ductName);
		return -1;
	}

	if (vduct->cloPid != ERROR && vduct->cloPid != sm_TaskIdSelf())
	{
		putErrmsg("CLO task is already started for this duct.",
				itoa(vduct->cloPid));
		return -1;
	}

	if (mailCurlGlobalInit() < 0)
	{
		putErrmsg("mailclo can't initialize libcurl.", NULL);
		return -1;
	}

	sdr = getIonsdr();
	oK(mailcloSemaphore(&(vduct->semaphore)));
	isignal(SIGTERM, shutDownClo);

	memset(&st, 0, sizeof(st));
	st.cfg = &cfg;
	st.recipient = ductName;
	pthread_mutex_init(&st.mtx, NULL);
	pthread_cond_init(&st.cv, NULL);

	if (cfg.digestSecs > 0)
	{
		if (pthread_begin(&flusher, NULL, flushThread, &st))
		{
			putSysErrmsg("mailclo can't create flush thread", NULL);
			mailCurlGlobalCleanup();
			return -1;
		}

		haveFlusher = 1;
	}

	{
		char	memoBuf[1024];

		isprintf(memoBuf, sizeof(memoBuf),
			"[i] mailclo is running, duct '%s', server '%s:%d', "
			"encoding '%s', digest %ds.", ductName, cfg.server.host,
			cfg.server.port, mailEncodingName(cfg.encoding),
			cfg.digestSecs);
		writeMemo(memoBuf);
	}

	while (!(sm_SemEnded(vduct->semaphore)))
	{
		unsigned char	*bytes;
		size_t		 len;

		if (bpDequeue(vduct, &bundleZco, &ancillaryData, -1) < 0)
		{
			putErrmsg("Can't dequeue bundle.", NULL);
			break;
		}

		if (bundleZco == 0)		/*	Outduct closed.	*/
		{
			writeMemo("[i] mailclo outduct closed.");
			sm_SemEnd(mailcloSemaphore(NULL));
			continue;
		}

		if (bundleZco == 1)	/*	Got a corrupt bundle.	*/
		{
			continue;
		}

		bytes = extractBundle(sdr, bundleZco, &len);
		if (bytes == NULL)
		{
			if (bpHandleXmitFailure(bundleZco) < 0)
			{
				putErrmsg("Can't handle xmit failure.", NULL);
				break;
			}

			continue;
		}

		if (cfg.digestSecs <= 0)
		{
			Object		zcos[1];
			MailBundle	arr[1];

			zcos[0] = bundleZco;
			arr[0].bytes = bytes;
			arr[0].len = len;
			sendAndAck(&cfg, ductName, zcos, arr, 1);
			free(bytes);
			sm_TaskYield();
		}
		else
		{
			Pend	*p = malloc(sizeof(Pend));

			if (p == NULL)
			{
				putErrmsg("No memory for digest entry.", NULL);
				free(bytes);
				oK(bpHandleXmitFailure(bundleZco));
				continue;
			}

			p->zco = bundleZco;
			p->bytes = bytes;
			p->len = len;
			p->next = NULL;

			pthread_mutex_lock(&st.mtx);
			if (st.tail == NULL)
			{
				st.head = st.tail = p;
				st.firstAt = time(NULL);
			}
			else
			{
				st.tail->next = p;
				st.tail = p;
			}

			st.count++;
			st.bytes += (long) len;
			pthread_cond_signal(&st.cv);
			pthread_mutex_unlock(&st.mtx);
		}
	}

	if (haveFlusher)
	{
		pthread_mutex_lock(&st.mtx);
		st.shutdown = 1;
		pthread_cond_signal(&st.cv);
		pthread_mutex_unlock(&st.mtx);
		pthread_join(flusher, NULL);
	}

	pthread_mutex_destroy(&st.mtx);
	pthread_cond_destroy(&st.cv);
	mailCurlGlobalCleanup();
	writeErrmsgMemos();
	writeMemo("[i] mailclo duct has ended.");
	ionDetach();
	return 0;
}
