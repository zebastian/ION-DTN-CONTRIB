/*	zclo.c:	zcl convergence-layer output daemon.  Compresses the
		bundles queued on its outduct into a zstd stream and sends
		the stream, cut into carrier bundles, to the peer endpoint
		that names the duct (see doc/design.md).		*/

#include "zclcla.h"

#include <fcntl.h>
#include <unistd.h>
#include <zstd.h>

typedef struct
{
	int		windowMs;	/*	-w			*/
	long long	flushBytes;	/*	-b			*/
	long long	chunkBytes;	/*	-c			*/
	long long	chunkMs;	/*	-C			*/
	int		level;		/*	-l			*/
	int		windowLog;	/*	-W			*/
	int		lifetime;	/*	-L			*/
	int		priority;	/*	-p			*/
	unsigned int	label;		/*	-D			*/
} ZclCloConfig;

typedef struct
{
	ZclCloConfig	*cfg;
	char		*peer;
	ZclEnc		enc;

	/*	Bundles compressed since the last carrier was cut.	*/

	Object		*zcos;
	int		zcoCount;
	int		zcoCap;
	uint64_t	firstPendingMs;
	uint64_t	chunkStartMs;

	int		shutdown;
	pthread_mutex_t	mtx;
	pthread_cond_t	cv;

	uint64_t	bundles;
	uint64_t	bytesIn;
	uint64_t	carriers;
	uint64_t	bytesOut;
	uint64_t	chunksAbandoned;
	uint64_t	loopsRefused;
} CloState;

static ReqAttendant	attendant;

static sm_SemId		zcloSemaphore(sm_SemId *semid)
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

	sm_SemEnd(zcloSemaphore(NULL));
	ionPauseAttendant(&attendant);
}

/*	*	*	Argument parsing	*	*	*	*/

static int	parsePriority(const char *text)
{
	if (strcmp(text, "bulk") == 0 || strcmp(text, "0") == 0)
	{
		return BP_BULK_PRIORITY;
	}

	if (strcmp(text, "std") == 0 || strcmp(text, "1") == 0)
	{
		return BP_STD_PRIORITY;
	}

	if (strcmp(text, "exp") == 0 || strcmp(text, "2") == 0)
	{
		return BP_EXPEDITED_PRIORITY;
	}

	return -1;
}

static int	parseCloArgs(int argc, char *argv[], ZclCloConfig *cfg)
{
	long long	v;
	int		i;

	cfg->windowMs = ZCL_DEFAULT_WINDOW_MS;
	cfg->flushBytes = ZCL_DEFAULT_FLUSH_BYTES;
	cfg->chunkBytes = ZCL_DEFAULT_CHUNK_BYTES;
	cfg->chunkMs = ZCL_DEFAULT_CHUNK_MS;
	cfg->level = ZCL_DEFAULT_LEVEL;
	cfg->windowLog = ZCL_DEFAULT_WINDOWLOG;
	cfg->lifetime = ZCL_DEFAULT_LIFETIME;
	cfg->priority = BP_STD_PRIORITY;
	cfg->label = ZCL_DEFAULT_LABEL;

	/*	argv[argc - 1] is the duct name appended by ION.	*/
	for (i = 1; i < argc - 1; i++)
	{
		const char	*opt = argv[i];
		const char	*arg = (i + 1 < argc - 1) ? argv[i + 1] : NULL;

		if (strcmp(opt, "-l") == 0 && arg)
		{
			/*	zstd levels below 1 are its fast modes.	*/

			cfg->level = atoi(arg);
			if (cfg->level < ZSTD_minCLevel()
			|| cfg->level > ZSTD_maxCLevel())
			{
				putErrmsg("zclo: bad level.", arg);
				return -1;
			}

			i++;
			continue;
		}

		if (strcmp(opt, "-p") == 0 && arg)
		{
			cfg->priority = parsePriority(arg);
			if (cfg->priority < 0)
			{
				putErrmsg("zclo: bad priority.", arg);
				return -1;
			}

			i++;
			continue;
		}

		v = zclParseCount(arg);
		if (arg == NULL || v < 0)
		{
			putErrmsg("zclo: unknown argument or bad value.", opt);
			return -1;
		}

		if (strcmp(opt, "-w") == 0 && v <= 3600000)
		{
			cfg->windowMs = (int) v;
		}
		else if (strcmp(opt, "-b") == 0 && v >= 1)
		{
			cfg->flushBytes = v;
		}
		else if (strcmp(opt, "-c") == 0 && v >= 1)
		{
			cfg->chunkBytes = v;
		}
		else if (strcmp(opt, "-C") == 0)
		{
			cfg->chunkMs = v;
		}
		else if (strcmp(opt, "-W") == 0 && v >= 10 && v <= 27)
		{
			cfg->windowLog = (int) v;
		}
		else if (strcmp(opt, "-L") == 0 && v >= 1 && v <= 0x7fffffff)
		{
			cfg->lifetime = (int) v;
		}
		else if (strcmp(opt, "-D") == 0 && v >= 1 && v <= 0xffffffffLL)
		{
			cfg->label = (unsigned int) v;
		}
		else
		{
			putErrmsg("zclo: unknown argument or bad value.", opt);
			return -1;
		}

		i++;
	}

	return 0;
}

/*	Random per run, so a restarted zclo is a new stream.		*/
static uint64_t	newStreamId(void)
{
	uint64_t	id = 0;
	int		fd = open("/dev/urandom", O_RDONLY);

	if (fd >= 0)
	{
		if (read(fd, &id, sizeof id) != (ssize_t) sizeof id)
		{
			id = 0;
		}

		close(fd);
	}

	if (id == 0)
	{
		id = ((uint64_t) time(NULL) << 32) ^ (uint64_t) getpid()
			^ zclNowMs();
	}

	return id;
}

/*	*	*	Sending carriers	*	*	*	*/

static int	sendCarrier(CloState *st, unsigned char *carrier, size_t len)
{
	Sdr		sdr = getIonsdr();
	BpAncillaryData	ancillary;
	Object		payload;
	Object		zco;
	Object		newBundle;

	CHKERR(sdr_begin_xn(sdr));
	payload = sdr_malloc(sdr, len);
	if (payload)
	{
		sdr_write(sdr, payload, (char *) carrier, len);
	}

	if (sdr_end_xn(sdr) < 0 || payload == 0)
	{
		putErrmsg("zclo can't allocate carrier payload.", itoa(len));
		return -1;
	}

	/*	Waits for ZCO space rather than failing for want of it.	*/

	zco = ionCreateZco(ZcoSdrSource, payload, 0, len,
			(unsigned char) st->cfg->priority, 0, ZcoOutbound,
			&attendant);
	if (zco == 0 || zco == (Object) ERROR)
	{
		putErrmsg("zclo can't create carrier ZCO.", NULL);
		CHKERR(sdr_begin_xn(sdr));
		sdr_free(sdr, payload);
		oK(sdr_end_xn(sdr));
		return -1;
	}

	memset(&ancillary, 0, sizeof ancillary);
	ancillary.dataLabel = st->cfg->label;
	if (bp_send(NULL, st->peer, NULL, st->cfg->lifetime,
			st->cfg->priority, NoCustodyRequested, 0, 0,
			&ancillary, zco, &newBundle) <= 0)
	{
		putErrmsg("zclo can't send carrier.", st->peer);
		CHKERR(sdr_begin_xn(sdr));
		zco_destroy(sdr, zco);
		oK(sdr_end_xn(sdr));
		return -1;
	}

	return 0;
}

static void	settle(Object *zcos, int n, int sent)
{
	int	i;

	for (i = 0; i < n; i++)
	{
		if (sent)
		{
			if (bpHandleXmitSuccess(zcos[i]) < 0)
			{
				putErrmsg("Can't handle xmit success.", NULL);
			}
		}
		else
		{
			if (bpHandleXmitFailure(zcos[i]) < 0)
			{
				putErrmsg("Can't handle xmit failure.", NULL);
			}
		}
	}

	MRELEASE(zcos);
}

/*	Hands over the list of pending bundles; NULL if there are none
 *	or no memory for a new list (then the old one is kept).	*/
static Object	*takeZcos(CloState *st, int *n)
{
	Object	*zcos = st->zcos;

	*n = st->zcoCount;
	if (zcos == NULL)
	{
		return NULL;
	}

	st->zcos = NULL;
	st->zcoCount = 0;
	st->zcoCap = 0;
	return zcos;
}

/*	Drops the open chunk: everything compressed into it and not
 *	yet sent goes back to ION for re-forwarding.  With st->mtx held;
 *	returns with it held.						*/
static void	abandonChunk(CloState *st)
{
	Object	*zcos;
	int	n;

	zclEncAbort(&st->enc);
	st->chunksAbandoned++;
	zcos = takeZcos(st, &n);
	if (zcos)
	{
		pthread_mutex_unlock(&st->mtx);
		settle(zcos, n, 0);
		pthread_mutex_lock(&st->mtx);
	}
}

/*	Cuts a carrier and sends it.  With st->mtx held; returns with it
 *	held.  The lock is let go while the carrier is sent, so the main
 *	thread can go on compressing into the chunk meanwhile.		*/
static void	cutAndSend(CloState *st, int endChunk)
{
	unsigned char	*carrier;
	size_t		len;
	Object		*zcos;
	int		n;
	int		rc;

	rc = zclEncCut(&st->enc, endChunk, &carrier, &len);
	if (rc == 0)
	{
		return;
	}

	if (rc < 0)
	{
		writeMemo("[?] zclo can't compress; chunk abandoned.");
		abandonChunk(st);
		return;
	}

	zcos = takeZcos(st, &n);
	pthread_mutex_unlock(&st->mtx);
	rc = sendCarrier(st, carrier, len);
	free(carrier);
	pthread_mutex_lock(&st->mtx);
	if (rc < 0)
	{
		/*	The peer can't decode the rest of this chunk.	*/

		writeMemo("[?] zclo carrier not sent; chunk abandoned.");
		abandonChunk(st);
	}
	else
	{
		st->carriers++;
		st->bytesOut += len;
	}

	if (zcos)
	{
		pthread_mutex_unlock(&st->mtx);
		settle(zcos, n, rc == 0);
		pthread_mutex_lock(&st->mtx);
	}
}

static void	waitUntil(CloState *st, uint64_t deadlineMs)
{
	struct timespec	ts;

	ts.tv_sec = (time_t) (deadlineMs / 1000);
	ts.tv_nsec = (long) (deadlineMs % 1000) * 1000000;
	pthread_cond_timedwait(&st->cv, &st->mtx, &ts);
}

static void	*flushThread(void *parm)
{
	CloState	*st = (CloState *) parm;
	ZclCloConfig	*cfg = st->cfg;
	uint64_t	now;
	int		end;

	pthread_mutex_lock(&st->mtx);
	while (1)
	{
		if (st->enc.pendingIn == 0)
		{
			if (st->shutdown)
			{
				break;
			}

			pthread_cond_wait(&st->cv, &st->mtx);
			continue;
		}

		now = zclNowMs();
		if (!st->shutdown
		&& (long long) st->enc.pendingIn < cfg->flushBytes
		&& now < st->firstPendingMs + cfg->windowMs)
		{
			waitUntil(st, st->firstPendingMs + cfg->windowMs);
			continue;
		}

		end = st->shutdown
			|| (long long) st->enc.chunkIn >= cfg->chunkBytes
			|| (long long) (now - st->chunkStartMs) >= cfg->chunkMs;
		cutAndSend(st, end);
	}

	/*	Close the frame so the peer can tell the chunk complete.	*/

	cutAndSend(st, 1);
	pthread_mutex_unlock(&st->mtx);
	return NULL;
}

/*	Read a dequeued bundle's bytes into a fresh buffer.		*/
static unsigned char	*extractBundle(Sdr sdr, Object bundleZco, size_t *len)
{
	unsigned int	bundleLength;
	unsigned char	*buf;
	ZcoReader	reader;
	int		bytesToSend;

	CHKNULL(sdr_begin_xn(sdr));
	bundleLength = zco_length(sdr, bundleZco);
	sdr_exit_xn(sdr);

	buf = malloc(bundleLength ? bundleLength : 1);
	if (buf == NULL)
	{
		putErrmsg("No memory for bundle in zclo.", itoa(bundleLength));
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

/*	Compresses one bundle into the open chunk.  0 when it is in,
 *	-1 if it must go back to ION.					*/
static int	addBundle(CloState *st, Object zco, const unsigned char *bytes,
			size_t len)
{
	uint64_t	now = zclNowMs();

	pthread_mutex_lock(&st->mtx);
	if (st->zcoCount == st->zcoCap)
	{
		int	cap = st->zcoCap ? st->zcoCap * 2 : 64;
		Object	*zcos = MTAKE(cap * sizeof(Object));

		if (zcos == NULL)
		{
			pthread_mutex_unlock(&st->mtx);
			return -1;
		}

		if (st->zcos)
		{
			memcpy(zcos, st->zcos, st->zcoCount * sizeof(Object));
			MRELEASE(st->zcos);
		}

		st->zcos = zcos;
		st->zcoCap = cap;
	}

	if (!st->enc.inChunk)
	{
		st->chunkStartMs = now;
	}

	if (st->enc.pendingIn == 0)
	{
		st->firstPendingMs = now;
	}

	if (zclEncAdd(&st->enc, bytes, len) < 0)
	{
		writeMemo("[?] zclo can't compress; chunk abandoned.");
		abandonChunk(st);
		pthread_mutex_unlock(&st->mtx);
		return -1;
	}

	st->zcos[st->zcoCount++] = zco;
	st->bundles++;
	st->bytesIn += len;
	pthread_cond_signal(&st->cv);
	pthread_mutex_unlock(&st->mtx);
	return 0;
}

/*	*	*	Main thread	*	*	*	*	*/

#if defined (ION_LWT)
int	zclo(saddr a1, saddr a2, saddr a3, saddr a4, saddr a5,
		saddr a6, saddr a7, saddr a8, saddr a9, saddr a10)
{
	char	*ductName = (char *) a1;
	int	largc = 2;
	char	*largv[2];

	largv[0] = "zclo";
	largv[1] = ductName;
#else
int	main(int argc, char *argv[])
{
	char	*ductName = (argc > 1 ? argv[argc - 1] : NULL);
	int	largc = argc;
	char	**largv = argv;
#endif
	VOutduct		*vduct;
	PsmAddress		vductElt;
	Sdr			sdr;
	Object			bundleZco;
	BpAncillaryData		ancillaryData;
	ZclCloConfig		cfg;
	CloState		st;
	pthread_condattr_t	cattr;
	pthread_t		flusher;

	if (ductName == NULL || ductName[0] == '-')
	{
		PUTS("Usage: zclo [-w window_ms] [-b flush_bytes] "
			"[-c chunk_bytes] [-C chunk_ms] [-l level] "
			"[-W window_log] [-L lifetime_s] [-p bulk|std|exp] "
			"[-D data_label] <peer EID>");
		return 0;
	}

	if (parseCloArgs(largc, largv, &cfg) < 0)
	{
		putErrmsg("zclo: invalid arguments.", NULL);
		return -1;
	}

	if (bpAttach() < 0)
	{
		putErrmsg("zclo can't attach to BP.", NULL);
		return -1;
	}

	findOutduct(ZCL_PROTOCOL, ductName, &vduct, &vductElt);
	if (vductElt == 0)
	{
		putErrmsg("No such zcl duct.", ductName);
		return -1;
	}

	if (vduct->cloPid != ERROR && vduct->cloPid != sm_TaskIdSelf())
	{
		putErrmsg("CLO task is already started for this duct.",
				itoa(vduct->cloPid));
		return -1;
	}

	if (ionStartAttendant(&attendant) < 0)
	{
		putErrmsg("zclo can't start ZCO attendant.", NULL);
		return -1;
	}

	memset(&st, 0, sizeof st);
	st.cfg = &cfg;
	st.peer = ductName;
	if (zclEncInit(&st.enc, cfg.level, cfg.windowLog, newStreamId()) < 0)
	{
		putErrmsg("zclo can't create zstd compressor.", NULL);
		ionStopAttendant(&attendant);
		return -1;
	}

	pthread_mutex_init(&st.mtx, NULL);
	pthread_condattr_init(&cattr);
	pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
	pthread_cond_init(&st.cv, &cattr);
	pthread_condattr_destroy(&cattr);

	sdr = getIonsdr();
	oK(zcloSemaphore(&(vduct->semaphore)));
	isignal(SIGTERM, shutDownClo);
	if (pthread_begin(&flusher, NULL, flushThread, &st))
	{
		putSysErrmsg("zclo can't create flush thread", NULL);
		zclEncFree(&st.enc);
		ionStopAttendant(&attendant);
		return -1;
	}

	{
		char	memoBuf[512];

		isprintf(memoBuf, sizeof(memoBuf),
			"[i] zclo is running, peer '%s', window %d ms / %lld "
			"bytes, chunk %lld bytes / %lld ms, level %d, label %u.",
			ductName, cfg.windowMs, cfg.flushBytes, cfg.chunkBytes,
			cfg.chunkMs, cfg.level, cfg.label);
		writeMemo(memoBuf);
	}

	while (!(sm_SemEnded(vduct->semaphore)))
	{
		unsigned char	*bytes;
		size_t		len;

		if (bpDequeue(vduct, &bundleZco, &ancillaryData, -1) < 0)
		{
			putErrmsg("Can't dequeue bundle.", NULL);
			break;
		}

		if (bundleZco == 0)		/*	Outduct closed.	*/
		{
			writeMemo("[i] zclo outduct closed.");
			sm_SemEnd(zcloSemaphore(NULL));
			continue;
		}

		if (bundleZco == 1)	/*	Got a corrupt bundle.	*/
		{
			continue;
		}

		/*	A carrier routed back into the tunnel would be
		 *	wrapped again, and again: the route override for
		 *	the carrier label is missing.  Drop it.		*/

		if (ancillaryData.dataLabel == cfg.label)
		{
			pthread_mutex_lock(&st.mtx);
			st.loopsRefused++;
			pthread_mutex_unlock(&st.mtx);
			writeMemoNote("[?] zclo: carrier routed into its own \
outduct, dropped; add a route override for the carrier label",
					itoa(cfg.label));
			if (bpHandleXmitSuccess(bundleZco) < 0)
			{
				putErrmsg("Can't handle xmit success.", NULL);
				break;
			}

			continue;
		}

		bytes = extractBundle(sdr, bundleZco, &len);
		if (bytes == NULL || len == 0
		|| addBundle(&st, bundleZco, bytes, len) < 0)
		{
			free(bytes);
			if (bpHandleXmitFailure(bundleZco) < 0)
			{
				putErrmsg("Can't handle xmit failure.", NULL);
				break;
			}

			continue;
		}

		free(bytes);
		sm_TaskYield();
	}

	pthread_mutex_lock(&st.mtx);
	st.shutdown = 1;
	pthread_cond_signal(&st.cv);
	pthread_mutex_unlock(&st.mtx);
	pthread_join(flusher, NULL);

	{
		char	memoBuf[512];

		isprintf(memoBuf, sizeof(memoBuf),
			"[i] zclo stats: %llu bundles, %llu bytes in; %llu "
			"carriers, %llu bytes out; %llu chunks abandoned, "
			"%llu looped carriers dropped.",
			(unsigned long long) st.bundles,
			(unsigned long long) st.bytesIn,
			(unsigned long long) st.carriers,
			(unsigned long long) st.bytesOut,
			(unsigned long long) st.chunksAbandoned,
			(unsigned long long) st.loopsRefused);
		writeMemo(memoBuf);
	}

	if (st.zcos)
	{
		MRELEASE(st.zcos);
	}

	zclEncFree(&st.enc);
	pthread_mutex_destroy(&st.mtx);
	pthread_cond_destroy(&st.cv);
	ionStopAttendant(&attendant);
	writeErrmsgMemos();
	writeMemo("[i] zclo duct has ended.");
	ionDetach();
	return 0;
}
