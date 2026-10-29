/*	zcli.c:	zcl convergence-layer input daemon.  Receives the carrier
		bundles sent to the endpoint that names its induct,
		decompresses them and hands the bundles inside to ION as
		if received from a neighbor (see doc/design.md).	*/

#include "zclcla.h"

static BpSAP	sap = NULL;

/*	Set from signal handlers, read by the main loop.		*/

#define ZCLI_GET(field)		__atomic_load_n(&(field), __ATOMIC_RELAXED)
#define ZCLI_SET(field, v)	__atomic_store_n(&(field), (v), \
				__ATOMIC_RELAXED)

static int	running = 1;
static int	statsWanted = 0;

static void	handleQuit(int signum)
{
	(void) signum;

	ZCLI_SET(running, 0);
	if (sap)
	{
		bp_interrupt(sap);
	}
}

static void	handleStats(int signum)
{
	(void) signum;

	ZCLI_SET(statsWanted, 1);
	if (sap)
	{
		bp_interrupt(sap);
	}
}

static int	parseCliArgs(int argc, char *argv[], ZclRxLimits *lim)
{
	long long	v;
	int		i;

	zclRxDefaults(lim);

	/*	argv[argc - 1] is the duct name appended by ION.	*/
	for (i = 1; i < argc - 1; i++)
	{
		const char	*opt = argv[i];
		const char	*arg = (i + 1 < argc - 1) ? argv[i + 1] : NULL;

		v = zclParseCount(arg);
		if (arg == NULL || v < 0)
		{
			putErrmsg("zcli: unknown argument or bad value.", opt);
			return -1;
		}

		if (strcmp(opt, "-r") == 0 && v <= 86400000)
		{
			lim->reorderMs = (unsigned int) v;
		}
		else if (strcmp(opt, "-B") == 0 && v >= 1 && v <= 0xffffffffLL)
		{
			lim->maxBundle = (size_t) v;
		}
		else if (strcmp(opt, "-X") == 0 && v >= 1)
		{
			lim->maxChunkOut = (uint64_t) v;
		}
		else if (strcmp(opt, "-W") == 0 && v >= 10 && v <= 31)
		{
			lim->windowLogMax = (int) v;
		}
		else if (strcmp(opt, "-S") == 0 && v >= 1 && v <= 4096)
		{
			lim->maxStreams = (unsigned int) v;
		}
		else
		{
			putErrmsg("zcli: unknown argument or bad value.", opt);
			return -1;
		}

		i++;
	}

	return 0;
}

static int	injectBundle(void *ctx, const unsigned char *bundle, size_t len)
{
	AcqWorkArea	*work = (AcqWorkArea *) ctx;

	if (bpBeginAcq(work, 0, NULL) < 0
	|| bpContinueAcq(work, (char *) bundle, len, 0, 0) < 0
	|| bpEndAcq(work) < 0)
	{
		putErrmsg("zcli can't acquire bundle.", NULL);
		return -1;
	}

	return 0;
}

static void	logStats(ZclRx *rx)
{
	ZclRxStats	s;
	char		memoBuf[512];

	zclRxGetStats(rx, &s);
	isprintf(memoBuf, sizeof(memoBuf),
		"[i] zcli stats: %llu carriers (%llu bad, %llu stale, %llu "
		"dropped), %llu bytes in; %llu bundles, %llu bytes out, "
		"%llu not acquired; chunks %llu done, %llu lost, %llu "
		"corrupt; %llu streams evicted.",
		(unsigned long long) s.carriersIn,
		(unsigned long long) s.carriersBad,
		(unsigned long long) s.carriersStale,
		(unsigned long long) s.carriersDropped,
		(unsigned long long) s.bytesIn,
		(unsigned long long) s.bundlesOut,
		(unsigned long long) s.bytesOut,
		(unsigned long long) s.emitFailed,
		(unsigned long long) s.chunksDone,
		(unsigned long long) s.chunksLost,
		(unsigned long long) s.chunksCorrupt,
		(unsigned long long) s.streamsEvicted);
	writeMemo(memoBuf);
}

/*	Reads one carrier out of a delivery; -1 on a database error, 0
 *	with *len 0 if the payload is too large to be a carrier.	*/
static int	readCarrier(Sdr sdr, BpDelivery *dlv, unsigned char **buf,
			size_t *cap, size_t *len)
{
	ZcoReader	reader;
	vast		length;
	int		got;

	*len = 0;
	CHKERR(sdr_begin_xn(sdr));
	length = zco_source_data_length(sdr, dlv->adu);
	if (length < 0 || length > ZCL_HDR_LEN + ZCL_MAX_CARRIER)
	{
		sdr_exit_xn(sdr);
		return 0;
	}

	if ((size_t) length > *cap)
	{
		unsigned char	*grown = realloc(*buf, (size_t) length);

		if (grown == NULL)
		{
			sdr_exit_xn(sdr);
			putErrmsg("No memory for carrier in zcli.",
					itoa((int) length));
			return 0;
		}

		*buf = grown;
		*cap = (size_t) length;
	}

	zco_start_receiving(dlv->adu, &reader);
	got = zco_receive_source(sdr, &reader, length, (char *) *buf);
	if (sdr_end_xn(sdr) < 0 || got != (int) length)
	{
		putErrmsg("zcli can't read carrier.", NULL);
		return -1;
	}

	*len = (size_t) length;
	return 0;
}

/*	*	*	Main thread	*	*	*	*	*/

#if defined (ION_LWT)
int	zcli(saddr a1, saddr a2, saddr a3, saddr a4, saddr a5,
		saddr a6, saddr a7, saddr a8, saddr a9, saddr a10)
{
	char	*ductName = (char *) a1;
	int	largc = 2;
	char	*largv[2];

	largv[0] = "zcli";
	largv[1] = ductName;
#else
int	main(int argc, char *argv[])
{
	char	*ductName = (argc > 1 ? argv[argc - 1] : NULL);
	int	largc = argc;
	char	**largv = argv;
#endif
	VInduct		*vduct;
	PsmAddress	vductElt;
	Sdr		sdr;
	ZclRxLimits	lim;
	ZclRx		*rx;
	AcqWorkArea	*work;
	BpDelivery	dlv;
	unsigned char	*buf = NULL;
	size_t		cap = 0;
	size_t		len;
	int		exitCode = 0;

	if (ductName == NULL || ductName[0] == '-')
	{
		PUTS("Usage: zcli [-r reorder_ms] [-B max_bundle] "
			"[-X max_chunk_bytes] [-W window_log_max] "
			"[-S max_streams] <own EID>");
		return 0;
	}

	if (parseCliArgs(largc, largv, &lim) < 0)
	{
		putErrmsg("zcli: invalid arguments.", NULL);
		return -1;
	}

	if (bpAttach() < 0)
	{
		putErrmsg("zcli can't attach to BP.", NULL);
		return -1;
	}

	findInduct(ZCL_PROTOCOL, ductName, &vduct, &vductElt);
	if (vductElt == 0)
	{
		putErrmsg("No such zcl duct.", ductName);
		return -1;
	}

	if (vduct->cliPid != ERROR && vduct->cliPid != sm_TaskIdSelf())
	{
		putErrmsg("CLI task is already started for this duct.",
				itoa(vduct->cliPid));
		return -1;
	}

	work = bpGetAcqArea(vduct);
	if (work == NULL)
	{
		putErrmsg("zcli can't get acquisition work area.", NULL);
		return -1;
	}

	rx = zclRxNew(&lim, injectBundle, work);
	if (rx == NULL)
	{
		putErrmsg("zcli can't create receiver.", NULL);
		bpReleaseAcqArea(work);
		return -1;
	}

	if (bp_open(ductName, &sap) < 0)
	{
		putErrmsg("zcli can't open its endpoint.", ductName);
		zclRxFree(rx);
		bpReleaseAcqArea(work);
		return -1;
	}

	sdr = getIonsdr();
	isignal(SIGTERM, handleQuit);
	isignal(SIGINT, handleQuit);
	isignal(SIGUSR1, handleStats);

	{
		char	memoBuf[512];

		isprintf(memoBuf, sizeof(memoBuf),
			"[i] zcli is running, endpoint '%s', reorder %u ms, "
			"max bundle %lu bytes.", ductName, lim.reorderMs,
			(unsigned long) lim.maxBundle);
		writeMemo(memoBuf);
	}

	while (ZCLI_GET(running))
	{
		/*	Wake up each second to apply the reorder timeout.	*/

		if (bp_receive(sap, &dlv, 1) < 0)
		{
			putErrmsg("zcli bundle reception failed.", NULL);
			exitCode = 1;
			break;
		}

		if (ZCLI_GET(statsWanted))
		{
			ZCLI_SET(statsWanted, 0);
			logStats(rx);
		}

		if (dlv.result == BpEndpointStopped)
		{
			bp_release_delivery(&dlv, 1);
			break;
		}

		if (dlv.result == BpPayloadPresent && dlv.adu != 0)
		{
			if (readCarrier(sdr, &dlv, &buf, &cap, &len) < 0)
			{
				bp_release_delivery(&dlv, 1);
				exitCode = 1;
				break;
			}

			bp_release_delivery(&dlv, 1);
			if (len > 0)
			{
				oK(zclRxCarrier(rx, buf, len, zclNowMs()));
			}

			continue;
		}

		bp_release_delivery(&dlv, 1);
		zclRxTick(rx, zclNowMs());
	}

	logStats(rx);
	bp_close(sap);
	sap = NULL;
	zclRxFree(rx);
	free(buf);
	bpReleaseAcqArea(work);
	writeErrmsgMemos();
	writeMemo("[i] zcli duct has ended.");
	ionDetach();
	return exitCode;
}
