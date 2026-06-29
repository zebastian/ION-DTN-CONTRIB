/*
	quiccli.c:	BP QUIC convergence-layer input daemon (server).
			Accepts QUIC connections and injects each
			reassembled bundle into ION.
								*/
#include "quicsession.h"

typedef struct
{
	VInduct	    *vduct;
	AcqWorkArea *work;
	QuicSession *session;
	ReqAttendant attendant;
	volatile int running;
} ReceiverThreadParms;

static void interruptThread(int signum)
{
	(void) signum;

	isignal(SIGTERM, interruptThread);
	ionKillMainThread("quiccli");
}

/*	Inject one reassembled bundle into ION.  bpContinueAcq is given the
 *	attendant so that, when ZCO reception space is exhausted, it blocks
 *	until space frees rather than dropping the bundle; that stalls the
 *	server's packet processing and so backpressures the QUIC sender.
 *	Returns 0 on success, -1 to stop the server loop.		*/

static int acquireBundle(void *user, unsigned char *bundle, int len)
{
	ReceiverThreadParms *rtp = user;

	if (bpBeginAcq(rtp->work, 0, NULL) < 0
			|| bpContinueAcq(rtp->work, (char *) bundle, len,
					   &rtp->attendant, 0)
					< 0
			|| bpEndAcq(rtp->work) < 0)
	{
		putErrmsg("quiccli: can't acquire bundle.", NULL);
		return -1;
	}

	return 0;
}

static void *receiveBundles(void *parm)
{
	ReceiverThreadParms *rtp = parm;

	snooze(1); /*	Let main thread become interruptible.	*/
	rtp->work = bpGetAcqArea(rtp->vduct);
	if (rtp->work == NULL)
	{
		putErrmsg("quiccli can't get acquisition work area.", NULL);
		ionKillMainThread("quiccli");
		return NULL;
	}

	if (quicServerRun(rtp->session, acquireBundle, rtp, &rtp->running) < 0)
	{
		writeMemo("[?] quiccli: server loop ended with error.");
		ionKillMainThread("quiccli");
	}

	writeErrmsgMemos();
	writeMemo("[i] quiccli receiver thread has ended.");
	bpReleaseAcqArea(rtp->work);
	return NULL;
}

#if defined(ION_LWT)
int quiccli(saddr a1, saddr a2, saddr a3, saddr a4, saddr a5, saddr a6,
		saddr a7, saddr a8, saddr a9, saddr a10)
{
	char *ductName = (char *) a1;
	int   largc = 2;
	char *largv[2];

	largv[0] = "quiccli";
	largv[1] = ductName;
#else
int main(int argc, char *argv[])
{
	char  *ductName = (argc > 1 ? argv[argc - 1] : NULL);
	int    largc = argc;
	char **largv = argv;
#endif
	VInduct		   *vduct;
	PsmAddress	    vductElt;
	QuicClaConfig	    cfg;
	char		    hostName[QUIC_MAX_HOST_LEN];
	ReceiverThreadParms rtp;
	pthread_t	    receiverThread;

	if (ductName == NULL)
	{
		PUTS("Usage: quiccli -c cert -k key [-C cafile] "
		     "[-A alpn] [-t idlesec] <host[:port]>");
		return 0;
	}

	if (parseQuicArgs(largc, largv, &cfg) < 0)
	{
		putErrmsg("quiccli: invalid arguments.", NULL);
		return -1;
	}

	if (parseQuicDuctName(ductName, hostName, &cfg.port) < 0)
	{
		putErrmsg("quiccli: invalid duct name.", ductName);
		return -1;
	}

	istrcpy(cfg.host, hostName, sizeof(cfg.host));

	if (bpAttach() < 0)
	{
		putErrmsg("quiccli can't attach to BP.", NULL);
		return -1;
	}

	findInduct("quic", ductName, &vduct, &vductElt);
	if (vductElt == 0)
	{
		putErrmsg("No such quic duct.", ductName);
		return -1;
	}

	if (vduct->cliPid != ERROR && vduct->cliPid != sm_TaskIdSelf())
	{
		putErrmsg("CLI task is already started for this duct.",
				itoa(vduct->cliPid));
		return -1;
	}

	memset((char *) &rtp, 0, sizeof(rtp));
	rtp.vduct = vduct;
	rtp.session = quicServerStart(&cfg);
	if (rtp.session == NULL)
	{
		putErrmsg("quiccli: can't start QUIC server.", NULL);
		return -1;
	}

	if (ionStartAttendant(&rtp.attendant) < 0)
	{
		putErrmsg("quiccli can't initialize blocking acquisition.", NULL);
		quicServerStop(rtp.session);
		return -1;
	}

	ionNoteMainThread("quiccli");
	isignal(SIGTERM, interruptThread);

	rtp.running = 1;
	if (pthread_begin(&receiverThread, NULL, receiveBundles, &rtp))
	{
		putSysErrmsg("quiccli can't create receiver thread", NULL);
		ionStopAttendant(&rtp.attendant);
		quicServerStop(rtp.session);
		return -1;
	}

	{
		char txt[1024];

		isprintf(txt, sizeof(txt), "[i] quiccli is running, duct '%s'.",
				ductName);
		writeMemo(txt);
	}

	ionPauseMainThread(-1);

	rtp.running = 0;
	ionPauseAttendant(&rtp.attendant); /* Unblock a stalled acquisition. */
	pthread_join(receiverThread, NULL);
	ionStopAttendant(&rtp.attendant);
	quicServerStop(rtp.session);

	writeErrmsgMemos();
	writeMemo("[i] quiccli duct has ended.");
	ionDetach();
	return 0;
}
