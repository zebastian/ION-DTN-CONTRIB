/*
	quicclo.c:	BP QUIC convergence-layer output daemon (client).
			Connects to a peer over QUIC and sends each
			outbound bundle on a bidirectional stream.
								*/
#include "quicsession.h"

static sm_SemId quiccloSemaphore(sm_SemId *semid)
{
	static sm_SemId semaphore = -1;

	if (semid)
	{
		semaphore = *semid;
	}

	return semaphore;
}

static void shutDownClo(int signum)
{
	(void) signum;

	sm_SemEnd(quiccloSemaphore(NULL));
}

#if defined(ION_LWT)
int quicclo(saddr a1, saddr a2, saddr a3, saddr a4, saddr a5, saddr a6,
		saddr a7, saddr a8, saddr a9, saddr a10)
{
	char *ductName = (char *) a1;
	int   largc = 2;
	char *largv[2];

	largv[0] = "quicclo";
	largv[1] = ductName;
#else
int main(int argc, char *argv[])
{
	char  *ductName = (argc > 1 ? argv[argc - 1] : NULL);
	int    largc = argc;
	char **largv = argv;
#endif
	unsigned char  *buffer;
	VOutduct       *vduct;
	PsmAddress	vductElt;
	Sdr		sdr;
	QuicClaConfig	cfg;
	char		hostName[QUIC_MAX_HOST_LEN];
	Object		bundleZco;
	BpAncillaryData ancillaryData;
	unsigned int	bundleLength;
	ZcoReader	reader;
	int		bytesToSend;
	QuicSession    *session = NULL;
	int		pause = 0;

	if (ductName == NULL)
	{
		PUTS("Usage: quicclo [-C cafile] [-c cert] [-k key] "
		     "[-A alpn] [-n] [-t idlesec] <host[:port]>");
		return 0;
	}

	if (parseQuicArgs(largc, largv, &cfg) < 0)
	{
		putErrmsg("quicclo: invalid arguments.", NULL);
		return -1;
	}

	if (parseQuicDuctName(ductName, hostName, &cfg.port) < 0)
	{
		putErrmsg("quicclo: invalid duct name.", ductName);
		return -1;
	}

	istrcpy(cfg.host, hostName, sizeof(cfg.host));

	if (bpAttach() < 0)
	{
		putErrmsg("quicclo can't attach to BP.", NULL);
		return -1;
	}

	buffer = MTAKE(QUICCLA_BUFSZ);
	if (buffer == NULL)
	{
		putErrmsg("No memory for QUIC buffer in quicclo.", NULL);
		return -1;
	}

	findOutduct("quic", ductName, &vduct, &vductElt);
	if (vductElt == 0)
	{
		putErrmsg("No such quic duct.", ductName);
		MRELEASE(buffer);
		return -1;
	}

	if (vduct->cloPid != ERROR && vduct->cloPid != sm_TaskIdSelf())
	{
		putErrmsg("CLO task is already started for this duct.",
				itoa(vduct->cloPid));
		MRELEASE(buffer);
		return -1;
	}

	sdr = getIonsdr();
	oK(quiccloSemaphore(&(vduct->semaphore)));
	isignal(SIGTERM, shutDownClo);

	{
		char memoBuf[1024];

		isprintf(memoBuf, sizeof(memoBuf),
				"[i] quicclo is running, duct '%s'.", ductName);
		writeMemo(memoBuf);
	}

	while (!(sm_SemEnded(vduct->semaphore)))
	{
		if (bpDequeue(vduct, &bundleZco, &ancillaryData, -1) < 0)
		{
			putErrmsg("Can't dequeue bundle.", NULL);
			break;
		}

		if (bundleZco == 0) /*	Outduct closed.	*/
		{
			writeMemo("[i] quicclo outduct closed.");
			sm_SemEnd(quiccloSemaphore(NULL));
			continue;
		}

		if (bundleZco == 1) /*	Corrupt bundle.	*/
		{
			continue;
		}

		CHKZERO(sdr_begin_xn(sdr));
		bundleLength = zco_length(sdr, bundleZco);
		sdr_exit_xn(sdr);

		if (bundleLength > QUICCLA_BUFSZ)
		{
			putErrmsg("Bundle too big for QUIC CLA buffer.",
					itoa(bundleLength));
			if (bpHandleXmitFailure(bundleZco) < 0)
			{
				break;
			}

			continue;
		}

		zco_start_transmitting(bundleZco, &reader);
		zco_track_file_offset(&reader);
		CHKZERO(sdr_begin_xn(sdr));
		bytesToSend = zco_transmit(sdr, &reader, QUICCLA_BUFSZ,
				(char *) buffer);
		if (sdr_end_xn(sdr) < 0 || bytesToSend < 0)
		{
			putErrmsg("Can't issue from ZCO.", NULL);
			break;
		}

		if (session == NULL)
		{
			session = quicClientStart(&cfg);
			if (session == NULL)
			{
				writeMemo("[?] quicclo: connect failed; will "
					  "retry.");
				if (bpHandleXmitFailure(bundleZco) < 0)
				{
					break;
				}

				pause = (pause == 0) ? 1 : pause << 1;
				if (pause > 30)
				{
					pause = 30;
				}

				snooze(pause);
				continue;
			}

			pause = 0;
		}

		if (quicClientSend(session, buffer, bytesToSend,
				    ancillaryData.ordinal)
				< 0)
		{
			writeMemo("[?] quicclo: send failed; reconnecting.");
			quicClientStop(session);
			session = NULL;
			if (bpHandleXmitFailure(bundleZco) < 0)
			{
				break;
			}

			continue;
		}

		if (bpHandleXmitSuccess(bundleZco) < 0)
		{
			putErrmsg("Can't handle xmit success.", NULL);
			break;
		}

		sm_TaskYield();
	}

	if (session)
	{
		quicClientStop(session);
	}

	writeErrmsgMemos();
	writeMemo("[i] quicclo duct has ended.");
	MRELEASE(buffer);
	ionDetach();
	return 0;
}
