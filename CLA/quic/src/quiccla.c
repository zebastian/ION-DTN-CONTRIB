/*
	quiccla.c:	BP QUIC convergence-layer daemon (draft-caini-dtn-quiccl).

			Accepts inbound connections and injects the bundles they
			carry into ION, and opens connections for the egress
			plans that cite quic outducts and drains those outducts,
			transmitting over the session to that node (reusing an
			existing session to the node when one exists).
									*/
#include "quicsession.h"

/*	Receive-side state: the acquisition work area and attendant into which
 *	every inbound bundle (on any connection) is injected.		*/

typedef struct
{
	AcqWorkArea *work;
	ReqAttendant attendant;
} ReceiverParms;

/*	One egress neighbour: a node reachable via a quic outduct.  A sender
 *	thread drains the outduct and transmits over the session to nodeNbr,
 *	opening one to host:port if none exists yet.			*/

typedef struct QuicNeighbor
{
	struct QuicNeighbor *next;
	uvast		     nodeNbr;
	char		     host[QUIC_MAX_HOST_LEN];
	int		     port;
	char		     outductName[MAX_CL_DUCT_NAME_LEN + 1];
	VOutduct	    *vduct;
	pthread_t	     sender;
	int		     hasSender;
} QuicNeighbor;

static QuicSession    *Engine;
static ReceiverParms   Rx;
static QuicNeighbor   *Neighbors;
static pthread_mutex_t NeighborsMutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int    Running;

static void interruptThread(int signum)
{
	(void) signum;

	isignal(SIGTERM, interruptThread);
	Running = 0;
	ionKillMainThread("quiccla");
}

/*	Inject one reassembled bundle into ION.  bpContinueAcq is given the
 *	attendant so that, when ZCO reception space is exhausted, it blocks
 *	until space frees rather than dropping the bundle; that stalls the
 *	engine's I/O thread and so backpressures the QUIC sender.  Runs on
 *	the engine I/O thread.  Returns 0 on success, -1 to fail the
 *	connection.							*/

static int acquireBundle(void *user, unsigned char *bundle, int len)
{
	ReceiverParms *rx = user;

	if (bpBeginAcq(rx->work, 0, NULL) < 0
			|| bpContinueAcq(rx->work, (char *) bundle, len,
					   &rx->attendant, 0)
					< 0
			|| bpEndAcq(rx->work) < 0)
	{
		putErrmsg("quiccla: can't acquire bundle.", NULL);
		return -1;
	}

	return 0;
}

/*	Parse the node number from an "ipn:<node>[.<service>]" EID.  Returns
 *	0 (an invalid node) when the EID is not an ipn EID.		*/

static uvast nodeNbrFromEid(const char *eid)
{
	uvast node = 0;

	if (eid != NULL && strncmp(eid, "ipn:", 4) == 0)
	{
		oK(sscanf(eid + 4, UVAST_FIELDSPEC, &node));
	}

	return node;
}

/*	Drain one quic outduct, transmitting each bundle over the session to
 *	the neighbour (opening one on demand, or reusing an accepted one).	*/

static void *senderThread(void *parm)
{
	QuicNeighbor   *nb = parm;
	Sdr		sdr = getIonsdr();
	unsigned char  *buffer;
	Object		bundleZco;
	BpAncillaryData ancillaryData;
	unsigned int	bundleLength;
	ZcoReader	reader;
	int		bytesToSend;

	buffer = MTAKE(QUICCLA_BUFSZ);
	if (buffer == NULL)
	{
		putErrmsg("No memory for QUIC buffer in quiccla.", NULL);
		ionKillMainThread("quiccla");
		return NULL;
	}

	/*	Adopt the outduct: mark it serviced by this thread and make
	 *	sure its semaphore is live so bpDequeue can be woken.		*/

	nb->vduct->hasThread = 1;
	nb->vduct->cloThread = pthread_self();
	sm_SemUnend(nb->vduct->semaphore);

	while (!(sm_SemEnded(nb->vduct->semaphore)))
	{
		if (bpDequeue(nb->vduct, &bundleZco, &ancillaryData, -1) < 0)
		{
			putErrmsg("Can't dequeue bundle.", nb->outductName);
			break;
		}

		if (bundleZco == 0) /*	Outduct closed.	*/
		{
			break;
		}

		if (bundleZco == 1) /*	Corrupt bundle.	*/
		{
			continue;
		}

		CHKNULL(sdr_begin_xn(sdr));
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
		CHKNULL(sdr_begin_xn(sdr));
		bytesToSend = zco_transmit(sdr, &reader, QUICCLA_BUFSZ,
				(char *) buffer);
		if (sdr_end_xn(sdr) < 0 || bytesToSend < 0)
		{
			putErrmsg("Can't issue from ZCO.", NULL);
			break;
		}

		if (quicEngineSendTo(Engine, nb->nodeNbr, nb->host, nb->port,
				    buffer, bytesToSend, ancillaryData.ordinal)
				< 0)
		{
			writeMemo("[?] quiccla: send failed; will retry.");
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

	nb->vduct->hasThread = 0;
	MRELEASE(buffer);
	return NULL;
}

/*	Add a sender for a quic outduct if one is not already running.	Called
 *	on the (single) rescan thread, so no lock is needed to insert; the
 *	NeighborsMutex only guards traversal from the shutdown path.	*/

static int ensureNeighbor(uvast nodeNbr, const char *outductName, VOutduct *vduct)
{
	QuicNeighbor *nb;
	char	      host[QUIC_MAX_HOST_LEN];
	int	      port = QUIC_DEFAULT_PORT;

	for (nb = Neighbors; nb != NULL; nb = nb->next)
	{
		if (strcmp(nb->outductName, outductName) == 0)
		{
			return 0; /* Already have a sender.		*/
		}
	}

	if (parseQuicDuctName(outductName, host, &port) < 0)
	{
		writeMemoNote("[?] quiccla: bad quic outduct name",
				(char *) outductName);
		return 0;
	}

	nb = MTAKE(sizeof(QuicNeighbor));
	if (nb == NULL)
	{
		putErrmsg("quiccla can't allocate neighbour.", outductName);
		return -1;
	}

	memset(nb, 0, sizeof(*nb));
	nb->nodeNbr = nodeNbr;
	istrcpy(nb->host, host, sizeof(nb->host));
	nb->port = port;
	istrcpy(nb->outductName, outductName, sizeof(nb->outductName));
	nb->vduct = vduct;

	pthread_mutex_lock(&NeighborsMutex);
	nb->next = Neighbors;
	Neighbors = nb;
	pthread_mutex_unlock(&NeighborsMutex);

	if (pthread_begin(&nb->sender, NULL, senderThread, nb))
	{
		putSysErrmsg("quiccla can't start sender thread", outductName);
		return -1;
	}

	nb->hasSender = 1;
	return 0;
}

/*	Scan egress plans for quic outducts and make sure each has a sender.	*/

static int scanPlans(void)
{
	Sdr	     sdr = getIonsdr();
	PsmPartition wm = getIonwm();
	BpVdb	    *vdb = getBpVdb();
	ClProtocol   clp;
	Object	     protocolElt;
	Object	     protocolObj;
	PsmAddress   vplanElt;
	VPlan	    *vplan;
	Object	     planObj;
	OBJ_POINTER(BpPlan, plan);
	Object ductElt;
	Object outductElt;
	OBJ_POINTER(Outduct, outduct);
	uvast	   nodeNbr;
	char	   outductName[MAX_CL_DUCT_NAME_LEN + 1];
	VOutduct  *vduct;
	PsmAddress vductElt;
	int	   result = 0;

	CHKERR(sdr_begin_xn(sdr));
	fetchProtocol("quic", &clp, &protocolElt);
	if (protocolElt == 0)
	{
		sdr_exit_xn(sdr);
		return 0; /* No quic protocol configured yet.		*/
	}

	protocolObj = sdr_list_data(sdr, protocolElt);
	for (vplanElt = sm_list_first(wm, vdb->plans); vplanElt;
			vplanElt = sm_list_next(wm, vplanElt))
	{
		vplan = (VPlan *) psp(wm, sm_list_data(wm, vplanElt));
		nodeNbr = nodeNbrFromEid(vplan->neighborEid);
		if (nodeNbr == 0)
		{
			continue; /* Not an ipn neighbour.		*/
		}

		planObj = sdr_list_data(sdr, vplan->planElt);
		GET_OBJ_POINTER(sdr, BpPlan, plan, planObj);
		for (ductElt = sdr_list_first(sdr, plan->ducts); ductElt;
				ductElt = sdr_list_next(sdr, ductElt))
		{
			outductElt = sdr_list_data(sdr, ductElt);
			GET_OBJ_POINTER(sdr, Outduct, outduct,
					sdr_list_data(sdr, outductElt));
			if (outduct->protocol != protocolObj
					|| outduct->name[0] == '#')
			{
				continue; /* Not a plannable quic duct.	*/
			}

			istrcpy(outductName, outduct->name, sizeof(outductName));
			findOutduct("quic", outductName, &vduct, &vductElt);
			if (vductElt == 0)
			{
				continue;
			}

			if (ensureNeighbor(nodeNbr, outductName, vduct) < 0)
			{
				result = -1;
				break;
			}
		}

		if (result < 0)
		{
			break;
		}
	}

	sdr_exit_xn(sdr);
	return result;
}

#if defined(ION_LWT)
int quiccla(saddr a1, saddr a2, saddr a3, saddr a4, saddr a5, saddr a6,
		saddr a7, saddr a8, saddr a9, saddr a10)
{
	char *ductName = (char *) a1;
	int   largc = 2;
	char *largv[2];

	largv[0] = "quiccla";
	largv[1] = ductName;
#else
int main(int argc, char *argv[])
{
	char  *ductName = (argc > 1 ? argv[argc - 1] : NULL);
	int    largc = argc;
	char **largv = argv;
#endif
	VInduct	     *vduct;
	PsmAddress    vductElt;
	QuicClaConfig cfg;
	char	      hostName[QUIC_MAX_HOST_LEN];
	QuicNeighbor *nb;

	if (ductName == NULL)
	{
		PUTS("Usage: quiccla -c cert -k key [-C cafile] [-n] "
		     "[-A alpn] [-t idlesec] <host[:port]>");
		return 0;
	}

	if (parseQuicArgs(largc, largv, &cfg) < 0)
	{
		putErrmsg("quiccla: invalid arguments.", NULL);
		return -1;
	}

	if (parseQuicDuctName(ductName, hostName, &cfg.port) < 0)
	{
		putErrmsg("quiccla: invalid duct name.", ductName);
		return -1;
	}

	istrcpy(cfg.host, hostName, sizeof(cfg.host));

	if (bpAttach() < 0)
	{
		putErrmsg("quiccla can't attach to BP.", NULL);
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

	/*	Set up the shared acquisition area and attendant into which
	 *	every inbound bundle is injected.			*/

	memset((char *) &Rx, 0, sizeof(Rx));
	Rx.work = bpGetAcqArea(vduct);
	if (Rx.work == NULL)
	{
		putErrmsg("quiccla can't get acquisition work area.", NULL);
		return -1;
	}

	if (ionStartAttendant(&Rx.attendant) < 0)
	{
		putErrmsg("quiccla can't initialize blocking acquisition.", NULL);
		return -1;
	}

	Engine = quicEngineStart(&cfg, acquireBundle, &Rx);
	if (Engine == NULL)
	{
		putErrmsg("quiccla: can't start QUIC engine.", NULL);
		ionStopAttendant(&Rx.attendant);
		return -1;
	}

	ionNoteMainThread("quiccla");
	isignal(SIGTERM, interruptThread);
	Running = 1;

	{
		char txt[1024];

		isprintf(txt, sizeof(txt), "[i] quiccla is running, duct '%s'.",
				ductName);
		writeMemo(txt);
	}

	/*	Discover quic outducts and keep discovering them (plans may be
	 *	added after start-up), spawning a sender per neighbour.	*/

	while (Running)
	{
		if (scanPlans() < 0)
		{
			ionKillMainThread("quiccla");
			break;
		}

		snooze(2);
	}

	/*	Shut down: stop the senders, then the engine.		*/

	Running = 0;
	pthread_mutex_lock(&NeighborsMutex);
	for (nb = Neighbors; nb != NULL; nb = nb->next)
	{
		if (nb->vduct->semaphore != SM_SEM_NONE)
		{
			sm_SemEnd(nb->vduct->semaphore);
		}
	}

	pthread_mutex_unlock(&NeighborsMutex);

	for (nb = Neighbors; nb != NULL; nb = nb->next)
	{
		if (nb->hasSender)
		{
			pthread_join(nb->sender, NULL);
			nb->hasSender = 0;
		}
	}

	ionPauseAttendant(&Rx.attendant); /* Unblock a stalled acquisition. */
	quicEngineStop(Engine);
	ionStopAttendant(&Rx.attendant);

	while (Neighbors != NULL)
	{
		nb = Neighbors;
		Neighbors = nb->next;
		MRELEASE(nb);
	}

	writeErrmsgMemos();
	writeMemo("[i] quiccla duct has ended.");
	ionDetach();
	return 0;
}
