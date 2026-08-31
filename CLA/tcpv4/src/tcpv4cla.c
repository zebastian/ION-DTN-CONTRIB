/*
	tcpv4cla.c:	BP TCPCLv4 convergence-layer daemon (RFC 9174).

			Accepts inbound TCPCL sessions and injects the bundles
			they carry into ION, and opens sessions for the egress
			plans that cite tcpv4 outducts and drains those
			outducts, transmitting over the session to that node
			(reusing an existing session to the node when one
			exists).
									*/
#include "tcpv4session.h"

/*	Per-session receive state.  Every session's receiver thread gets its
 *	own acquisition work area and attendant, so that one session
 *	stalling on ZCO space cannot corrupt another's acquisition.	*/

typedef struct Tcpv4Rx
{
	struct Tcpv4Rx *next;
	AcqWorkArea    *work;
	ReqAttendant	attendant;
	int		hasAttendant;
} Tcpv4Rx;

/*	One egress neighbour: a node reachable via a tcpv4 outduct.  A
 *	sender thread drains the outduct and transmits over the session to
 *	nodeNbr, opening one to the outduct's host:port if none exists.	*/

typedef struct Tcpv4Neighbor
{
	struct Tcpv4Neighbor *next;
	uvast		      nodeNbr;
	char		      outductName[MAX_CL_DUCT_NAME_LEN + 1];
	VOutduct	     *vduct;
	pthread_t	      sender;
	int		      hasSender;
} Tcpv4Neighbor;

static Tcpv4Engine     *Engine;
static VInduct	       *RxInduct;
static Tcpv4Rx	       *Receivers;
static pthread_mutex_t	ReceiversMutex = PTHREAD_MUTEX_INITIALIZER;
static Tcpv4Neighbor   *Neighbors;
static pthread_mutex_t	NeighborsMutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int	Running;

static void interruptThread(int signum)
{
	(void) signum;

	isignal(SIGTERM, interruptThread);
	Running = 0;
	ionKillMainThread("tcpv4cla");
}

/*	*	*	Reception	*	*	*	*	*/

static void *rxOpen(void *user)
{
	Tcpv4Rx *rx = MTAKE(sizeof(Tcpv4Rx));

	(void) user;

	if (rx == NULL)
	{
		putErrmsg("tcpv4cla: no memory for reception context.", NULL);
		return NULL;
	}

	memset(rx, 0, sizeof(*rx));
	rx->work = bpGetAcqArea(RxInduct);
	if (rx->work == NULL)
	{
		putErrmsg("tcpv4cla can't get acquisition work area.", NULL);
		MRELEASE(rx);
		return NULL;
	}

	if (ionStartAttendant(&rx->attendant) < 0)
	{
		putErrmsg("tcpv4cla can't initialize blocking acquisition.",
				NULL);
		bpReleaseAcqArea(rx->work);
		MRELEASE(rx);
		return NULL;
	}

	rx->hasAttendant = 1;
	pthread_mutex_lock(&ReceiversMutex);
	rx->next = Receivers;
	Receivers = rx;
	pthread_mutex_unlock(&ReceiversMutex);
	return rx;
}

/*	Inject one received bundle into ION.  bpContinueAcq is given the
 *	attendant so that, when ZCO reception space is exhausted, it blocks
 *	until space frees rather than dropping the bundle; that stalls this
 *	session's receiver thread and so backpressures the peer.  Returns 0
 *	on success, -1 to fail the session.				*/

static int rxDeliver(void *parm, unsigned char *bundle, int len)
{
	Tcpv4Rx *rx = parm;

	if (bpBeginAcq(rx->work, 0, NULL) < 0
			|| bpContinueAcq(rx->work, (char *) bundle, len,
					   &rx->attendant, 0)
					< 0
			|| bpEndAcq(rx->work) < 0)
	{
		putErrmsg("tcpv4cla: can't acquire bundle.", NULL);
		return -1;
	}

	return 0;
}

static void rxClose(void *parm)
{
	Tcpv4Rx	 *rx = parm;
	Tcpv4Rx **pp;

	pthread_mutex_lock(&ReceiversMutex);
	for (pp = &Receivers; *pp != NULL; pp = &(*pp)->next)
	{
		if (*pp == rx)
		{
			*pp = rx->next;
			break;
		}
	}

	pthread_mutex_unlock(&ReceiversMutex);

	if (rx->hasAttendant)
	{
		ionStopAttendant(&rx->attendant);
	}

	bpReleaseAcqArea(rx->work);
	MRELEASE(rx);
}

/*	Unblock every acquisition that is waiting for ZCO space, so that
 *	the receiver threads can notice the shutdown.			*/

static void pauseReceivers(void)
{
	Tcpv4Rx *rx;

	pthread_mutex_lock(&ReceiversMutex);
	for (rx = Receivers; rx != NULL; rx = rx->next)
	{
		if (rx->hasAttendant)
		{
			ionPauseAttendant(&rx->attendant);
		}
	}

	pthread_mutex_unlock(&ReceiversMutex);
}

/*	ION acquires a bundle into the SDR heap only while it fits
 *	maxAcqInHeap - bpadmin's "m heapmax" - and writes it to a file
 *	otherwise, one open/write/close/unlink per bundle.  That costs far
 *	more than this convergence layer does, and the default is 560
 *	bytes, so a node that has not raised it spools very nearly every
 *	bundle through the file system.  The cliff is silent, so say so.	*/

static void checkAcqHeapMax(int transferMru)
{
	Sdr sdr = getIonsdr();
	OBJ_POINTER(BpDB, bpdb);
	unsigned int maxAcqInHeap;
	char	     txt[512];

	CHKVOID(sdr_begin_xn(sdr));
	GET_OBJ_POINTER(sdr, BpDB, bpdb, getBpDbObject());
	maxAcqInHeap = bpdb->maxAcqInHeap;
	sdr_exit_xn(sdr);

	if (maxAcqInHeap >= (unsigned int) transferMru)
	{
		return;
	}

	isprintf(txt, sizeof(txt),
			"[?] tcpv4cla: ION acquires at most %u bytes into the"
			" heap, below this induct's Transfer MRU of %d;"
			" every larger bundle is spooled through a file on"
			" reception.  Consider 'm heapmax %d' in bpadmin.",
			maxAcqInHeap, transferMru, transferMru);
	writeMemo(txt);
}

/*	*	*	Transmission	*	*	*	*	*/

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

/*	Drain one tcpv4 outduct, transmitting each bundle over the session
 *	to the neighbour (opening one on demand, or reusing an accepted
 *	one).								*/

static void *senderThread(void *parm)
{
	Tcpv4Neighbor  *nb = parm;
	Sdr		sdr = getIonsdr();
	unsigned char  *buffer;
	Object		bundleZco;
	BpAncillaryData ancillaryData;
	unsigned int	bundleLength;
	ZcoReader	reader;
	int		bytesToSend;

	buffer = MTAKE(TCPV4CLA_BUFSZ);
	if (buffer == NULL)
	{
		putErrmsg("No memory for TCP buffer in tcpv4cla.", NULL);
		ionKillMainThread("tcpv4cla");
		return NULL;
	}

	/*	Adopt the outduct: mark it serviced by this thread and make
	 *	sure its semaphore is live so bpDequeue can be woken.	*/

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

		if (bundleZco == 0) /*	Outduct closed.			*/
		{
			break;
		}

		if (bundleZco == 1) /*	Corrupt bundle.			*/
		{
			continue;
		}

		CHKNULL(sdr_begin_xn(sdr));
		bundleLength = zco_length(sdr, bundleZco);
		sdr_exit_xn(sdr);

		if (bundleLength > TCPV4CLA_BUFSZ)
		{
			putErrmsg("Bundle too big for TCPCLv4 CLA buffer.",
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
		bytesToSend = zco_transmit(sdr, &reader, TCPV4CLA_BUFSZ,
				(char *) buffer);
		if (sdr_end_xn(sdr) < 0 || bytesToSend < 0)
		{
			putErrmsg("Can't issue from ZCO.", NULL);
			break;
		}

		if (tcpv4EngineSendTo(Engine, nb->nodeNbr, nb->outductName,
				    buffer, bytesToSend)
				< 0)
		{
			writeMemo("[?] tcpv4cla: transfer failed; will retry.");
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

/*	Add a sender for a tcpv4 outduct if one is not already running.
 *	Called on the (single) rescan thread, so no lock is needed to
 *	insert; the NeighborsMutex only guards traversal from the shutdown
 *	path.								*/

static int ensureNeighbor(uvast nodeNbr, const char *outductName,
		VOutduct *vduct)
{
	Tcpv4Neighbor *nb;
	char	       host[TCPV4_MAX_HOST_LEN];
	int	       port = TCPV4_DEFAULT_PORT;

	for (nb = Neighbors; nb != NULL; nb = nb->next)
	{
		if (strcmp(nb->outductName, outductName) == 0)
		{
			return 0; /* Already have a sender.		*/
		}
	}

	if (parseTcpv4DuctName(outductName, host, &port) < 0)
	{
		writeMemoNote("[?] tcpv4cla: bad tcpv4 outduct name",
				(char *) outductName);
		return 0;
	}

	nb = MTAKE(sizeof(Tcpv4Neighbor));
	if (nb == NULL)
	{
		putErrmsg("tcpv4cla can't allocate neighbour.", outductName);
		return -1;
	}

	memset(nb, 0, sizeof(*nb));
	nb->nodeNbr = nodeNbr;
	istrcpy(nb->outductName, outductName, sizeof(nb->outductName));
	nb->vduct = vduct;

	pthread_mutex_lock(&NeighborsMutex);
	nb->next = Neighbors;
	Neighbors = nb;
	pthread_mutex_unlock(&NeighborsMutex);

	if (pthread_begin(&nb->sender, NULL, senderThread, nb))
	{
		putSysErrmsg("tcpv4cla can't start sender thread", outductName);
		return -1;
	}

	nb->hasSender = 1;
	return 0;
}

/*	Scan egress plans for tcpv4 outducts and make sure each has a
 *	sender.								*/

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
	fetchProtocol("tcpv4", &clp, &protocolElt);
	if (protocolElt == 0)
	{
		sdr_exit_xn(sdr);
		return 0; /* No tcpv4 protocol configured yet.		*/
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
				continue; /* Not a plannable tcpv4 duct.	*/
			}

			istrcpy(outductName, outduct->name,
					sizeof(outductName));
			findOutduct("tcpv4", outductName, &vduct, &vductElt);
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
int tcpv4cla(saddr a1, saddr a2, saddr a3, saddr a4, saddr a5, saddr a6,
		saddr a7, saddr a8, saddr a9, saddr a10)
{
	char *ductName = (char *) a1;
	int   largc = 2;
	char *largv[2];

	largv[0] = "tcpv4cla";
	largv[1] = ductName;
#else
int main(int argc, char *argv[])
{
	char  *ductName = (argc > 1 ? argv[argc - 1] : NULL);
	int    largc = argc;
	char **largv = argv;
#endif
	VInduct	      *vduct;
	PsmAddress     vductElt;
	Tcpv4ClaConfig cfg;
	Tcpv4Receiver  rx;
	char	       hostName[TCPV4_MAX_HOST_LEN];
	Tcpv4Neighbor *nb;

	if (ductName == NULL)
	{
		PUTS("Usage: tcpv4cla -c cert -k key [-C cafile] [-n] "
		     "[-T require|prefer|none] [-E require|prefer|none] "
		     "[-K keepalive] [-t idlesec] [-S segmentmru] "
		     "[-M transfermru] [-r rcvbuf] [-w sndbuf] "
		     "<host[:port]>");
		PUTS("  -r/-w set SO_RCVBUF/SO_SNDBUF; leaving them at 0 "
		     "keeps the kernel's socket buffer autotuning, which "
		     "is usually the better choice.");
		return 0;
	}

	if (parseTcpv4Args(largc, largv, &cfg) < 0)
	{
		putErrmsg("tcpv4cla: invalid arguments.", NULL);
		return -1;
	}

	if (parseTcpv4DuctName(ductName, hostName, &cfg.port) < 0)
	{
		putErrmsg("tcpv4cla: invalid duct name.", ductName);
		return -1;
	}

	istrcpy(cfg.host, hostName, sizeof(cfg.host));

	if (bpAttach() < 0)
	{
		putErrmsg("tcpv4cla can't attach to BP.", NULL);
		return -1;
	}

	findInduct("tcpv4", ductName, &vduct, &vductElt);
	if (vductElt == 0)
	{
		putErrmsg("No such tcpv4 duct.", ductName);
		return -1;
	}

	if (vduct->cliPid != ERROR && vduct->cliPid != sm_TaskIdSelf())
	{
		putErrmsg("CLI task is already started for this duct.",
				itoa(vduct->cliPid));
		return -1;
	}

	checkAcqHeapMax(cfg.transferMru);

	RxInduct = vduct;
	rx.open = rxOpen;
	rx.deliver = rxDeliver;
	rx.close = rxClose;
	rx.user = vduct;

	Engine = tcpv4EngineStart(&cfg, &rx);
	if (Engine == NULL)
	{
		putErrmsg("tcpv4cla: can't start TCPCLv4 engine.", NULL);
		return -1;
	}

	ionNoteMainThread("tcpv4cla");
	isignal(SIGTERM, interruptThread);
	isignal(SIGPIPE, itcp_handleConnectionLoss);
	Running = 1;

	{
		char txt[1024];

		isprintf(txt, sizeof(txt),
				"[i] tcpv4cla is running, duct '%s'.",
				ductName);
		writeMemo(txt);
	}

	/*	Discover tcpv4 outducts and keep discovering them (plans may
	 *	be added after start-up), spawning a sender per neighbour.	*/

	while (Running)
	{
		if (scanPlans() < 0)
		{
			ionKillMainThread("tcpv4cla");
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

	pauseReceivers(); /* Unblock any stalled acquisition.		*/
	tcpv4EngineStop(Engine);

	while (Neighbors != NULL)
	{
		nb = Neighbors;
		Neighbors = nb->next;
		MRELEASE(nb);
	}

	writeErrmsgMemos();
	writeMemo("[i] tcpv4cla duct has ended.");
	ionDetach();
	return 0;
}
