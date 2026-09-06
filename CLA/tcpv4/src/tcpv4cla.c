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
 *	nodeId, opening one to the outduct's host:port if none exists.
 *
 *	The neighbour is named by the plan's neighbour EID rather than by a
 *	node number, so a peer named in any EID scheme is reachable: it is
 *	that EID which the peer's own SESS_INIT node ID is matched against
 *	(RFC 9174 4.6) and which its certificate has to authenticate
 *	(4.4.4.3), and neither of those is an ipn-only question.		*/

typedef struct Tcpv4Neighbor
{
	struct Tcpv4Neighbor *next;
	char		      nodeId[MAX_EID_LEN];
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

/*	The engine reads a bundle's octets through these, so that it needs
 *	to know nothing of ZCOs or of BP.  A bundle is streamed out a
 *	bufferful at a time rather than copied whole into memory, which
 *	keeps each SDR transaction short - the SDR lock is held against
 *	every other ION task for its duration - and takes the ceiling off
 *	how large a bundle this CLA can send.				*/

typedef struct
{
	Object	  bundle;
	ZcoReader reader;
} Tcpv4TxCursor;

static int txOpen(void *user, Object bundle, void **cursor)
{
	Tcpv4TxCursor *c;

	(void) user;

	c = MTAKE(sizeof(Tcpv4TxCursor));
	if (c == NULL)
	{
		putErrmsg("tcpv4cla: no memory for a transmission cursor.",
				NULL);
		return -1;
	}

	c->bundle = bundle;
	zco_start_transmitting(bundle, &c->reader);
	zco_track_file_offset(&c->reader);
	*cursor = c;
	return 0;
}

static int txRead(void *user, void *cursor, char *into, int len)
{
	Sdr	       sdr = getIonsdr();
	Tcpv4TxCursor *c = cursor;
	int	       got;

	(void) user;

	CHKERR(sdr_begin_xn(sdr));
	got = zco_transmit(sdr, &c->reader, len, into);
	if (sdr_end_xn(sdr) < 0)
	{
		putErrmsg("tcpv4cla: can't issue from ZCO.", NULL);
		return -1;
	}

	return got;
}

static void txClose(void *user, void *cursor)
{
	(void) user;

	MRELEASE(cursor);
}

/*	Report one transfer's outcome to BP.  This runs on whichever engine
 *	thread established it - the receiver thread when an XFER_ACK
 *	completes the transfer, the clock thread when a failed session is
 *	reaped - and every bundle handed to the engine reaches it once.	*/

static void txDone(void *user, Object bundle, int succeeded)
{
	(void) user;

	if (succeeded)
	{
		if (bpHandleXmitSuccess(bundle) < 0)
		{
			putErrmsg("tcpv4cla can't handle xmit success.", NULL);
			ionKillMainThread("tcpv4cla");
		}

		return;
	}

	if (bpHandleXmitFailure(bundle) < 0)
	{
		putErrmsg("tcpv4cla can't handle xmit failure.", NULL);
		ionKillMainThread("tcpv4cla");
	}
}

/*	Drain one tcpv4 outduct, handing each bundle to the session to the
 *	neighbour (opening one on demand, or reusing an accepted one).
 *	The hand-off does not wait for the bundle to be written, let alone
 *	acknowledged, so this thread goes straight back to the outduct and
 *	several transfers are in flight at once.			*/

static void *senderThread(void *parm)
{
	Tcpv4Neighbor  *nb = parm;
	Sdr		sdr = getIonsdr();
	Object		bundleZco;
	BpAncillaryData ancillaryData;
	vast		bundleLength;
	int		refusals = 0;

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

		/*	From here the engine owns the bundle and reports its
		 *	outcome through txDone - unless it declines it, in
		 *	which case it is still ours to requeue.		*/

		if (tcpv4EngineSendTo(Engine, nb->nodeId, nb->outductName,
				    bundleZco, bundleLength)
				== 0)
		{
			refusals = 0;
			continue;
		}

		/*	No session took the bundle, so it goes back to BP to
		 *	be offered again.  BP offers it again at once, and
		 *	the reason the engine declined is usually one that
		 *	has not gone away a microsecond later - a
		 *	reconnection backoff that has seconds to run, a peer
		 *	that is down, a bundle larger than the peer's
		 *	Transfer MRU, which will be refused for as long as
		 *	the bundle lives.  Without a pause here the two of
		 *	us spin: dequeue, decline, requeue, dequeue.  So
		 *	wait, a little longer for each successive refusal,
		 *	and say so once rather than once per turn round the
		 *	loop.							*/

		if (refusals == 0)
		{
			writeMemoNote("[?] tcpv4cla: no session took the"
				      " bundle, will retry;",
					nb->outductName);
		}

		if (bpHandleXmitFailure(bundleZco) < 0)
		{
			break;
		}

		refusals++;
		snooze(refusals < TCPV4_RETRY_MAX_SEC ? refusals
						      : TCPV4_RETRY_MAX_SEC);
	}

	nb->vduct->hasThread = 0;
	return NULL;
}

/*	Add a sender for a tcpv4 outduct if one is not already running.
 *	Called on the (single) rescan thread, so no lock is needed to
 *	insert; the NeighborsMutex only guards traversal from the shutdown
 *	path.								*/

static int ensureNeighbor(const char *nodeId, const char *outductName,
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
	istrcpy(nb->nodeId, nodeId, sizeof(nb->nodeId));
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
		if (!tcpv4NodeIdIsSet(vplan->neighborEid))
		{
			continue; /* A plan with no neighbour to name.	*/
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

			if (ensureNeighbor(vplan->neighborEid, outductName,
					    vduct)
					< 0)
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
	Tcpv4Transmitter tx;
	char	       hostName[TCPV4_MAX_HOST_LEN];
	Tcpv4Neighbor *nb;

	if (ductName == NULL)
	{
		PUTS("Usage: tcpv4cla -c cert -k key [-C cafile] "
		     "[-R crlfile] [-n] "
		     "[-T require|prefer|none] [-E require|prefer|none] "
		     "[-B require|prefer|none] "
		     "[-K keepalive] [-t idlesec] [-S segmentmru] "
		     "[-M transfermru] [-r rcvbuf] [-w sndbuf] "
		     "[-L maxsessions] [-W count[:bytes]] "
		     "[-P tlspriority] <host[:port]>");
		PUTS("  -r/-w set SO_RCVBUF/SO_SNDBUF; leaving them at 0 "
		     "keeps the kernel's socket buffer autotuning, which "
		     "is usually the better choice.");
		PUTS("  -W bounds the transfers awaiting acknowledgment on "
		     "one session, by count and by octets (default "
		     "100:4194304); a link with a long round-trip time "
		     "carries about one window per round trip.");
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

	tx.open = txOpen;
	tx.read = txRead;
	tx.close = txClose;
	tx.done = txDone;
	tx.user = NULL;

	Engine = tcpv4EngineStart(&cfg, &rx, &tx);
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
