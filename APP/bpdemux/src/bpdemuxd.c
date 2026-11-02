/*	bpdemuxd.c:	demux daemon.  Owns one local ipn endpoint and moves
			every bundle delivered to it on to the local
			endpoint its data label names - the same bundle,
			not a copy, so its source, ID, lifetime and
			status reports are those the sender gave it
			(see doc/design.md).				*/

#include "bpdemux.h"

/*	Exported by libbp (libbpP.c) in 4.1.4 and 4.2.x, but declared
 *	in no header.							*/
extern void	bpEndpointTally(VEndpoint *vpoint, unsigned int idx,
			unsigned int size);

/*	Bundles moved per SDR transaction.				*/
#define	BATCH		64

static BpSAP	sap = NULL;

/*	Set from signal handlers, read by the main loop.		*/

#define DMX_GET(field)		__atomic_load_n(&(field), __ATOMIC_RELAXED)
#define DMX_SET(field, v)	__atomic_store_n(&(field), (v), \
				__ATOMIC_RELAXED)

static int	running = 1;
static int	statsWanted = 0;

typedef struct
{
	unsigned long long	byRule;		/*	moved by a rule	*/
	unsigned long long	byDefault;	/*	to the default	*/
	unsigned long long	abandoned;	/*	nowhere to go	*/
	unsigned long long	bytes;		/*	payload moved	*/
} DmxCounters;

static DmxCounters	counters;
static DmxRule		rules[DMX_MAX_RULES];

static void	handleQuit(int signum)
{
	(void) signum;

	DMX_SET(running, 0);
	if (sap)
	{
		bp_interrupt(sap);
	}
}

static void	handleStats(int signum)
{
	(void) signum;

	DMX_SET(statsWanted, 1);
	if (sap)
	{
		bp_interrupt(sap);
	}
}

static void	logStats(const char *ownEid)
{
	char	memoBuf[256];

	isprintf(memoBuf, sizeof memoBuf, "[i] bpdemuxd %s: %llu bundles "
			"moved by rule, %llu to the default, %llu abandoned; "
			"%llu payload bytes moved.", ownEid, counters.byRule,
			counters.byDefault, counters.abandoned, counters.bytes);
	writeMemo(memoBuf);
}

/*	Reads the database and its rules; in a transaction.  -1 if it
 *	is missing or not this endpoint's.				*/
static int	loadDb(Sdr sdr, uvast ownNode, uvast ownSvc, DmxDb *db,
			int *count)
{
	Object	dbObj;
	Object	elt;
	int	type;
	int	n = 0;

	dbObj = sdr_find(sdr, BPDEMUX_DB_NAME, &type);
	if (dbObj == 0)
	{
		putErrmsg("bpdemuxd: no rules database; run bpdemuxadmin \
with '1 <own EID>' first.", NULL);
		return -1;
	}

	sdr_read(sdr, (char *) db, dbObj, sizeof(DmxDb));
	if (db->version != BPDEMUX_DB_VERSION)
	{
		putErrmsg("bpdemuxd: rules database has an unknown version.",
				itoa(db->version));
		return -1;
	}

	if (db->ownNode != ownNode || db->ownSvc != ownSvc)
	{
		putErrmsg("bpdemuxd: rules database is for another endpoint.",
				NULL);
		return -1;
	}

	for (elt = sdr_list_first(sdr, db->rules); elt && n < DMX_MAX_RULES;
			elt = sdr_list_next(sdr, elt))
	{
		sdr_read(sdr, (char *) &rules[n], sdr_list_data(sdr, elt),
				sizeof(DmxRule));
		rules[n].name[DMX_NAME_LEN] = '\0';
		n++;
	}

	*count = n;
	return 0;
}

/*	The local endpoint ipn:<the bundle's node>.<svc>, or NULL.	*/
static VEndpoint	*findTarget(Bundle *bundle, uint64_t svc)
{
	EndpointId	eid = bundle->destination;
	VScheme		*vscheme;
	VEndpoint	*vpoint = NULL;

	if (svc == 0 || !dmxServiceFits(svc))
	{
		return NULL;
	}

	eid.ssp.ipn.serviceNbr = (unsigned long) svc;
	lookUpEidScheme(&eid, &vscheme);
	if (vscheme == NULL)
	{
		return NULL;
	}

	lookUpEndpoint(&eid, vscheme, &vpoint);
	return vpoint;
}

/*	Puts the bundle into the target endpoint's delivery queue, as
 *	ION's own enqueueForDelivery() does (libbpP.c; static there
 *	since 4.2.0): the endpoint's reanimation script and discard
 *	rule apply if no application has it open.  The bundle is
 *	complete - ION reassembled any fragments before it reached
 *	the demux endpoint.						*/
static int	enqueue(Sdr sdr, Object bundleObj, Bundle *bundle,
			VEndpoint *vpoint)
{
		OBJ_POINTER(Endpoint, endpoint);
	char	scriptBuf[SDRSTRING_BUFSZ];

	GET_OBJ_POINTER(sdr, Endpoint, endpoint, sdr_list_data(sdr,
				vpoint->endpointElt));
	if (vpoint->appPid == ERROR)
	{
		if (endpoint->recvScript != 0)
		{
			if (sdr_string_read(sdr, scriptBuf,
					endpoint->recvScript) < 0)
			{
				putErrmsg("bpdemuxd: can't read recvScript.",
						NULL);
				return -1;
			}

			if (pseudoshell(scriptBuf) < 0)
			{
				putErrmsg("bpdemuxd: recvScript failed.",
						NULL);
				return -1;
			}
		}

		if (endpoint->recvRule == DiscardBundle)
		{
			sdr_write(sdr, bundleObj, (char *) bundle,
					sizeof(Bundle));
			bpEndpointTally(vpoint, BP_ENDPOINT_ABANDONED,
					bundle->payload.length);
			bpDbTally(BP_DB_ABANDON, bundle->payload.length);
			return 0;
		}
	}

	bundle->dlvQueueElt = sdr_list_insert_last(sdr,
			endpoint->deliveryQueue, bundleObj);
	if (bundle->dlvQueueElt == 0)
	{
		putErrmsg("bpdemuxd: can't append to delivery queue.", NULL);
		return -1;
	}

	bundle->delivered = 1;
	sdr_write(sdr, bundleObj, (char *) bundle, sizeof(Bundle));
	if (vpoint->semaphore != SM_SEM_NONE)
	{
		sm_SemGive(vpoint->semaphore);
	}

	bpEndpointTally(vpoint, BP_ENDPOINT_QUEUED, bundle->payload.length);
	return 0;
}

/*	Moves one bundle out of the demux endpoint's queue; in a
 *	transaction.							*/
static int	moveBundle(Sdr sdr, Object elt, const DmxDb *db, int count)
{
	Object		bundleObj = sdr_list_data(sdr, elt);
	Bundle		bundle;
	VEndpoint	*target = NULL;
	DmxResult	result;
	uint64_t	svc = 0;

	sdr_stage(sdr, (char *) &bundle, bundleObj, sizeof(Bundle));
	sdr_list_delete(sdr, elt, NULL, NULL);
	bundle.dlvQueueElt = 0;
	bundle.delivered = 0;

	result = dmxResolve(rules, count, bundle.ancillaryData.dataLabel,
			db->defaultSvc, &svc);
	if (result != DmxToNowhere && svc != db->ownSvc)
	{
		target = findTarget(&bundle, svc);
	}

	if (target == NULL && result == DmxToRule && db->defaultSvc != 0
			&& db->defaultSvc != db->ownSvc)
	{
		/*	The rule names an endpoint the node lacks.	*/

		svc = db->defaultSvc;
		result = DmxToDefault;
		target = findTarget(&bundle, svc);
	}

	if (target == NULL)
	{
		counters.abandoned++;
		return bpAbandon(bundleObj, &bundle, BP_REASON_NO_ROUTE);
	}

	bundle.destination.ssp.ipn.serviceNbr = (unsigned long) svc;
	if (enqueue(sdr, bundleObj, &bundle, target) < 0)
	{
		return -1;
	}

	if (result == DmxToRule)
	{
		counters.byRule++;
	}
	else
	{
		counters.byDefault++;
	}

	counters.bytes += bundle.payload.length;

	/*	As ION does after delivery: destroys the bundle only if
	 *	the target's discard rule left it in no queue.		*/

	return bpDestroyBundle(bundleObj, 0);
}

#if defined (ION_LWT)
int	bpdemuxd(saddr a1, saddr a2, saddr a3, saddr a4, saddr a5,
		saddr a6, saddr a7, saddr a8, saddr a9, saddr a10)
{
	char	*ownEid = (char *) a1;
#else
int	main(int argc, char *argv[])
{
	char	*ownEid = (argc == 2 ? argv[1] : NULL);
#endif
	Sdr		sdr;
	VEndpoint	*vpoint;
		OBJ_POINTER(Endpoint, endpoint);
	DmxDb		db;
	Object		elt;
	Object		nextElt;
	uint64_t	ownNode;
	uint64_t	ownSvc;
	int		count;
	int		moved;
	int		exitCode = 0;

	if (ownEid == NULL || dmxParseIpnEid(ownEid, &ownNode, &ownSvc) < 0)
	{
		PUTS("Usage: bpdemuxd ipn:<node>.<service>");
		return 0;
	}

	if (bp_attach() < 0)
	{
		putErrmsg("bpdemuxd can't attach to BP.", NULL);
		return 1;
	}

	if (ownNode != (uint64_t) getOwnFqnn())
	{
		putErrmsg("bpdemuxd: endpoint is not on this node.", ownEid);
		writeErrmsgMemos();
		bp_detach();
		return 1;
	}

	if (bp_open(ownEid, &sap) < 0)
	{
		putErrmsg("bpdemuxd can't open its endpoint.", ownEid);
		writeErrmsgMemos();
		bp_detach();
		return 1;
	}

	sdr = getIonsdr();
	CHKZERO(sdr_begin_xn(sdr));
	if (loadDb(sdr, ownNode, ownSvc, &db, &count) < 0)
	{
		sdr_exit_xn(sdr);
		writeErrmsgMemos();
		bp_close(sap);
		bp_detach();
		return 1;
	}

	sdr_exit_xn(sdr);
	vpoint = sap->vpoint;
	isignal(SIGTERM, handleQuit);
	isignal(SIGINT, handleQuit);
	isignal(SIGUSR1, handleStats);

	{
		char	memoBuf[256];

		isprintf(memoBuf, sizeof memoBuf, "[i] bpdemuxd is running, \
endpoint '%s', %d rules, default service " UVAST_FIELDSPEC ".", ownEid,
				count, db.defaultSvc);
		writeMemo(memoBuf);
	}

	while (DMX_GET(running))
	{
		if (DMX_GET(statsWanted))
		{
			DMX_SET(statsWanted, 0);
			logStats(ownEid);
		}

		if (!sdr_begin_xn(sdr))
		{
			putErrmsg("bpdemuxd can't begin transaction.", NULL);
			exitCode = 1;
			break;
		}

		if (sm_SemEnded(vpoint->semaphore))
		{
			sdr_exit_xn(sdr);
			writeMemo("[i] bpdemuxd: endpoint has been stopped.");
			break;
		}

		GET_OBJ_POINTER(sdr, Endpoint, endpoint, sdr_list_data(sdr,
				vpoint->endpointElt));
		elt = sdr_list_first(sdr, endpoint->deliveryQueue);
		if (elt == 0)
		{
			sdr_exit_xn(sdr);

			/*	Given by every delivery to the endpoint,
			 *	and by bp_interrupt().			*/

			if (sm_SemTake(vpoint->semaphore) < 0)
			{
				putErrmsg("bpdemuxd can't take endpoint \
semaphore.", NULL);
				exitCode = 1;
				break;
			}

			continue;
		}

		/*	Rules are read afresh for every batch, so a
		 *	change applies to the next bundle.		*/

		if (loadDb(sdr, ownNode, ownSvc, &db, &count) < 0)
		{
			sdr_exit_xn(sdr);
			exitCode = 1;
			break;
		}

		for (moved = 0; elt && moved < BATCH; moved++, elt = nextElt)
		{
			nextElt = sdr_list_next(sdr, elt);
			if (moveBundle(sdr, elt, &db, count) < 0)
			{
				putErrmsg("bpdemuxd can't move bundle.", NULL);
				exitCode = 1;
				break;
			}
		}

		if (exitCode)
		{
			sdr_cancel_xn(sdr);
			break;
		}

		if (sdr_end_xn(sdr) < 0)
		{
			putErrmsg("bpdemuxd can't move bundles.", NULL);
			exitCode = 1;
			break;
		}
	}

	logStats(ownEid);
	bp_close(sap);
	sap = NULL;
	writeErrmsgMemos();
	writeMemo("[i] bpdemuxd has ended.");
	bp_detach();
	return exitCode;
}
