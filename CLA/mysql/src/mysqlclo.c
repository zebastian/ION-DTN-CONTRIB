/*
        mysqlclo.c:	BP MySQL-based convergence-layer output daemon.
                        Takes bundles from ION (bpDequeue) and always
                        stores them, with metadata, into its table
                        (default "inbound"), where a peer node or an
                        application picks them up.

        Inserts are batched: a dequeue thread buffers bundles and a
        flush thread commits them in one transaction once the batch is
        full or a short flush window elapses.
                                                                */
#include <errno.h>
#include <time.h>
#include "mysqlcla.h"

typedef struct
{
	Object	       zco;	/*	Ack after commit.	*/
	unsigned char *payload; /*	Heap copy of bundle.	*/
	int	       len;
	char	       src[MYSQL_MAX_EID_LEN];
	char	       dst[MYSQL_MAX_EID_LEN];
} BatchItem;

typedef struct
{
	pthread_mutex_t mutex;
	pthread_cond_t	notEmpty;
	pthread_cond_t	notFull;
	BatchItem      *items;
	int		count;
	int		running;
	MysqlClaConfig *cfg;
} CloState;

static sm_SemId mysqlcloSemaphore(sm_SemId *semid)
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

	sm_SemEnd(mysqlcloSemaphore(NULL));
}

/*	Insert one batch of bundles in a single transaction.  Returns 1
 *	on success, 0 on any SQL error (caller reconnects + retries).	*/

static int insertBatch(MYSQL *conn, MysqlClaConfig *cfg, BatchItem *items,
		int n, char *query, int queryLen, char *escPayload)
{
	char escSrc[2 * MYSQL_MAX_EID_LEN + 1];
	char escDst[2 * MYSQL_MAX_EID_LEN + 1];
	int  i;

	if (mysql_query(conn, "START TRANSACTION") != 0)
	{
		return 0;
	}

	for (i = 0; i < n; i++)
	{
		mysql_real_escape_string(conn, escPayload,
				(char *) items[i].payload, items[i].len);
		mysql_real_escape_string(conn, escSrc, items[i].src,
				strlen(items[i].src));
		mysql_real_escape_string(conn, escDst, items[i].dst,
				strlen(items[i].dst));

		isprintf(query, queryLen,
				"INSERT INTO `%s` "
				"(payload,length,src_eid,dst_eid) "
				"VALUES ('%s',%d,'%s','%s')",
				cfg->table, escPayload, items[i].len, escSrc,
				escDst);

		if (mysql_query(conn, query) != 0)
		{
			oK(mysql_query(conn, "ROLLBACK"));
			return 0;
		}
	}

	if (mysql_query(conn, "COMMIT") != 0)
	{
		oK(mysql_query(conn, "ROLLBACK"));
		return 0;
	}

	return 1;
}

static void *flushBundles(void *parm)
{
	CloState       *state = parm;
	MysqlClaConfig *cfg = state->cfg;
	MYSQL	       *conn = NULL;
	BatchItem      *snapshot;
	char	       *query;
	char	       *escPayload;
	int		queryLen;
	int		n;
	int		i;
	int		pause = 0;
	int		ok;

	snapshot = MTAKE(sizeof(BatchItem) * cfg->batch);
	escPayload = MTAKE((2 * cfg->bufSz) + 1);
	queryLen = (2 * cfg->bufSz) + 512;
	query = MTAKE(queryLen);
	if (snapshot == NULL || escPayload == NULL || query == NULL)
	{
		putErrmsg("mysqlclo: no memory for flush buffers.", NULL);
		ionKillMainThread("mysqlclo");
		return NULL;
	}

	pthread_mutex_lock(&state->mutex);
	while (state->running || state->count > 0)
	{
		if (state->count == 0)
		{
			pthread_cond_wait(&state->notEmpty, &state->mutex);
			continue;
		}

		/*	Hold a partial batch for up to flushMs to let it
     *	fill, but flush at once when it reaches batch.	*/

		if (state->count < cfg->batch && state->running
				&& cfg->flushMs > 0)
		{
			struct timespec ts;

			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_sec += cfg->flushMs / 1000;
			ts.tv_nsec += (cfg->flushMs % 1000) * 1000000L;
			if (ts.tv_nsec >= 1000000000L)
			{
				ts.tv_sec += 1;
				ts.tv_nsec -= 1000000000L;
			}

			while (state->count < cfg->batch && state->running)
			{
				if (pthread_cond_timedwait(&state->notEmpty,
						    &state->mutex, &ts)
						== ETIMEDOUT)
				{
					break;
				}
			}
		}

		n = state->count;
		memcpy(snapshot, state->items, n * sizeof(BatchItem));
		state->count = 0;
		pthread_cond_broadcast(&state->notFull);
		pthread_mutex_unlock(&state->mutex);

		/*	Ensure a live connection (best-effort backoff).	*/

		while ((conn == NULL || mysql_ping(conn) != 0) && state->running)
		{
			if (conn != NULL)
			{
				mysql_close(conn);
			}

			conn = mysqlClaConnect(cfg);
			if (conn == NULL)
			{
				pause = (pause == 0) ? 1 : pause << 1;
				if (pause > MYSQL_MAX_RECONNECT_PAUSE)
				{
					pause = MYSQL_MAX_RECONNECT_PAUSE;
				}

				snooze(pause);
				continue;
			}

			pause = 0;
		}

		ok = (conn != NULL)
				&& insertBatch(conn, cfg, snapshot, n, query,
						queryLen, escPayload);

		for (i = 0; i < n; i++)
		{
			if (ok)
			{
				oK(bpHandleXmitSuccess(snapshot[i].zco));
			}
			else
			{
				oK(bpHandleXmitFailure(snapshot[i].zco));
			}

			MRELEASE(snapshot[i].payload);
		}

		if (!ok && conn != NULL)
		{
			mysql_close(conn);
			conn = NULL;
		}

		pthread_mutex_lock(&state->mutex);
	}

	pthread_mutex_unlock(&state->mutex);

	if (conn != NULL)
	{
		mysql_close(conn);
	}

	MRELEASE(snapshot);
	MRELEASE(escPayload);
	MRELEASE(query);
	return NULL;
}

/*	*	*	Main thread functions	*	*	*	*/

#if defined(ION_LWT)
int mysqlclo(saddr a1, saddr a2, saddr a3, saddr a4, saddr a5, saddr a6,
		saddr a7, saddr a8, saddr a9, saddr a10)
{
	char *ductName = (char *) a1;
	int   largc = 2;
	char *largv[2];

	largv[0] = "mysqlclo";
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
	MysqlClaConfig	cfg;
	char		hostName[MYSQL_MAX_HOST_LEN];
	Object		bundleZco;
	BpAncillaryData ancillaryData;
	unsigned int	bundleLength;
	ZcoReader	reader;
	int		bytesToSend;
	CloState	state;
	pthread_t	flushThread;

	if (ductName == NULL)
	{
		PUTS("Usage: mysqlclo <host[:port]> [-d db] [-T table] "
		     "[-u user] [-p pass] [-S socket] [-n batch] "
		     "[-f flushms] [-b bufsz] "
		     "[-t] [-c cafile] [-k cert] [-K key]");
		return 0;
	}

	if (parseMysqlArgs(largc, largv, &cfg, MYSQL_INBOUND_TABLE) < 0)
	{
		putErrmsg("mysqlclo: invalid arguments.", NULL);
		return -1;
	}

	if (parseMysqlDuctName(ductName, hostName, &cfg.port) < 0)
	{
		putErrmsg("mysqlclo: invalid duct name.", ductName);
		return -1;
	}

	istrcpy(cfg.host, hostName, sizeof(cfg.host));

	if (bpAttach() < 0)
	{
		putErrmsg("mysqlclo can't attach to BP.", NULL);
		return -1;
	}

	buffer = MTAKE(cfg.bufSz);
	if (buffer == NULL)
	{
		putErrmsg("No memory for MySQL buffer in mysqlclo.", NULL);
		return -1;
	}

	findOutduct("mysql", ductName, &vduct, &vductElt);
	if (vductElt == 0)
	{
		putErrmsg("No such mysql duct.", ductName);
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

	/*	All command-line arguments are now validated.		*/

	sdr = getIonsdr();

	memset((char *) &state, 0, sizeof(state));
	state.cfg = &cfg;
	state.running = 1;
	state.items = MTAKE(sizeof(BatchItem) * cfg.batch);
	if (state.items == NULL)
	{
		putErrmsg("No memory for MySQL batch in mysqlclo.", NULL);
		MRELEASE(buffer);
		return -1;
	}

	pthread_mutex_init(&state.mutex, NULL);
	pthread_cond_init(&state.notEmpty, NULL);
	pthread_cond_init(&state.notFull, NULL);

	oK(mysqlcloSemaphore(&(vduct->semaphore)));
	isignal(SIGTERM, shutDownClo);

	if (pthread_begin(&flushThread, NULL, flushBundles, &state))
	{
		putSysErrmsg("mysqlclo can't create flush thread", NULL);
		MRELEASE(state.items);
		MRELEASE(buffer);
		return -1;
	}

	{
		char memoBuf[1024];

		isprintf(memoBuf, sizeof(memoBuf),
				"[i] mysqlclo is running, duct '%s', "
				"db '%s', table '%s'.",
				ductName, cfg.db, cfg.table);
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
			writeMemo("[i] mysqlclo outduct closed.");
			sm_SemEnd(mysqlcloSemaphore(NULL));
			continue;
		}

		if (bundleZco == 1) /*	Corrupt bundle.	*/
		{
			continue;
		}

		CHKZERO(sdr_begin_xn(sdr));
		bundleLength = zco_length(sdr, bundleZco);
		sdr_exit_xn(sdr);

		if (bundleLength > (unsigned int) cfg.bufSz)
		{
			putErrmsg("Bundle too big for MySQL CLA buffer.",
					itoa(bundleLength));
			if (bpHandleXmitFailure(bundleZco) < 0)
			{
				putErrmsg("Can't handle xmit failure.", NULL);
				break;
			}

			continue;
		}

		zco_start_transmitting(bundleZco, &reader);
		zco_track_file_offset(&reader);
		CHKZERO(sdr_begin_xn(sdr));
		bytesToSend = zco_transmit(sdr, &reader, cfg.bufSz,
				(char *) buffer);
		if (sdr_end_xn(sdr) < 0 || bytesToSend < 0)
		{
			putErrmsg("Can't issue from ZCO.", NULL);
			break;
		}

		/*	Buffer the bundle for the flush thread.		*/

		{
			BatchItem item;

			memset((char *) &item, 0, sizeof(item));
			item.zco = bundleZco;
			item.len = bytesToSend;
			item.payload = MTAKE(bytesToSend);
			if (item.payload == NULL)
			{
				putErrmsg("No memory for bundle copy.", NULL);
				oK(bpHandleXmitFailure(bundleZco));
				continue;
			}

			memcpy(item.payload, buffer, bytesToSend);
			oK(mysqlExtractEids(buffer, bytesToSend, item.src,
					sizeof(item.src), item.dst,
					sizeof(item.dst)));

			pthread_mutex_lock(&state.mutex);
			while (state.count == cfg.batch && state.running)
			{
				pthread_cond_wait(&state.notFull, &state.mutex);
			}

			state.items[state.count] = item;
			state.count++;
			pthread_cond_signal(&state.notEmpty);
			pthread_mutex_unlock(&state.mutex);
		}
	}

	/*	Shut down: let the flush thread drain remaining bundles.*/

	pthread_mutex_lock(&state.mutex);
	state.running = 0;
	pthread_cond_broadcast(&state.notEmpty);
	pthread_cond_broadcast(&state.notFull);
	pthread_mutex_unlock(&state.mutex);
	pthread_join(flushThread, NULL);

	pthread_mutex_destroy(&state.mutex);
	pthread_cond_destroy(&state.notEmpty);
	pthread_cond_destroy(&state.notFull);

	writeErrmsgMemos();
	writeMemo("[i] mysqlclo duct has ended.");
	MRELEASE(state.items);
	MRELEASE(buffer);
	ionDetach();
	return 0;
}
