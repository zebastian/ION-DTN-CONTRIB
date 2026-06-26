/*
        mysqlcli.c:	BP MySQL-based convergence-layer input daemon.
                        Reads bundles addressed to this node (src_eid =
                        local node) from its table, injects them into
                        ION, and deletes the consumed rows.  Several
                        nodes may share one table; each picks up only
                        its own rows.
                                                                */
#include "mysqlcla.h"

typedef struct
{
	VInduct	       *vduct;
	int		running;
	MYSQL	       *conn;
	MysqlClaConfig *cfg;
} ReceiverThreadParms;

static void interruptThread(int signum)
{
	(void) signum;

	isignal(SIGTERM, interruptThread);
	ionKillMainThread("mysqlcli");
}

/*	Inject one batch.  Returns rows processed (>=0), or -1 on a
 *	connection/SQL error (caller reconnects).			*/

static int processBatch(ReceiverThreadParms *rtp, AcqWorkArea *work)
{
	MysqlClaConfig	   *cfg = rtp->cfg;
	MYSQL		   *conn = rtp->conn;
	char		    pattern[256];
	char		    escPattern[513];
	char		    query[1024];
	MYSQL_RES	   *result;
	MYSQL_ROW	    row;
	unsigned long	   *lengths;
	unsigned long long *idList;
	int		    count;
	int		    i;
	int		    failed = 0;

	idList = MTAKE(sizeof(unsigned long long) * cfg->batch);
	if (idList == NULL)
	{
		putErrmsg("mysqlcli: no memory for id list.", NULL);
		return -1;
	}

	mysqlOwnEidPattern(cfg, pattern, sizeof(pattern));
	mysql_real_escape_string(conn, escPattern, pattern, strlen(pattern));

	if (mysql_query(conn, "START TRANSACTION") != 0)
	{
		MRELEASE(idList);
		return -1;
	}

	isprintf(query, sizeof(query),
			"SELECT id,payload FROM `%s` WHERE src_eid LIKE '%s' "
			"ORDER BY id LIMIT %d FOR UPDATE",
			cfg->table, escPattern, cfg->batch);
	if (mysql_query(conn, query) != 0)
	{
		oK(mysql_query(conn, "ROLLBACK"));
		MRELEASE(idList);
		return -1;
	}

	result = mysql_store_result(conn);
	if (result == NULL)
	{
		oK(mysql_query(conn, "ROLLBACK"));
		MRELEASE(idList);
		return -1;
	}

	count = 0;
	while (!failed && (row = mysql_fetch_row(result)) != NULL)
	{
		lengths = mysql_fetch_lengths(result);
		if (row[1] == NULL || lengths == NULL)
		{
			continue;
		}

		idList[count] = strtoull(row[0], NULL, 10);

		if (bpBeginAcq(work, 0, NULL) < 0
				|| bpContinueAcq(work, row[1], (int) lengths[1],
						   0, 0)
						< 0
				|| bpEndAcq(work) < 0)
		{
			putErrmsg("mysqlcli: can't acquire bundle.", NULL);
			failed = 1;
			break;
		}

		count++;
	}

	mysql_free_result(result);

	if (failed)
	{
		/*	Leave the rows in place; a later pass retries.	*/

		oK(mysql_query(conn, "ROLLBACK"));
		MRELEASE(idList);
		return -1;
	}

	if (count == 0)
	{
		oK(mysql_query(conn, "COMMIT"));
		MRELEASE(idList);
		return 0;
	}

	/*	Delete the rows we injected, then commit.		*/

	{
		char *delQuery;
		int   pos;
		int   delLen = 64 + (count * 21) + strlen(cfg->table);

		delQuery = MTAKE(delLen);
		if (delQuery == NULL)
		{
			oK(mysql_query(conn, "ROLLBACK"));
			MRELEASE(idList);
			return -1;
		}

		isprintf(delQuery, delLen,
				"DELETE FROM `%s` WHERE id IN (", cfg->table);
		pos = strlen(delQuery);
		for (i = 0; i < count; i++)
		{
			isprintf(delQuery + pos, delLen - pos,
					"%s" UVAST_FIELDSPEC, i == 0 ? "" : ",",
					(uvast) idList[i]);
			pos += strlen(delQuery + pos);
		}

		delQuery[pos] = ')';
		delQuery[pos + 1] = '\0';

		if (mysql_query(conn, delQuery) != 0
				|| mysql_query(conn, "COMMIT") != 0)
		{
			oK(mysql_query(conn, "ROLLBACK"));
			MRELEASE(delQuery);
			MRELEASE(idList);
			return -1;
		}

		MRELEASE(delQuery);
	}

	MRELEASE(idList);
	return count;
}

static void *receiveBundles(void *parm)
{
	ReceiverThreadParms *rtp = (ReceiverThreadParms *) parm;
	char		    *procName = "mysqlcli";
	AcqWorkArea	    *work;
	int		     pause = 0;
	int		     processed;

	snooze(1); /*	Let main thread become interruptible.	*/
	work = bpGetAcqArea(rtp->vduct);
	if (work == NULL)
	{
		putErrmsg("mysqlcli can't get acquisition work area.", NULL);
		ionKillMainThread(procName);
		return NULL;
	}

	while (rtp->running)
	{
		if (rtp->conn == NULL || mysql_ping(rtp->conn) != 0)
		{
			if (rtp->conn != NULL)
			{
				mysql_close(rtp->conn);
			}

			rtp->conn = mysqlClaConnect(rtp->cfg);
			if (rtp->conn == NULL)
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

		processed = processBatch(rtp, work);
		if (processed < 0)
		{
			writeMemo("[?] mysqlcli: batch error; will reconnect.");
			mysql_close(rtp->conn);
			rtp->conn = NULL;
			continue;
		}

		if (processed == 0)
		{
			/*	Table empty for us; idle-poll.		*/

			microsnooze(rtp->cfg->pollMs * 1000);
		}
		else
		{
			sm_TaskYield();
		}
	}

	writeErrmsgMemos();
	writeMemo("[i] mysqlcli receiver thread has ended.");
	bpReleaseAcqArea(work);
	return NULL;
}

/*	*	*	Main thread functions	*	*	*	*/

#if defined(ION_LWT)
int mysqlcli(saddr a1, saddr a2, saddr a3, saddr a4, saddr a5, saddr a6,
		saddr a7, saddr a8, saddr a9, saddr a10)
{
	char *ductName = (char *) a1;
	int   largc = 2;
	char *largv[2];

	largv[0] = "mysqlcli";
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
	MysqlClaConfig	    cfg;
	ReceiverThreadParms rtp;
	pthread_t	    receiverThread;
	char		    hostName[MYSQL_MAX_HOST_LEN];

	if (ductName == NULL)
	{
		PUTS("Usage: mysqlcli <host[:port]> [-d db] [-T table] "
		     "[-u user] [-p pass] [-S socket] [-n batch] "
		     "[-i pollms] [-e srcpattern] "
		     "[-t] [-c cafile] [-k cert] [-K key]");
		return 0;
	}

	if (parseMysqlArgs(largc, largv, &cfg, MYSQL_OUTBOUND_TABLE) < 0)
	{
		putErrmsg("mysqlcli: invalid arguments.", NULL);
		return -1;
	}

	if (parseMysqlDuctName(ductName, hostName, &cfg.port) < 0)
	{
		putErrmsg("mysqlcli: invalid duct name.", ductName);
		return -1;
	}

	istrcpy(cfg.host, hostName, sizeof(cfg.host));

	if (bpAttach() < 0)
	{
		putErrmsg("mysqlcli can't attach to BP.", NULL);
		return -1;
	}

	findInduct("mysql", ductName, &vduct, &vductElt);
	if (vductElt == 0)
	{
		putErrmsg("No such mysql duct.", ductName);
		return -1;
	}

	if (vduct->cliPid != ERROR && vduct->cliPid != sm_TaskIdSelf())
	{
		putErrmsg("CLI task is already started for this duct.",
				itoa(vduct->cliPid));
		return -1;
	}

	/*	All command-line arguments are now validated.		*/

	memset((char *) &rtp, 0, sizeof(rtp));
	rtp.vduct = vduct;
	rtp.cfg = &cfg;
	rtp.conn = mysqlClaConnect(&cfg);
	if (rtp.conn == NULL)
	{
		writeMemo("[?] mysqlcli will attempt connect in receiver "
			  "thread.");
	}

	ionNoteMainThread("mysqlcli");
	isignal(SIGTERM, interruptThread);

	rtp.running = 1;
	if (pthread_begin(&receiverThread, NULL, receiveBundles, &rtp))
	{
		putSysErrmsg("mysqlcli can't create receiver thread", NULL);
		if (rtp.conn)
		{
			mysql_close(rtp.conn);
		}

		return -1;
	}

	{
		char txt[1024];

		isprintf(txt, sizeof(txt),
				"[i] mysqlcli is running, duct '%s', "
				"db '%s', table '%s'.",
				ductName, cfg.db, cfg.table);
		writeMemo(txt);
	}

	ionPauseMainThread(-1);

	rtp.running = 0;
	pthread_join(receiverThread, NULL);

	if (rtp.conn)
	{
		mysql_close(rtp.conn);
	}

	writeErrmsgMemos();
	writeMemo("[i] mysqlcli duct has ended.");
	ionDetach();
	return 0;
}
