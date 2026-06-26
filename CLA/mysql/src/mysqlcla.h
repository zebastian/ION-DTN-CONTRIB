/*
        mysqlcla.h:	common definitions for the MySQL convergence
                        layer adapter modules.

        The MySQL server is used as a shared bundle mailbox.  Per ION
        convention:

          mysqlclo  (outduct): ION hands it bundles via bpDequeue; it
                    ALWAYS inserts them, with metadata, into its table
                    (default "inbound").  No filtering.

          mysqlcli  (induct):  it selects bundles from its table
                    (default "outbound") that belong to THIS node --
                    src_eid matches the local node's own EID -- injects
                    them into ION, and deletes the consumed rows.

        Several ION nodes may share one server/table; each node's cli
        picks up only its own rows, so the same table multiplexes many
        connections.
                                                                */

#ifndef MYSQLCLA_H
#define MYSQLCLA_H

#include <mysql.h>
#include <pthread.h>
#include "bpP.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MYSQLCLA_BUFSZ		  (256 * 1024)
#define MYSQL_DEFAULT_PORT	  3306
#define MYSQL_DEFAULT_DB	  "ion"
#define MYSQL_INBOUND_TABLE	  "inbound"
#define MYSQL_OUTBOUND_TABLE	  "outbound"
#define MYSQL_DEFAULT_BATCH	  100
#define MYSQL_DEFAULT_POLL_MS	  1000
#define MYSQL_DEFAULT_FLUSH_MS	  100
#define MYSQL_MAX_RECONNECT_PAUSE 30

#define MYSQL_MAX_HOST_LEN	  256
#define MYSQL_MAX_IDENT_LEN	  64
#define MYSQL_MAX_EID_LEN	  64
#define MYSQL_MAX_CRED_LEN	  128
#define MYSQL_MAX_PATH_LEN	  1024

/*
 * Configuration parsed from command-line arguments.
 */
typedef struct
{
	char host[MYSQL_MAX_HOST_LEN];
	int  port;
	char socket[MYSQL_MAX_PATH_LEN];
	char db[MYSQL_MAX_IDENT_LEN];
	char table[MYSQL_MAX_IDENT_LEN];
	char user[MYSQL_MAX_CRED_LEN];
	char password[MYSQL_MAX_CRED_LEN];
	int  batch;	     /*	Max rows per chunk.		*/
	int  pollMs;	     /*	cli: idle poll interval.	*/
	int  flushMs;	     /*	clo: partial-batch flush window.*/
	int  bufSz;	     /*	Max bundle size handled.	*/
	char srcFilter[256]; /*	cli: -e override for src match.	*/
	int  useTls;
	char caFile[MYSQL_MAX_PATH_LEN];
	char certFile[MYSQL_MAX_PATH_LEN];
	char keyFile[MYSQL_MAX_PATH_LEN];
} MysqlClaConfig;

/*
 * Validate a SQL identifier (database or table name).  Identifiers are
 * interpolated into statement text, so restrict them to a safe set to
 * keep the queries injection-proof.  Returns 0 if valid, -1 otherwise.
 */
static int mysqlValidIdent(const char *ident)
{
	const char *c;

	if (ident == NULL || *ident == '\0'
			|| strlen(ident) >= MYSQL_MAX_IDENT_LEN)
	{
		return -1;
	}

	for (c = ident; *c != '\0'; c++)
	{
		if (!isalnum((int) *c) && *c != '_')
		{
			return -1;
		}
	}

	return 0;
}

/*
 * Parse a duct name of the form "host[:port]" into components.
 * Returns 0 on success, -1 on error.  Leaves *port unchanged when no
 * ":port" is present, so the caller's default is kept.
 */
static int parseMysqlDuctName(const char *ductName, char *host, int *port)
{
	const char *colon;
	int	    hostLen;

	if (ductName == NULL || host == NULL || port == NULL)
	{
		return -1;
	}

	colon = strchr(ductName, ':');
	if (colon == NULL)
	{
		if (strlen(ductName) == 0
				|| strlen(ductName) >= MYSQL_MAX_HOST_LEN)
		{
			return -1;
		}

		istrcpy(host, ductName, MYSQL_MAX_HOST_LEN);
		return 0;
	}

	hostLen = colon - ductName;
	if (hostLen <= 0 || hostLen >= MYSQL_MAX_HOST_LEN)
	{
		return -1;
	}

	memcpy(host, ductName, hostLen);
	host[hostLen] = '\0';

	if (sscanf(colon + 1, "%d", port) != 1 || *port <= 0 || *port > 65535)
	{
		return -1;
	}

	return 0;
}

/*
 * Parse optional command-line arguments.
 *
 *   -d <db>        database name (default "ion")
 *   -T <table>     table name (default supplied by caller)
 *   -u <user>      MySQL user
 *   -p <pass>      MySQL password
 *   -S <socket>    Unix domain socket path
 *   -n <batch>     max rows per chunk (default 100)
 *   -i <ms>        cli: idle poll interval (default 1000)
 *   -f <ms>        clo: partial-batch flush window (default 100)
 *   -b <bytes>     max bundle size handled (default 262144)
 *   -e <pattern>   cli: override src_eid match (SQL LIKE pattern)
 *   -t             enable TLS
 *   -c <cafile>    CA certificate (PEM)
 *   -k <certfile>  client certificate (PEM)
 *   -K <keyfile>   client private key (PEM)
 *
 * defaultTable is applied when -T is not given.  ION appends the duct
 * name as the final argument (argv[argc-1], the host), which the caller
 * consumes; this scans the options in argv[1..argc-2].
 * Returns 0 on success, -1 on error.
 */
static int parseMysqlArgs(int argc, char *argv[], MysqlClaConfig *cfg,
		const char *defaultTable)
{
	int i;

	memset(cfg, 0, sizeof(MysqlClaConfig));
	cfg->port = MYSQL_DEFAULT_PORT;
	istrcpy(cfg->db, MYSQL_DEFAULT_DB, MYSQL_MAX_IDENT_LEN);
	istrcpy(cfg->table, defaultTable, MYSQL_MAX_IDENT_LEN);
	cfg->batch = MYSQL_DEFAULT_BATCH;
	cfg->pollMs = MYSQL_DEFAULT_POLL_MS;
	cfg->flushMs = MYSQL_DEFAULT_FLUSH_MS;
	cfg->bufSz = MYSQLCLA_BUFSZ;

	for (i = 1; i < argc - 1; i++)
	{
		if (strcmp(argv[i], "-d") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->db, argv[++i], MYSQL_MAX_IDENT_LEN);
		}
		else if (strcmp(argv[i], "-T") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->table, argv[++i], MYSQL_MAX_IDENT_LEN);
		}
		else if (strcmp(argv[i], "-u") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->user, argv[++i], MYSQL_MAX_CRED_LEN);
		}
		else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->password, argv[++i], MYSQL_MAX_CRED_LEN);
		}
		else if (strcmp(argv[i], "-S") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->socket, argv[++i], MYSQL_MAX_PATH_LEN);
		}
		else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc)
		{
			cfg->batch = atoi(argv[++i]);
			if (cfg->batch < 1)
			{
				cfg->batch = 1;
			}
		}
		else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc)
		{
			cfg->pollMs = atoi(argv[++i]);
		}
		else if (strcmp(argv[i], "-f") == 0 && i + 1 < argc)
		{
			cfg->flushMs = atoi(argv[++i]);
		}
		else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc)
		{
			cfg->bufSz = atoi(argv[++i]);
			if (cfg->bufSz < 1024)
			{
				cfg->bufSz = 1024;
			}
		}
		else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->srcFilter, argv[++i],
					sizeof(cfg->srcFilter));
		}
		else if (strcmp(argv[i], "-t") == 0)
		{
			cfg->useTls = 1;
		}
		else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->caFile, argv[++i], MYSQL_MAX_PATH_LEN);
			cfg->useTls = 1;
		}
		else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->certFile, argv[++i], MYSQL_MAX_PATH_LEN);
			cfg->useTls = 1;
		}
		else if (strcmp(argv[i], "-K") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->keyFile, argv[++i], MYSQL_MAX_PATH_LEN);
			cfg->useTls = 1;
		}
		else
		{
			putErrmsg("mysqlcla: unknown argument.", argv[i]);
			return -1;
		}
	}

	if (mysqlValidIdent(cfg->db) < 0 || mysqlValidIdent(cfg->table) < 0)
	{
		putErrmsg("mysqlcla: invalid database/table name.", NULL);
		return -1;
	}

	return 0;
}

/*
 * Open a connection to the MySQL server and ensure the configured
 * database and table exist.  Returns a connected MYSQL handle, or NULL
 * on failure (caller may retry).
 */
static MYSQL *mysqlClaConnect(const MysqlClaConfig *cfg)
{
	MYSQL *conn;
	char   stmt[1024];

	conn = mysql_init(NULL);
	if (conn == NULL)
	{
		putErrmsg("mysqlcla: mysql_init failed.", NULL);
		return NULL;
	}

	if (cfg->useTls)
	{
		mysql_ssl_set(conn, cfg->keyFile[0] ? cfg->keyFile : NULL,
				cfg->certFile[0] ? cfg->certFile : NULL,
				cfg->caFile[0] ? cfg->caFile : NULL, NULL, NULL);
	}

	/*	Connect without selecting a database; it may not exist
   *	yet (we create it below).				*/

	if (mysql_real_connect(conn, cfg->host, cfg->user, cfg->password, NULL,
			    cfg->port, cfg->socket[0] ? cfg->socket : NULL, 0)
			== NULL)
	{
		putErrmsg("mysqlcla: can't connect.", mysql_error(conn));
		mysql_close(conn);
		return NULL;
	}

	isprintf(stmt, sizeof(stmt), "CREATE DATABASE IF NOT EXISTS `%s`",
			cfg->db);
	if (mysql_query(conn, stmt) != 0)
	{
		putErrmsg("mysqlcla: can't create database.", mysql_error(conn));
		mysql_close(conn);
		return NULL;
	}

	if (mysql_select_db(conn, cfg->db) != 0)
	{
		putErrmsg("mysqlcla: can't select database.", mysql_error(conn));
		mysql_close(conn);
		return NULL;
	}

	isprintf(stmt, sizeof(stmt),
			"CREATE TABLE IF NOT EXISTS `%s` ("
			"id BIGINT AUTO_INCREMENT PRIMARY KEY,"
			"payload LONGBLOB NOT NULL,"
			"length INT NOT NULL,"
			"src_eid VARCHAR(64),"
			"dst_eid VARCHAR(64),"
			"created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
			"INDEX (src_eid))",
			cfg->table);
	if (mysql_query(conn, stmt) != 0)
	{
		putErrmsg("mysqlcla: can't create table.", mysql_error(conn));
		mysql_close(conn);
		return NULL;
	}

	return conn;
}

/*
 * Extract source and destination EID strings (and implicitly validate
 * the framing) from a serialized BPv7 bundle.  Fills src/dst with EID
 * text, or empty strings if extraction fails.  Returns 0 on success,
 * -1 if the primary block can't be parsed.
 */
static int mysqlExtractEids(unsigned char *buf, int len, char *src, int srcLen,
		char *dst, int dstLen)
{
	unsigned char *cursor = buf;
	unsigned int   remaining = (unsigned int) len;
	uvast	       uvtemp;
	uvast	       arrayLen;
	EndpointId     destEid;
	EndpointId     srcEid;
	char	      *str;

	src[0] = '\0';
	dst[0] = '\0';
	memset((char *) &destEid, 0, sizeof destEid);
	memset((char *) &srcEid, 0, sizeof srcEid);

	/*	A bundle is an indefinite-length CBOR array of blocks;
   *	the first block is the primary block, itself an array
   *	of [version, flags, crcType, dest, source, ...].
   *	cbor_decode_array_open requires *size pre-set to 0 ("any").	*/

	arrayLen = 0;
	if (cbor_decode_array_open(&arrayLen, &cursor, &remaining) < 1)
	{
		return -1;
	}

	arrayLen = 0;
	if (cbor_decode_array_open(&arrayLen, &cursor, &remaining) < 1
			|| cbor_decode_integer(&uvtemp, CborAny, &cursor,
					   &remaining)
					< 1
			|| cbor_decode_integer(&uvtemp, CborAny, &cursor,
					   &remaining)
					< 1
			|| cbor_decode_integer(&uvtemp, CborAny, &cursor,
					   &remaining)
					< 1)
	{
		return -1;
	}

	if (acquireEid(&destEid, &cursor, &remaining) < 1)
	{
		eraseEid(&destEid);
		return -1;
	}

	if (acquireEid(&srcEid, &cursor, &remaining) < 1)
	{
		eraseEid(&destEid);
		eraseEid(&srcEid);
		return -1;
	}

	readEid(&destEid, &str);
	if (str)
	{
		istrcpy(dst, str, dstLen);
		MRELEASE(str);
	}

	readEid(&srcEid, &str);
	if (str)
	{
		istrcpy(src, str, srcLen);
		MRELEASE(str);
	}

	eraseEid(&destEid);
	eraseEid(&srcEid);
	return 0;
}

/*
 * Build the SQL boolean expression that selects the rows belonging to
 * this connection.  When the operator supplied an -e override it is
 * used verbatim as a LIKE pattern; otherwise the local node's own EID
 * (ipn:<ownNodeNbr>.*) is derived from ION.  buf must hold the escaped
 * pattern produced by the caller via mysql_real_escape_string.
 */
static void mysqlOwnEidPattern(const MysqlClaConfig *cfg, char *buf, int bufLen)
{
	if (cfg->srcFilter[0] != '\0')
	{
		istrcpy(buf, cfg->srcFilter, bufLen);
	}
	else
	{
		isprintf(buf, bufLen, "ipn:" UVAST_FIELDSPEC ".%%", getOwnFqnn());
	}
}

#ifdef __cplusplus
}
#endif

#endif /* MYSQLCLA_H */
