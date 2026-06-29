/*
	quiccla.h:	common definitions for the QUIC convergence layer
			adapter (ngtcp2 + GnuTLS).

	quicclo (outduct) is the QUICCL active entity (QUIC client); quiccli
	(induct) is the passive entity (QUIC server).  Bundles are carried
	as XFER_SEGMENT messages on QUIC streams (reliable) or, with -u, as
	QUIC datagrams (unreliable).
								*/

#ifndef QUICCLA_H
#define QUICCLA_H

#include <pthread.h>
#include "bpP.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QUIC_DEFAULT_PORT     4560	   /* draft-caini-dtn-quiccl.	*/
#define QUIC_ALPN	      "quicclav1"  /* ALPN protocol id (QUICCLv1).*/
#define QUICCLA_BUFSZ	      (256 * 1024) /* Max bundle handled.	*/
#define QUIC_LEN_PREFIX	      4		   /* uint32 BE per bundle.*/
#define QUIC_DEFAULT_IDLE_SEC 30

#define QUIC_MAX_HOST_LEN     256
#define QUIC_MAX_PATH_LEN     1024
#define QUIC_MAX_ALPN_LEN     64

/*
 * Configuration parsed from command-line arguments.  TLS material is
 * required on the server (quiccli); the client (quicclo) verifies the
 * server certificate against caFile unless noVerify is set.
 */
typedef struct
{
	char host[QUIC_MAX_HOST_LEN];
	int  port;
	char certFile[QUIC_MAX_PATH_LEN]; /* server cert (PEM).	*/
	char keyFile[QUIC_MAX_PATH_LEN];  /* server key (PEM).	*/
	char caFile[QUIC_MAX_PATH_LEN];	  /* trust anchors (PEM).	*/
	int  noVerify;			  /* client: skip verify.	*/
	char alpn[QUIC_MAX_ALPN_LEN];
	int  idleSec;
	int  unreliable;		  /* use QUIC datagrams, not streams.	*/
} QuicClaConfig;

/*
 * Parse a duct name of the form "host[:port]" into components.
 * Returns 0 on success, -1 on error.  Leaves *port at the caller's
 * default when no ":port" is present.
 */
static int parseQuicDuctName(const char *ductName, char *host, int *port)
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
		if (strlen(ductName) == 0 || strlen(ductName) >= QUIC_MAX_HOST_LEN)
		{
			return -1;
		}

		istrcpy(host, ductName, QUIC_MAX_HOST_LEN);
		return 0;
	}

	hostLen = colon - ductName;
	if (hostLen <= 0 || hostLen >= QUIC_MAX_HOST_LEN)
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
 *   -c <certfile>  server certificate (PEM)        [required: quiccli]
 *   -k <keyfile>   server private key (PEM)        [required: quiccli]
 *   -C <cafile>    CA trust anchors (PEM)
 *   -A <alpn>      ALPN protocol id (default "quicclav1")
 *   -n             client: do not verify server certificate
 *   -u             use the unreliable (QUIC datagram) service
 *   -t <seconds>   idle timeout (default 30)
 *
 * Scans the options in argv[1..argc-2]; ION appends the duct name as
 * the final argument (the host), which the caller consumes.
 * Returns 0 on success, -1 on error.
 */
static int parseQuicArgs(int argc, char *argv[], QuicClaConfig *cfg)
{
	int i;

	memset(cfg, 0, sizeof(QuicClaConfig));
	cfg->port = QUIC_DEFAULT_PORT;
	cfg->idleSec = QUIC_DEFAULT_IDLE_SEC;
	istrcpy(cfg->alpn, QUIC_ALPN, QUIC_MAX_ALPN_LEN);

	for (i = 1; i < argc - 1; i++)
	{
		if (strcmp(argv[i], "-c") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->certFile, argv[++i], QUIC_MAX_PATH_LEN);
		}
		else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->keyFile, argv[++i], QUIC_MAX_PATH_LEN);
		}
		else if (strcmp(argv[i], "-C") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->caFile, argv[++i], QUIC_MAX_PATH_LEN);
		}
		else if (strcmp(argv[i], "-A") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->alpn, argv[++i], QUIC_MAX_ALPN_LEN);
		}
		else if (strcmp(argv[i], "-n") == 0)
		{
			cfg->noVerify = 1;
		}
		else if (strcmp(argv[i], "-u") == 0)
		{
			cfg->unreliable = 1;
		}
		else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
		{
			cfg->idleSec = atoi(argv[++i]);
			if (cfg->idleSec < 1)
			{
				cfg->idleSec = QUIC_DEFAULT_IDLE_SEC;
			}
		}
		else
		{
			putErrmsg("quiccla: unknown argument.", argv[i]);
			return -1;
		}
	}

	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* QUICCLA_H */
