/*
	tcpv4cla.h:	common definitions for the TCPCLv4 convergence
			layer adapter (RFC 9174, TLS via GnuTLS).

	Bundles are carried as XFER_SEGMENT messages over a TCP connection
	that is (by default) protected with TLS 1.3.
								*/

#ifndef TCPV4CLA_H
#define TCPV4CLA_H

#include <pthread.h>
#include "bpP.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TCPV4_DEFAULT_PORT	4556	    /* RFC 9174 8.1 (dtn-bundle).*/
#define TCPV4CLA_BUFSZ		(256 * 1024) /* Max bundle handled.	*/
#define TCPV4_DEFAULT_SEGMENT_MRU (64 * 1024)
#define TCPV4_DEFAULT_KEEPALIVE	30	/* RFC 9174 5.1.1: >= 30 s.	*/
#define TCPV4_MAX_KEEPALIVE	600	/* RFC 9174 5.1.1: <= 600 s.	*/
#define TCPV4_CONTACT_TIMEOUT	60	/* RFC 9174 4.1: <= 60 s.	*/
#define TCPV4_MAX_RECONNECT	60	/* RFC 9174 4.1: <= 60 s.	*/

#define TCPV4_MAX_HOST_LEN	256
#define TCPV4_MAX_PATH_LEN	1024
#define TCPV4_MAX_NODEID_LEN	256

/*	Local policy applied to the negotiated Enable TLS parameter
 *	(RFC 9174 4.3).  REQUIRE terminates the session with "Contact
 *	Failure" when the peer cannot do TLS; PREFER is the opportunistic
 *	security model of RFC 7435; DISABLE clears our CAN_TLS flag.	*/
#define TCPV4_TLS_REQUIRE	0
#define TCPV4_TLS_PREFER	1
#define TCPV4_TLS_DISABLE	2

/*
 * Configuration parsed from command-line arguments.  A certificate and key
 * are required whenever TLS is not disabled: RFC 9174 4.4.3 has the passive
 * entity supply a certificate and request one from the active entity, so
 * both roles need their own end-entity credentials.
 */
typedef struct
{
	char host[TCPV4_MAX_HOST_LEN];
	int  port;
	char certFile[TCPV4_MAX_PATH_LEN]; /* end-entity cert (PEM).	*/
	char keyFile[TCPV4_MAX_PATH_LEN];  /* private key (PEM).	*/
	char caFile[TCPV4_MAX_PATH_LEN];   /* trust anchors (PEM).	*/
	int  noVerify;			   /* skip peer verification.	*/
	int  tlsPolicy;			   /* TCPV4_TLS_*.		*/
	int  keepalive;	   /* Keepalive Interval we propose, seconds.	*/
	int  idleSec;	   /* Idle session termination; 0 disables.	*/
	int  segmentMru;   /* advertised Segment MRU.			*/
	int  transferMru;  /* advertised Transfer MRU.			*/
	int  rcvBufSize;   /* SO_RCVBUF, bytes; 0 = OS default.		*/
	int  sndBufSize;   /* SO_SNDBUF, bytes; 0 = OS default.		*/
} Tcpv4ClaConfig;

/*
 * Parse a duct name of the form "host[:port]" into components, where host
 * is a DNS name, an IPv4 address, or a bracketed IPv6 address ("[::1]").
 * The brackets are stripped, so host is what getaddrinfo() wants.
 * Returns 0 on success, -1 on error.  Leaves *port at the caller's
 * default when no ":port" is present.
 */
static int parseTcpv4DuctName(const char *ductName, char *host, int *port)
{
	const char *hostStart;
	const char *colon;
	int	    hostLen;

	if (ductName == NULL || host == NULL || port == NULL)
	{
		return -1;
	}

	if (*ductName == '[') /*	Bracketed IPv6 literal.		*/
	{
		hostStart = ductName + 1;
		colon = strchr(hostStart, ']');
		if (colon == NULL)
		{
			return -1;
		}

		hostLen = colon - hostStart;
		colon = (colon[1] == ':' ? colon + 1 : NULL);
	}
	else
	{
		hostStart = ductName;

		/*	An unbracketed name has at most one colon; more
		 *	than one means a bare IPv6 literal, which has no
		 *	port at all.					*/

		colon = strchr(hostStart, ':');
		if (colon != NULL && strchr(colon + 1, ':') != NULL)
		{
			colon = NULL;
		}

		hostLen = (colon == NULL ? (int) strlen(hostStart)
					 : (int) (colon - hostStart));
	}

	if (hostLen <= 0 || hostLen >= TCPV4_MAX_HOST_LEN)
	{
		return -1;
	}

	memcpy(host, hostStart, hostLen);
	host[hostLen] = '\0';

	if (colon != NULL
			&& (sscanf(colon + 1, "%d", port) != 1 || *port <= 0
					|| *port > 65535))
	{
		return -1;
	}

	return 0;
}

/*
 * Parse optional command-line arguments.
 *
 *   -c <certfile>  end-entity certificate (PEM)  [required unless -T none]
 *   -k <keyfile>   private key (PEM)             [required unless -T none]
 *   -C <cafile>    CA trust anchors (PEM)
 *   -n             do not verify the peer certificate
 *   -T <policy>    TLS policy: require (default), prefer, none
 *   -K <seconds>   Keepalive Interval to propose (default 30, 0 disables)
 *   -t <seconds>   idle session termination timeout (default 0 = never)
 *   -S <bytes>     advertised Segment MRU (default 65536)
 *   -M <bytes>     advertised Transfer MRU (default 262144)
 *   -r <bytes>     socket receive buffer (SO_RCVBUF; 0 = OS default)
 *   -w <bytes>     socket send buffer (SO_SNDBUF; 0 = OS default)
 *
 * Scans the options in argv[1..argc-2]; ION appends the duct name as
 * the final argument (the host), which the caller consumes.
 * Returns 0 on success, -1 on error.
 */
static int parseTcpv4Args(int argc, char *argv[], Tcpv4ClaConfig *cfg)
{
	int i;

	memset(cfg, 0, sizeof(Tcpv4ClaConfig));
	cfg->port = TCPV4_DEFAULT_PORT;
	cfg->tlsPolicy = TCPV4_TLS_REQUIRE;
	cfg->keepalive = TCPV4_DEFAULT_KEEPALIVE;
	cfg->segmentMru = TCPV4_DEFAULT_SEGMENT_MRU;
	cfg->transferMru = TCPV4CLA_BUFSZ;

	for (i = 1; i < argc - 1; i++)
	{
		if (strcmp(argv[i], "-c") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->certFile, argv[++i], TCPV4_MAX_PATH_LEN);
		}
		else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->keyFile, argv[++i], TCPV4_MAX_PATH_LEN);
		}
		else if (strcmp(argv[i], "-C") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->caFile, argv[++i], TCPV4_MAX_PATH_LEN);
		}
		else if (strcmp(argv[i], "-n") == 0)
		{
			cfg->noVerify = 1;
		}
		else if (strcmp(argv[i], "-T") == 0 && i + 1 < argc)
		{
			i++;
			if (strcmp(argv[i], "require") == 0)
			{
				cfg->tlsPolicy = TCPV4_TLS_REQUIRE;
			}
			else if (strcmp(argv[i], "prefer") == 0)
			{
				cfg->tlsPolicy = TCPV4_TLS_PREFER;
			}
			else if (strcmp(argv[i], "none") == 0)
			{
				cfg->tlsPolicy = TCPV4_TLS_DISABLE;
			}
			else
			{
				putErrmsg("tcpv4cla: bad -T policy.", argv[i]);
				return -1;
			}
		}
		else if (strcmp(argv[i], "-K") == 0 && i + 1 < argc)
		{
			cfg->keepalive = atoi(argv[++i]);
			if (cfg->keepalive < 0
					|| cfg->keepalive > TCPV4_MAX_KEEPALIVE)
			{
				putErrmsg("tcpv4cla: bad -K interval.",
						argv[i]);
				return -1;
			}
		}
		else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
		{
			cfg->idleSec = atoi(argv[++i]);
			if (cfg->idleSec < 0)
			{
				cfg->idleSec = 0;
			}
		}
		else if (strcmp(argv[i], "-S") == 0 && i + 1 < argc)
		{
			cfg->segmentMru = atoi(argv[++i]);
			if (cfg->segmentMru < 1
					|| cfg->segmentMru > TCPV4CLA_BUFSZ)
			{
				putErrmsg("tcpv4cla: bad -S segment MRU.",
						argv[i]);
				return -1;
			}
		}
		else if (strcmp(argv[i], "-M") == 0 && i + 1 < argc)
		{
			cfg->transferMru = atoi(argv[++i]);
			if (cfg->transferMru < 1
					|| cfg->transferMru > TCPV4CLA_BUFSZ)
			{
				putErrmsg("tcpv4cla: bad -M transfer MRU.",
						argv[i]);
				return -1;
			}
		}
		else if (strcmp(argv[i], "-r") == 0 && i + 1 < argc)
		{
			cfg->rcvBufSize = atoi(argv[++i]);
		}
		else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc)
		{
			cfg->sndBufSize = atoi(argv[++i]);
		}
		else
		{
			putErrmsg("tcpv4cla: unknown argument.", argv[i]);
			return -1;
		}
	}

	if (cfg->tlsPolicy != TCPV4_TLS_DISABLE
			&& (cfg->certFile[0] == '\0' || cfg->keyFile[0] == '\0'))
	{
		putErrmsg("tcpv4cla: -c and -k are required unless -T none.",
				NULL);
		return -1;
	}

	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* TCPV4CLA_H */
