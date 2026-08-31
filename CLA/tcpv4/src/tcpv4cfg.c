/*
	tcpv4cfg.c:	configuration parsing for the TCPCLv4 convergence
			layer adapter.

			The duct name ION hands the adapter and the optional
			command-line arguments that carry the TLS credentials
			and the local policies.  Both the daemon and the
			session engine parse duct names, so this lives in its
			own translation unit rather than in tcpv4cla.h.
								*/

#include "tcpv4cla.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Parse a duct name of the form "host[:port]" into components, where host
 * is a DNS name, an IPv4 address, or a bracketed IPv6 address ("[::1]").
 * The brackets are stripped, so host is what getaddrinfo() wants.
 * Returns 0 on success, -1 on error.  Leaves *port at the caller's
 * default when no ":port" is present.
 */
int parseTcpv4DuctName(const char *ductName, char *host, int *port)
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
 *   -E <policy>    NODE-ID authentication: require (default), prefer, none
 *   -K <seconds>   Keepalive Interval to propose (default 30, 0 disables)
 *   -t <seconds>   idle session termination timeout (default 0 = never)
 *   -S <bytes>     advertised Segment MRU (default 65536)
 *   -M <bytes>     advertised Transfer MRU (default 262144)
 *   -r <bytes>     socket receive buffer (SO_RCVBUF; 0 = OS default)
 *   -w <bytes>     socket send buffer (SO_SNDBUF; 0 = OS default)
 *   -L <count>     concurrently open sessions (default 64)
 *   -P <string>    TLS priority string (GnuTLS syntax)
 *
 * Scans the options in argv[1..argc-2]; ION appends the duct name as
 * the final argument (the host), which the caller consumes.
 * Returns 0 on success, -1 on error.
 */
int parseTcpv4Args(int argc, char *argv[], Tcpv4ClaConfig *cfg)
{
	int i;
	int eidGiven = 0;

	memset(cfg, 0, sizeof(Tcpv4ClaConfig));
	cfg->port = TCPV4_DEFAULT_PORT;
	cfg->tlsPolicy = TCPV4_TLS_REQUIRE;
	cfg->eidPolicy = TCPV4_EIDPOL_REQUIRE;
	cfg->keepalive = TCPV4_DEFAULT_KEEPALIVE;
	cfg->segmentMru = TCPV4_DEFAULT_SEGMENT_MRU;
	cfg->transferMru = TCPV4CLA_BUFSZ;
	cfg->maxSessions = TCPV4_DEFAULT_MAX_SESSIONS;

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
		else if (strcmp(argv[i], "-E") == 0 && i + 1 < argc)
		{
			i++;
			if (strcmp(argv[i], "require") == 0)
			{
				cfg->eidPolicy = TCPV4_EIDPOL_REQUIRE;
			}
			else if (strcmp(argv[i], "prefer") == 0)
			{
				cfg->eidPolicy = TCPV4_EIDPOL_PREFER;
			}
			else if (strcmp(argv[i], "none") == 0)
			{
				cfg->eidPolicy = TCPV4_EIDPOL_NONE;
			}
			else
			{
				putErrmsg("tcpv4cla: bad -E policy.", argv[i]);
				return -1;
			}

			eidGiven = 1;
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
		else if (strcmp(argv[i], "-L") == 0 && i + 1 < argc)
		{
			cfg->maxSessions = atoi(argv[++i]);
			if (cfg->maxSessions < 1
					|| cfg->maxSessions
							> TCPV4_MAX_SESSIONS_LIMIT)
			{
				putErrmsg("tcpv4cla: bad -L session limit.",
						argv[i]);
				return -1;
			}
		}
		else if (strcmp(argv[i], "-P") == 0 && i + 1 < argc)
		{
			istrcpy(cfg->tlsPriority, argv[++i],
					TCPV4_MAX_PRIORITY_LEN);
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

	/*	A NODE-ID is only as good as the certificate that carries
	 *	it, so -n - which is a decision not to authenticate the peer
	 *	at all - also gives up on authenticating its node ID, unless
	 *	the operator asked for a policy explicitly.		*/

	if (cfg->noVerify && !eidGiven)
	{
		cfg->eidPolicy = TCPV4_EIDPOL_NONE;
	}

	return 0;
}
