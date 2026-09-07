/*
	tcpv4tls_mbedtls.c:	Mbed TLS backend for the TCPCLv4 convergence
				layer (see tcpv4tls.h).
									*/

#include "tcpv4tls.h"
#include "tcpv4x509.h"
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <mbedtls/build_info.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/oid.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

/*	RFC 9174 4.4.3 requires the handshake to be TLS 1.3, which Mbed TLS
 *	has only from 3.6 on, and only when the build was configured for it.
 *	The convergence layer runs a handshake per session on its own thread
 *	and shares one configuration - credentials, trust anchors, random
 *	generator - between them, which is what the threading layer of the
 *	library is there to make safe.					*/

#if MBEDTLS_VERSION_NUMBER < 0x03060000
#error "The TCPCLv4 Mbed TLS backend needs Mbed TLS 3.6 or later."
#endif
#ifndef MBEDTLS_SSL_PROTO_TLS1_3
#error "The TCPCLv4 Mbed TLS backend needs MBEDTLS_SSL_PROTO_TLS1_3."
#endif
#ifndef MBEDTLS_THREADING_C
#error "The TCPCLv4 Mbed TLS backend needs MBEDTLS_THREADING_C."
#endif

/*	Mbed TLS has no system trust store of its own: where GnuTLS asks the
 *	platform, this backend has to name the file the platform keeps its
 *	trust anchors in.  These are the usual ones; -C names it outright
 *	where a deployment keeps it somewhere else.			*/

static const char *systemTrustFiles[] = {
	"/etc/ssl/certs/ca-certificates.crt",	/* Debian, Ubuntu, Arch	*/
	"/etc/pki/tls/certs/ca-bundle.crt",	/* Fedora, RHEL		*/
	"/etc/ssl/ca-bundle.pem",		/* SUSE			*/
	"/etc/ssl/cert.pem",			/* Alpine, the BSDs	*/
	NULL
};

#define TCPV4_SYSTEM_TRUST_DIR "/etc/ssl/certs"

/*	How long a handshake may take before the connection is abandoned.
 *	The sockets of this CLA are blocking, so without a deadline a peer
 *	that opens a connection and then says nothing would hold a session
 *	slot and its threads for as long as it liked (RFC 9174 7.10).	*/

#define TCPV4_TLS_HANDSHAKE_SEC	40

/*	Corked sends are gathered here and written as one record, so that a
 *	segment's header and its payload do not go out as two.  One record's
 *	worth is the most that gathering can save; past that the library
 *	would split the write anyway.					*/

#if MBEDTLS_SSL_OUT_CONTENT_LEN < 16384
#define TCPV4_TLS_CORK_BUFSZ	MBEDTLS_SSL_OUT_CONTENT_LEN
#else
#define TCPV4_TLS_CORK_BUFSZ	16384
#endif

/*	Ciphersuites named by -P.  TLS 1.3 defines five; the room here is
 *	for the operator who names them all and then some.		*/

#define TCPV4_MAX_SUITES	16

/*	RFC 9174 4.4.3 has the handshake follow BCP 195, which asks that
 *	TLS_AES_128_CCM_8_SHA256 - the one TLS 1.3 suite whose
 *	authentication tag is truncated, to 64 bits - not be negotiated
 *	(RFC 9325 4.2).  Mbed TLS offers every suite it was built with
 *	unless it is told otherwise, so this is that list without it, and
 *	is what a node without -P offers.  A suite the library was built
 *	without is skipped rather than refused, so naming them all here
 *	costs a lean build nothing.					*/

static const int defaultSuites[] = {
	MBEDTLS_TLS1_3_AES_256_GCM_SHA384,
	MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256,
	MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
	MBEDTLS_TLS1_3_AES_128_CCM_SHA256,
	0
};

struct Tcpv4TlsCreds
{
	mbedtls_ssl_config	 conf;
	mbedtls_entropy_context	 entropy;
	mbedtls_ctr_drbg_context drbg;
	mbedtls_x509_crt	 cert;	/*	Our own chain.		*/
	mbedtls_pk_context	 key;
	mbedtls_x509_crt	 ca;	/*	Trust anchors.		*/
	mbedtls_x509_crl	 crl;

	/*	Mbed TLS keeps the list rather than copying it, so it
	 *	lives as long as the configuration that cites it.	*/

	int			 suites[TCPV4_MAX_SUITES + 1];
};

/*	One per connection, and allocated from the process heap rather than
 *	from ION's working memory: it carries a record-sized gathering
 *	buffer, and Mbed TLS allocates its own record buffers from the heap
 *	beside it, so a node at its session limit (-L) would otherwise be
 *	spending a megabyte of a shared resource - sized once at node
 *	start-up - on TLS buffers.					*/

struct Tcpv4TlsConn
{
	mbedtls_ssl_context ssl;
	int		    sock;
	int		    peerAuthenticated;
	int		    isServer;	/* We are the passive entity.	*/
	time_t		    deadline;	/* Handshake only; 0 = none.	*/
	int		    corked;
	int		    corkLen;
	unsigned char	    corkBuf[TCPV4_TLS_CORK_BUFSZ];
};

/*	Render an Mbed TLS error for putErrmsg.  The codes are negative and
 *	the text is optional in a stripped-down build, so the number is
 *	always given as well.						*/

static char *tlsErr(int rc, char *into, int cap)
{
	char text[128];

#ifdef MBEDTLS_ERROR_C
	mbedtls_strerror(rc, text, sizeof text);
#else
	istrcpy(text, "no error text in this build", sizeof text);
#endif
	isprintf(into, cap, "-0x%04X: %s", (unsigned int) -rc, text);
	return into;
}

const char *tcpv4TlsBackend(void)
{
	return "Mbed TLS " MBEDTLS_VERSION_STRING;
}

/*	*	*	Credentials	*	*	*	*	*/

static void credsInit(Tcpv4TlsCreds *creds)
{
	memset(creds, 0, sizeof(*creds));
	mbedtls_ssl_config_init(&creds->conf);
	mbedtls_entropy_init(&creds->entropy);
	mbedtls_ctr_drbg_init(&creds->drbg);
	mbedtls_x509_crt_init(&creds->cert);
	mbedtls_pk_init(&creds->key);
	mbedtls_x509_crt_init(&creds->ca);
	mbedtls_x509_crl_init(&creds->crl);
}

static void credsDestroy(Tcpv4TlsCreds *creds)
{
	mbedtls_ssl_config_free(&creds->conf);
	mbedtls_x509_crl_free(&creds->crl);
	mbedtls_x509_crt_free(&creds->ca);
	mbedtls_pk_free(&creds->key);
	mbedtls_x509_crt_free(&creds->cert);
	mbedtls_ctr_drbg_free(&creds->drbg);
	mbedtls_entropy_free(&creds->entropy);
	MRELEASE(creds);
}

/*	Load the trust anchors the platform keeps, GnuTLS's system trust
 *	having no equivalent here.  Returns 0 once something was loaded.	*/

static int loadSystemTrust(Tcpv4TlsCreds *creds)
{
	int i;

	for (i = 0; systemTrustFiles[i] != NULL; i++)
	{
		if (mbedtls_x509_crt_parse_file(&creds->ca,
				systemTrustFiles[i]) >= 0
				&& creds->ca.version != 0)
		{
			return 0;
		}

		/*	A partly read bundle leaves what it did read in
		 *	place; start the next candidate from nothing.	*/

		mbedtls_x509_crt_free(&creds->ca);
		mbedtls_x509_crt_init(&creds->ca);
	}

	if (mbedtls_x509_crt_parse_path(&creds->ca, TCPV4_SYSTEM_TRUST_DIR) >= 0
			&& creds->ca.version != 0)
	{
		return 0;
	}

	putErrmsg("tcpv4cla: no system trust store found; name one with -C.",
			NULL);
	return -1;
}

/*	Apply -P, which under this backend names ciphersuites rather than
 *	carrying a GnuTLS priority string.  Returns 0 on success.	*/

static int setCiphersuites(Tcpv4TlsCreds *creds, const char *priority)
{
	char  copy[TCPV4_MAX_PRIORITY_LEN];
	char *state = NULL;
	char *cursor;
	int   count = 0;

	istrcpy(copy, priority, sizeof copy);
	for (cursor = strtok_r(copy, ":", &state); cursor != NULL;
			cursor = strtok_r(NULL, ":", &state))
	{
		int id;

		if (count == TCPV4_MAX_SUITES)
		{
			putErrmsg("tcpv4cla: too many TLS ciphersuites named.",
					(char *) priority);
			return -1;
		}

		id = mbedtls_ssl_get_ciphersuite_id(cursor);
		if (id == 0)
		{
			putErrmsg("tcpv4cla: unknown TLS ciphersuite.", cursor);
			return -1;
		}

		creds->suites[count++] = id;
	}

	if (count == 0)
	{
		putErrmsg("tcpv4cla: no TLS ciphersuite named.",
				(char *) priority);
		return -1;
	}

	creds->suites[count] = 0;
	mbedtls_ssl_conf_ciphersuites(&creds->conf, creds->suites);
	return 0;
}

Tcpv4TlsCreds *tcpv4TlsCredsNew(const Tcpv4ClaConfig *cfg, int isServer)
{
	Tcpv4TlsCreds *creds = MTAKE(sizeof(Tcpv4TlsCreds));
	char	       err[192];
	int	       rc;

	if (creds == NULL)
	{
		putErrmsg("tcpv4cla: no memory for TLS credentials.", NULL);
		return NULL;
	}

	credsInit(creds);

	/*	TLS 1.3 does its cryptography through the PSA interface,
	 *	which has to be started before any of it is asked for.	*/

	if (psa_crypto_init() != PSA_SUCCESS)
	{
		putErrmsg("tcpv4cla: can't initialize PSA crypto.", NULL);
		credsDestroy(creds);
		return NULL;
	}

	rc = mbedtls_ssl_config_defaults(&creds->conf,
			isServer ? MBEDTLS_SSL_IS_SERVER
				 : MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (rc != 0)
	{
		putErrmsg("tcpv4cla: can't set up TLS configuration.",
				tlsErr(rc, err, sizeof err));
		credsDestroy(creds);
		return NULL;
	}

	/*	RFC 9174 4.4.3 requires TLS 1.3, so no earlier version is
	 *	offered; -P chooses the ciphersuites within it, not the
	 *	protocol version.  Both entities authenticate with
	 *	certificates, which is the ephemeral key exchange mode; the
	 *	pre-shared key modes have no certificates to check.	*/

	mbedtls_ssl_conf_min_tls_version(&creds->conf, MBEDTLS_SSL_VERSION_TLS1_3);
	mbedtls_ssl_conf_max_tls_version(&creds->conf, MBEDTLS_SSL_VERSION_TLS1_3);
	mbedtls_ssl_conf_tls13_key_exchange_modes(&creds->conf,
			MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL);

	if (cfg->tlsPriority[0] == '\0')
	{
		mbedtls_ssl_conf_ciphersuites(&creds->conf, defaultSuites);
	}
	else if (setCiphersuites(creds, cfg->tlsPriority) < 0)
	{
		credsDestroy(creds);
		return NULL;
	}

	rc = mbedtls_ctr_drbg_seed(&creds->drbg, mbedtls_entropy_func,
			&creds->entropy, (const unsigned char *) "tcpv4cla", 8);
	if (rc != 0)
	{
		putErrmsg("tcpv4cla: can't seed TLS random generator.",
				tlsErr(rc, err, sizeof err));
		credsDestroy(creds);
		return NULL;
	}

	mbedtls_ssl_conf_rng(&creds->conf, mbedtls_ctr_drbg_random,
			&creds->drbg);

	if (cfg->caFile[0] != '\0')
	{
		rc = mbedtls_x509_crt_parse_file(&creds->ca, cfg->caFile);
		if (rc < 0 || creds->ca.version == 0)
		{
			putErrmsg("tcpv4cla: can't load CA file.",
					rc < 0 ? tlsErr(rc, err, sizeof err)
					       : (char *) cfg->caFile);
			credsDestroy(creds);
			return NULL;
		}
	}
	else if (loadSystemTrust(creds) < 0)
	{
		credsDestroy(creds);
		return NULL;
	}

	/*	RFC 9174 4.4.4.1 has the entity perform the certification
	 *	path validation of RFC 5280, of which checking whether the
	 *	issuer has withdrawn the certificate is a part (RFC 5280
	 *	6.3).  The RFC names OCSP as the way to ask that question
	 *	and puts the distribution of revocation lists outside its
	 *	scope (1.1), but a list is a file, and a file is something
	 *	a disconnected node can be given in advance - or carried
	 *	one over the DTN itself - where an OCSP responder is
	 *	something it may have no way to reach.			*/

	if (cfg->crlFile[0] != '\0')
	{
		rc = mbedtls_x509_crl_parse_file(&creds->crl, cfg->crlFile);

		/*	An operator who asked for revocation checking has
		 *	to be told when it is not happening: a file that
		 *	cannot be read, or that holds no list, leaves the
		 *	node believing it checks revocation when it does
		 *	not.  So this is fatal rather than a warning.	*/

		if (rc != 0 || creds->crl.version == 0)
		{
			putErrmsg("tcpv4cla: can't load CRL file.",
					rc != 0 ? tlsErr(rc, err, sizeof err)
						: (char *) cfg->crlFile);
			credsDestroy(creds);
			return NULL;
		}

		mbedtls_ssl_conf_ca_chain(&creds->conf, &creds->ca, &creds->crl);
	}
	else
	{
		mbedtls_ssl_conf_ca_chain(&creds->conf, &creds->ca, NULL);
	}

	/*	RFC 9174 4.4.3: the passive entity supplies a certificate
	 *	and the active entity supplies one in response to the
	 *	passive entity's certificate request, so both roles load
	 *	the same end-entity credentials.			*/

	if (cfg->certFile[0] != '\0' && cfg->keyFile[0] != '\0')
	{
		rc = mbedtls_x509_crt_parse_file(&creds->cert, cfg->certFile);
		if (rc == 0)
		{
			rc = mbedtls_pk_parse_keyfile(&creds->key, cfg->keyFile,
					NULL, mbedtls_ctr_drbg_random,
					&creds->drbg);
		}

		if (rc == 0)
		{
			rc = mbedtls_ssl_conf_own_cert(&creds->conf,
					&creds->cert, &creds->key);
		}

		if (rc != 0)
		{
			putErrmsg("tcpv4cla: can't load cert/key.",
					tlsErr(rc, err, sizeof err));
			credsDestroy(creds);
			return NULL;
		}
	}
	else if (isServer)
	{
		putErrmsg("tcpv4cla: TLS server role needs -c and -k.", NULL);
		credsDestroy(creds);
		return NULL;
	}

	/*	RFC 9174 4.4.3: "the passive entity SHALL request a
	 *	client-side certificate", which Mbed TLS does for any
	 *	authentication mode but NONE.  Without -n the peer must also
	 *	present one that validates, in either role - which checkPeer
	 *	decides rather than the handshake, for the reason given at
	 *	TCPV4_TLS_OUR_VERDICT.					*/

	mbedtls_ssl_conf_authmode(&creds->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	return creds;
}

void tcpv4TlsCredsFree(Tcpv4TlsCreds *creds)
{
	if (creds == NULL)
	{
		return;
	}

	credsDestroy(creds);
}

/*	*	*	Transport	*	*	*	*	*/

/*	Mbed TLS reads and writes the connection through these.  The socket
 *	is the session engine's, and blocking, so the only returns that
 *	matter are the ones an interrupted call makes.			*/

static int connSend(void *ctx, const unsigned char *from, size_t len)
{
	Tcpv4TlsConn *conn = (Tcpv4TlsConn *) ctx;
	ssize_t	      n;

#ifdef MSG_NOSIGNAL
	n = send(conn->sock, from, len, MSG_NOSIGNAL);
#else
	n = send(conn->sock, from, len, 0);
#endif
	if (n >= 0)
	{
		return (int) n;
	}

	if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
	{
		return MBEDTLS_ERR_SSL_WANT_WRITE;
	}

	if (errno == EPIPE || errno == ECONNRESET)
	{
		return MBEDTLS_ERR_NET_CONN_RESET;
	}

	return MBEDTLS_ERR_NET_SEND_FAILED;
}

static int connRecv(void *ctx, unsigned char *into, size_t len)
{
	Tcpv4TlsConn *conn = (Tcpv4TlsConn *) ctx;
	ssize_t	      n;

	for (;;)
	{
		if (conn->deadline != 0)
		{
			/*	Handshake in progress: a peer that stops
			 *	talking part way through one must not hold
			 *	the session's threads for ever.		*/

			struct pollfd pfd;
			time_t	      now = time(NULL);
			int	      rc;

			if (now >= conn->deadline)
			{
				return MBEDTLS_ERR_SSL_TIMEOUT;
			}

			pfd.fd = conn->sock;
			pfd.events = POLLIN;
			pfd.revents = 0;
			rc = poll(&pfd, 1, (int) (conn->deadline - now) * 1000);
			if (rc == 0)
			{
				return MBEDTLS_ERR_SSL_TIMEOUT;
			}

			if (rc < 0)
			{
				if (errno == EINTR)
				{
					continue;
				}

				return MBEDTLS_ERR_NET_RECV_FAILED;
			}
		}

		n = recv(conn->sock, into, len, 0);
		if (n >= 0)
		{
			return (int) n; /* 0 == end of stream.		*/
		}

		if (errno == EINTR)
		{
			continue;
		}

		if (errno == EAGAIN || errno == EWOULDBLOCK)
		{
			return MBEDTLS_ERR_SSL_WANT_READ;
		}

		if (errno == ECONNRESET)
		{
			return MBEDTLS_ERR_NET_CONN_RESET;
		}

		return MBEDTLS_ERR_NET_RECV_FAILED;
	}
}

/*	*	*	Handshake	*	*	*	*	*/

/*	Mbed TLS applies the web PKI's rule to the peer's extended key
 *	usage - id-kp-serverAuth of a server, id-kp-clientAuth of a client,
 *	and nothing else will do.  RFC 9174 4.4.2 asks for something
 *	different: a TCPCL certificate SHOULD carry id-kp-bundleSecurity
 *	and MAY carry the TLS purposes, so the very profile 4.4.5
 *	recommends names no TLS purpose at all, and that rule would refuse
 *	it.  The verdict on this one extension is therefore taken back
 *	from the library and left to tcpv4TlsCheckKeyPurpose below, which
 *	the session engine applies together with the -B policy; every
 *	other fault the library found still refuses the peer.
 *
 *	Taking it back means verifying alongside the handshake rather than
 *	within it, so a peer this node refuses completes a handshake
 *	before its connection is closed (RFC 9174 4.4.3).  Nothing but
 *	certificates, which are public, is exchanged in that handshake,
 *	and no TCPCL message follows one this node refuses.		*/

#define TCPV4_TLS_OUR_VERDICT MBEDTLS_X509_BADCERT_EXT_KEY_USAGE

/*	Say which of the checks of RFC 9174 4.4.4 refused the peer.  "TLS
 *	handshake failed" tells an operator nothing about that, and a
 *	withdrawn certificate in particular is a fact about the peer rather
 *	than about this node's configuration.				*/

static void reportVerdict(uint32_t flags, const char *hostName)
{
	char  info[256];
	char *cursor;

	if (flags & MBEDTLS_X509_BADCERT_REVOKED)
	{
		writeMemoNote("[?] tcpv4cla: peer's certificate has been"
			      " revoked by its issuer;", (char *) hostName);
	}

	if (mbedtls_x509_crt_verify_info(info, sizeof info, "", flags) < 1)
	{
		return;
	}

	/*	The rendering is one line per fault; ion.log takes one
	 *	line per note.						*/

	for (cursor = info; *cursor != '\0'; cursor++)
	{
		if (*cursor == '\n')
		{
			*cursor = ' ';
		}
	}

	writeMemoNote("[?] tcpv4cla: peer's certificate was refused;", info);
}

/*	The peer's certificate, as this node judges it once the handshake
 *	is over.  Returns 0 when the peer is authenticated, -1 when it is
 *	refused - in which case the caller closes the connection, there
 *	being no session yet to terminate (RFC 9174 4.4.3).		*/

static int checkPeer(Tcpv4TlsConn *conn, const char *hostName)
{
	uint32_t flags;

	if (mbedtls_ssl_get_peer_cert(&conn->ssl) == NULL)
	{
		putErrmsg("tcpv4cla: peer supplied no certificate.",
				(char *) hostName);
		return -1;
	}

	/*	The result is (uint32_t) -1 when no verification result is
	 *	available, which after a completed handshake means the
	 *	certificate was never weighed.  Every bit is then set, the
	 *	revocation bit included, so it is reported as the failure it
	 *	is rather than handed to reportVerdict, which would name a
	 *	revocation that never happened.				*/

	flags = mbedtls_ssl_get_verify_result(&conn->ssl);
	if (flags == (uint32_t) -1)
	{
		putErrmsg("tcpv4cla: peer's certificate was not verified.",
				(char *) hostName);
		return -1;
	}

	flags &= ~(uint32_t) TCPV4_TLS_OUR_VERDICT;
	if (flags == 0)
	{
		return 0;
	}

	reportVerdict(flags, hostName);
	return -1;
}

Tcpv4TlsConn *tcpv4TlsHandshake(const Tcpv4ClaConfig *cfg,
		Tcpv4TlsCreds *creds, int sock, int isServer,
		const char *hostName)
{
	Tcpv4TlsConn *conn;
	char	      err[192];
	int	      rc;

	conn = malloc(sizeof(Tcpv4TlsConn));
	if (conn == NULL)
	{
		putErrmsg("tcpv4cla: no memory for TLS session.", NULL);
		return NULL;
	}

	memset(conn, 0, sizeof(*conn));
	conn->sock = sock;
	conn->isServer = isServer;
	conn->deadline = time(NULL) + TCPV4_TLS_HANDSHAKE_SEC;
	mbedtls_ssl_init(&conn->ssl);
	rc = mbedtls_ssl_setup(&conn->ssl, &creds->conf);
	if (rc != 0)
	{
		putErrmsg("tcpv4cla: can't init TLS session.",
				tlsErr(rc, err, sizeof err));
		mbedtls_ssl_free(&conn->ssl);
		free(conn);
		return NULL;
	}

	if (!isServer)
	{
		/*	RFC 9174 4.4.3: the ClientHello carries the passive
		 *	entity's DNS name as server_name (never its node
		 *	ID), and that name is what the certificate is
		 *	checked against.  Saying so explicitly, NULL and
		 *	all, is what Mbed TLS asks of a client that means
		 *	to verify at all.				*/

		rc = mbedtls_ssl_set_hostname(&conn->ssl,
				(hostName != NULL && *hostName != '\0')
				? hostName : NULL);
		if (rc != 0)
		{
			putErrmsg("tcpv4cla: can't set TLS server name.",
					tlsErr(rc, err, sizeof err));
			mbedtls_ssl_free(&conn->ssl);
			free(conn);
			return NULL;
		}
	}

	mbedtls_ssl_set_bio(&conn->ssl, conn, connSend, connRecv, NULL);

	do
	{
		rc = mbedtls_ssl_handshake(&conn->ssl);
	} while (rc == MBEDTLS_ERR_SSL_WANT_READ
			|| rc == MBEDTLS_ERR_SSL_WANT_WRITE);

	if (rc != 0)
	{
		uint32_t flags = cfg->noVerify ? 0
				: mbedtls_ssl_get_verify_result(&conn->ssl);

		/*	Every bit is set when there is no verification
		 *	result at all - a handshake that failed before the
		 *	peer's certificate was ever weighed - so without
		 *	this guard any handshake failure whatever would
		 *	report the peer as revoked.			*/

		if (flags != 0 && flags != (uint32_t) -1)
		{
			reportVerdict(flags, hostName);
		}

		putErrmsg("tcpv4cla: TLS handshake failed.",
				tlsErr(rc, err, sizeof err));
		mbedtls_ssl_free(&conn->ssl);
		free(conn);
		return NULL;
	}

	conn->deadline = 0;	/*	Established; reads may block.	*/

	/*	Verification ran alongside the handshake rather than
	 *	stopping it, so the verdict is passed here.		*/

	conn->peerAuthenticated = 0;
	if (!cfg->noVerify)
	{
		if (checkPeer(conn, hostName) < 0)
		{
			mbedtls_ssl_free(&conn->ssl);
			free(conn);
			return NULL;
		}

		conn->peerAuthenticated = 1;
	}

	return conn;
}

/*	*	*	Records		*	*	*	*	*/

static int writeAll(Tcpv4TlsConn *conn, const unsigned char *from, int len)
{
	int sent = 0;

	while (sent < len)
	{
		int n = mbedtls_ssl_write(&conn->ssl, from + sent, len - sent);

		if (n > 0)
		{
			sent += n;
			continue;
		}

		/*	A write that could not proceed is retried with the
		 *	same octets, which is what Mbed TLS requires.	*/

		if (n == MBEDTLS_ERR_SSL_WANT_READ
				|| n == MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			continue;
		}

		return -1;
	}

	return 0;
}

static int flushCork(Tcpv4TlsConn *conn)
{
	int len = conn->corkLen;

	conn->corkLen = 0;
	if (len == 0)
	{
		return 0;
	}

	return writeAll(conn, conn->corkBuf, len);
}

int tcpv4TlsSend(Tcpv4TlsConn *conn, const void *data, int len)
{
	const unsigned char *from = (const unsigned char *) data;
	int		     sent = 0;

	if (conn == NULL || len < 0)
	{
		return -1;
	}

	if (!conn->corked)
	{
		return writeAll(conn, from, len) < 0 ? -1 : len;
	}

	while (sent < len)
	{
		int room = TCPV4_TLS_CORK_BUFSZ - conn->corkLen;
		int take;

		if (room == 0)
		{
			if (flushCork(conn) < 0)
			{
				return -1;
			}

			room = TCPV4_TLS_CORK_BUFSZ;
		}

		take = (len - sent < room) ? len - sent : room;
		memcpy(conn->corkBuf + conn->corkLen, from + sent, take);
		conn->corkLen += take;
		sent += take;
	}

	return len;
}

/*	Mbed TLS has no record corking of its own, so the pieces are
 *	gathered here and written as one.				*/

void tcpv4TlsCork(Tcpv4TlsConn *conn)
{
	if (conn != NULL)
	{
		conn->corked = 1;
	}
}

int tcpv4TlsUncork(Tcpv4TlsConn *conn)
{
	if (conn == NULL)
	{
		return -1;
	}

	conn->corked = 0;
	return flushCork(conn);
}

int tcpv4TlsRecv(Tcpv4TlsConn *conn, void *into, int len)
{
	for (;;)
	{
		int n = mbedtls_ssl_read(&conn->ssl, (unsigned char *) into,
				(size_t) len);

		if (n >= 0)
		{
			return n;
		}

		if (n == MBEDTLS_ERR_SSL_WANT_READ
				|| n == MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			continue;
		}

		/*	A TLS 1.3 peer may send a session ticket at any
		 *	time; it is not application data, and not an
		 *	error either.					*/

		if (n == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET)
		{
			continue;
		}

		if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
		{
			return 0; /* Orderly shutdown.			*/
		}

		if (n == MBEDTLS_ERR_SSL_CONN_EOF)
		{
			return 0; /* Peer vanished; treat as EOF.	*/
		}

		return -1;
	}
}

int tcpv4TlsPeerAuthenticated(Tcpv4TlsConn *conn)
{
	return conn == NULL ? 0 : conn->peerAuthenticated;
}

/*	*	*	Certificate profile	*	*	*	*/

/*	id-kp-bundleSecurity, the PKIX Extended Key Purpose RFC 9174 8.11
 *	registers for a certificate usable with TCPCL security, and which
 *	4.4.5 recommends requiring of one that carries an EKU at all.	*/
#define TCPV4_OID_BUNDLE_SECURITY MBEDTLS_OID_KP "\x23"

/*	The peer's end-entity certificate, which is the one whose extensions
 *	govern this handshake, or NULL when there is none.		*/

static const mbedtls_x509_crt *peerCert(Tcpv4TlsConn *conn)
{
	return conn == NULL ? NULL : mbedtls_ssl_get_peer_cert(&conn->ssl);
}

int tcpv4TlsCheckKeyPurpose(Tcpv4TlsConn *conn)
{
	const mbedtls_x509_crt	    *crt = peerCert(conn);
	const mbedtls_x509_sequence *cursor;
	const char		    *tlsPurpose;
	size_t			     tlsPurposeLen;
	int			     usable = 0;
	int			     forBundles = 0;

	if (crt == NULL)
	{
		return TCPV4_EKU_ERROR;
	}

	/*	An absent extension restricts nothing (RFC 5280 4.2.1.12);
	 *	Mbed TLS leaves the list empty in that case.		*/

	if (crt->ext_key_usage.buf.p == NULL)
	{
		return TCPV4_EKU_ABSENT;
	}

	/*	RFC 9174 4.4.3 makes the active entity the TLS client and
	 *	the passive entity the TLS server, so the purpose wanted of
	 *	the peer is the one for the role opposite ours.		*/

	if (conn->isServer)
	{
		tlsPurpose = MBEDTLS_OID_CLIENT_AUTH;
		tlsPurposeLen = MBEDTLS_OID_SIZE(MBEDTLS_OID_CLIENT_AUTH);
	}
	else
	{
		tlsPurpose = MBEDTLS_OID_SERVER_AUTH;
		tlsPurposeLen = MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH);
	}

	for (cursor = &crt->ext_key_usage; cursor != NULL;
			cursor = cursor->next)
	{
		const mbedtls_x509_buf *oid = &cursor->buf;

		if (oid->p == NULL)
		{
			break;
		}

		/*	anyExtendedKeyUsage leaves the certificate usable
		 *	for every purpose (RFC 5280 4.2.1.12), this one
		 *	included.					*/

		if (MBEDTLS_OID_CMP(MBEDTLS_OID_ANY_EXTENDED_KEY_USAGE, oid)
				== 0)
		{
			usable = 1;
			forBundles = 1;
			continue;
		}

		if (MBEDTLS_OID_CMP(TCPV4_OID_BUNDLE_SECURITY, oid) == 0)
		{
			usable = 1;
			forBundles = 1;
			continue;
		}

		if (oid->len == tlsPurposeLen
				&& memcmp(oid->p, tlsPurpose, tlsPurposeLen)
					== 0)
		{
			usable = 1;
		}
	}

	if (!usable)
	{
		return TCPV4_EKU_WRONG;
	}

	return forBundles ? TCPV4_EKU_PRESENT : TCPV4_EKU_NO_BUNDLE;
}

int tcpv4TlsCheckKeyUsage(Tcpv4TlsConn *conn)
{
	const mbedtls_x509_crt *crt = peerCert(conn);

	if (crt == NULL)
	{
		return TCPV4_KU_ERROR;
	}

	/*	mbedtls_x509_crt_check_key_usage answers "is this use
	 *	permitted", and an absent extension permits everything
	 *	(RFC 5280 4.2.1.3), so the two are told apart by asking the
	 *	certificate whether it carries the extension at all.	*/

	if (!tcpv4X509HasExtension(crt->v3_ext.p, crt->v3_ext.len,
			(const unsigned char *) MBEDTLS_OID_KEY_USAGE,
			MBEDTLS_OID_SIZE(MBEDTLS_OID_KEY_USAGE)))
	{
		return TCPV4_KU_ABSENT;
	}

	/*	RFC 9174 4.4.2 asks for digitalSignature, which is the bit
	 *	a TLS 1.3 handshake uses: every cipher suite it offers
	 *	authenticates the peer by a signature.			*/

	return mbedtls_x509_crt_check_key_usage(crt,
			MBEDTLS_X509_KU_DIGITAL_SIGNATURE) == 0
			? TCPV4_KU_OK : TCPV4_KU_WRONG;
}

/*	*	*	NODE-ID authentication	*	*	*	*/

/*	id-on-bundleEID, the PKIX Other Name Form RFC 9174 8.10 registers
 *	for a bundle endpoint ID.					*/
#define TCPV4_OID_BUNDLE_EID MBEDTLS_OID_PKIX "\x08\x0b"

int tcpv4TlsMatchNodeId(Tcpv4TlsConn *conn, const char *nodeId)
{
	const mbedtls_x509_crt	    *crt;
	const mbedtls_x509_sequence *cursor;
	int			     found = 0;

	if (conn == NULL || nodeId == NULL || *nodeId == '\0')
	{
		return TCPV4_NODEID_ERROR;
	}

	/*	Only the end-entity certificate identifies the entity
	 *	(RFC 9174 4.4.4.3).					*/

	crt = peerCert(conn);
	if (crt == NULL)
	{
		return TCPV4_NODEID_ERROR;
	}

	for (cursor = &crt->subject_alt_names; cursor != NULL;
			cursor = cursor->next)
	{
		const unsigned char *value;
		size_t		     valueLen;
		size_t		     off = 0;
		size_t		     oidLen;
		char		     uri[TCPV4_MAX_NODEID_LEN];

		if (cursor->buf.p == NULL)
		{
			break;
		}

		/*	A GeneralName is stored with its context tag; an
		 *	otherName is [0], and its content is the type OID
		 *	followed by the [0] EXPLICIT value (RFC 5280
		 *	4.2.1.6).					*/

		if ((cursor->buf.tag & (MBEDTLS_ASN1_TAG_CLASS_MASK
					| MBEDTLS_ASN1_TAG_VALUE_MASK))
				!= (MBEDTLS_ASN1_CONTEXT_SPECIFIC
					| MBEDTLS_X509_SAN_OTHER_NAME))
		{
			continue;
		}

		value = cursor->buf.p;
		valueLen = cursor->buf.len;
		if (valueLen < 2 || value[0] != MBEDTLS_ASN1_OID)
		{
			continue;
		}

		oidLen = value[1];
		if (oidLen > 0x7F || valueLen < 2 + oidLen)
		{
			continue; /* Not an OID short enough to be this one.*/
		}

		if (oidLen != MBEDTLS_OID_SIZE(TCPV4_OID_BUNDLE_EID)
				|| memcmp(value + 2, TCPV4_OID_BUNDLE_EID,
					oidLen) != 0)
		{
			continue;
		}

		off = 2 + oidLen;
		if (tcpv4X509BundleEid(value + off, valueLen - off, uri,
				sizeof uri) < 0)
		{
			continue; /* Malformed; not a NODE-ID we can use.*/
		}

		if (!tcpv4X509IsNodeId(uri))
		{
			continue;
		}

		found = 1;
		if (strcmp(uri, nodeId) == 0)
		{
			return TCPV4_NODEID_SUCCESS;
		}
	}

	return found ? TCPV4_NODEID_FAILURE : TCPV4_NODEID_ABSENT;
}

void tcpv4TlsClose(Tcpv4TlsConn *conn, int graceful)
{
	if (conn == NULL)
	{
		return;
	}

	if (graceful)
	{
		int rc;

		do
		{
			rc = mbedtls_ssl_close_notify(&conn->ssl);
		} while (rc == MBEDTLS_ERR_SSL_WANT_READ
				|| rc == MBEDTLS_ERR_SSL_WANT_WRITE);
	}

	mbedtls_ssl_free(&conn->ssl);
	free(conn);
}
