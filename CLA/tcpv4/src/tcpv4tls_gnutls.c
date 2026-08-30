/*
	tcpv4tls_gnutls.c:	GnuTLS backend for the TCPCLv4 convergence
				layer (see tcpv4tls.h).
									*/

#include "tcpv4tls.h"
#include <errno.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

/*	RFC 9174 4.4.3 requires the handshake to be TLS 1.3 ([RFC8446]) and
 *	to follow BCP 195, so no earlier version is offered.		*/

#define TCPV4_TLS_PRIORITY "SECURE128:-VERS-ALL:+VERS-TLS1.3"

struct Tcpv4TlsCreds
{
	gnutls_certificate_credentials_t cred;
};

struct Tcpv4TlsConn
{
	gnutls_session_t session;
	int		 peerAuthenticated;
};

Tcpv4TlsCreds *tcpv4TlsCredsNew(const Tcpv4ClaConfig *cfg, int isServer)
{
	Tcpv4TlsCreds *creds = MTAKE(sizeof(Tcpv4TlsCreds));

	if (creds == NULL)
	{
		putErrmsg("tcpv4cla: no memory for TLS credentials.", NULL);
		return NULL;
	}

	if (gnutls_certificate_allocate_credentials(&creds->cred) != 0)
	{
		putErrmsg("tcpv4cla: can't allocate TLS credentials.", NULL);
		MRELEASE(creds);
		return NULL;
	}

	if (cfg->caFile[0] != '\0')
	{
		if (gnutls_certificate_set_x509_trust_file(creds->cred,
				    cfg->caFile, GNUTLS_X509_FMT_PEM)
				< 0)
		{
			putErrmsg("tcpv4cla: can't load CA file.",
					(char *) cfg->caFile);
			gnutls_certificate_free_credentials(creds->cred);
			MRELEASE(creds);
			return NULL;
		}
	}
	else
	{
		gnutls_certificate_set_x509_system_trust(creds->cred);
	}

	/*	RFC 9174 4.4.3: the passive entity supplies a certificate
	 *	and the active entity supplies one in response to the
	 *	passive entity's certificate request, so both roles load
	 *	the same end-entity credentials.			*/

	if (cfg->certFile[0] != '\0' && cfg->keyFile[0] != '\0')
	{
		if (gnutls_certificate_set_x509_key_file(creds->cred,
				    cfg->certFile, cfg->keyFile,
				    GNUTLS_X509_FMT_PEM)
				!= 0)
		{
			putErrmsg("tcpv4cla: can't load cert/key.",
					(char *) cfg->certFile);
			gnutls_certificate_free_credentials(creds->cred);
			MRELEASE(creds);
			return NULL;
		}
	}
	else if (isServer)
	{
		putErrmsg("tcpv4cla: TLS server role needs -c and -k.", NULL);
		gnutls_certificate_free_credentials(creds->cred);
		MRELEASE(creds);
		return NULL;
	}

	return creds;
}

void tcpv4TlsCredsFree(Tcpv4TlsCreds *creds)
{
	if (creds == NULL)
	{
		return;
	}

	gnutls_certificate_free_credentials(creds->cred);
	MRELEASE(creds);
}

Tcpv4TlsConn *tcpv4TlsHandshake(const Tcpv4ClaConfig *cfg,
		Tcpv4TlsCreds *creds, int sock, int isServer,
		const char *hostName)
{
	Tcpv4TlsConn *conn;
	const char   *errPos = NULL;
	int	      rc;

	conn = MTAKE(sizeof(Tcpv4TlsConn));
	if (conn == NULL)
	{
		putErrmsg("tcpv4cla: no memory for TLS session.", NULL);
		return NULL;
	}

	memset(conn, 0, sizeof(*conn));
	if (gnutls_init(&conn->session,
			    isServer ? GNUTLS_SERVER : GNUTLS_CLIENT)
			!= 0)
	{
		putErrmsg("tcpv4cla: can't init TLS session.", NULL);
		MRELEASE(conn);
		return NULL;
	}

	if (gnutls_priority_set_direct(conn->session, TCPV4_TLS_PRIORITY,
			    &errPos)
			!= 0)
	{
		putErrmsg("tcpv4cla: bad TLS priority string.",
				(char *) errPos);
		gnutls_deinit(conn->session);
		MRELEASE(conn);
		return NULL;
	}

	gnutls_credentials_set(conn->session, GNUTLS_CRD_CERTIFICATE,
			creds->cred);

	if (isServer)
	{
		/*	RFC 9174 4.4.3: "the passive entity SHALL request
		 *	a client-side certificate".  Without -n the peer
		 *	must also present one that validates.		*/

		gnutls_certificate_server_set_request(conn->session,
				cfg->noVerify ? GNUTLS_CERT_REQUEST
					      : GNUTLS_CERT_REQUIRE);
		if (!cfg->noVerify)
		{
			gnutls_session_set_verify_cert(conn->session, NULL, 0);
		}
	}
	else
	{
		/*	RFC 9174 4.4.3: the ClientHello carries the passive
		 *	entity's DNS name as server_name (never its node
		 *	ID), and that name is what the certificate is
		 *	checked against.				*/

		if (hostName != NULL && *hostName != '\0')
		{
			gnutls_server_name_set(conn->session, GNUTLS_NAME_DNS,
					hostName, strlen(hostName));
		}

		if (!cfg->noVerify)
		{
			gnutls_session_set_verify_cert(conn->session, hostName,
					0);
		}
	}

	gnutls_transport_set_int(conn->session, sock);
	gnutls_handshake_set_timeout(conn->session,
			GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

	do
	{
		rc = gnutls_handshake(conn->session);
	} while (rc < 0 && gnutls_error_is_fatal(rc) == 0);

	if (rc < 0)
	{
		putErrmsg("tcpv4cla: TLS handshake failed.",
				(char *) gnutls_strerror(rc));
		gnutls_deinit(conn->session);
		MRELEASE(conn);
		return NULL;
	}

	/*	With verification enabled the handshake itself fails on an
	 *	untrusted peer, so reaching here with a peer certificate
	 *	present means the peer is authenticated.		*/

	conn->peerAuthenticated = 0;
	if (!cfg->noVerify)
	{
		unsigned int	     count = 0;
		const gnutls_datum_t *certs;

		certs = gnutls_certificate_get_peers(conn->session, &count);
		conn->peerAuthenticated = (certs != NULL && count > 0);
	}

	return conn;
}

int tcpv4TlsSend(Tcpv4TlsConn *conn, const void *data, int len)
{
	const char *from = (const char *) data;
	int	    sent = 0;

	while (sent < len)
	{
		ssize_t n = gnutls_record_send(conn->session, from + sent,
				len - sent);

		if (n > 0)
		{
			sent += (int) n;
			continue;
		}

		if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED)
		{
			continue;
		}

		return -1;
	}

	return len;
}

void tcpv4TlsCork(Tcpv4TlsConn *conn)
{
	gnutls_record_cork(conn->session);
}

int tcpv4TlsUncork(Tcpv4TlsConn *conn)
{
	for (;;)
	{
		int rc = gnutls_record_uncork(conn->session, GNUTLS_RECORD_WAIT);

		if (rc >= 0)
		{
			return 0;
		}

		if (rc == GNUTLS_E_AGAIN || rc == GNUTLS_E_INTERRUPTED)
		{
			continue;
		}

		return -1;
	}
}

int tcpv4TlsRecv(Tcpv4TlsConn *conn, void *into, int len)
{
	for (;;)
	{
		ssize_t n = gnutls_record_recv(conn->session, into, len);

		if (n >= 0)
		{
			return (int) n; /* 0 == orderly shutdown.	*/
		}

		if (n == GNUTLS_E_AGAIN || n == GNUTLS_E_INTERRUPTED)
		{
			continue;
		}

		if (n == GNUTLS_E_PREMATURE_TERMINATION)
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

void tcpv4TlsClose(Tcpv4TlsConn *conn, int graceful)
{
	if (conn == NULL)
	{
		return;
	}

	if (graceful)
	{
		oK(gnutls_bye(conn->session, GNUTLS_SHUT_WR));
	}

	gnutls_deinit(conn->session);
	MRELEASE(conn);
}
