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

#define TCPV4_TLS_PRIORITY "SECURE128"

/*	RFC 9174 4.4.3 requires TLS 1.3, so the version restriction is
 *	appended to whatever the operator asked for rather than left to
 *	them: -P chooses the cipher policy, not the protocol version.	*/
#define TCPV4_TLS_VERSIONS "-VERS-ALL:+VERS-TLS1.3"

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
		int rc = gnutls_certificate_set_x509_trust_file(creds->cred,
				cfg->caFile, GNUTLS_X509_FMT_PEM);

		if (rc < 1) /* Negative on error, 0 if it held no CA.	*/
		{
			putErrmsg("tcpv4cla: can't load CA file.",
					rc < 0 ? (char *) gnutls_strerror(rc)
					       : (char *) cfg->caFile);
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
	char	      priority[TCPV4_MAX_PRIORITY_LEN + sizeof(TCPV4_TLS_VERSIONS)
			      + 1];
	int	      rc;

	isprintf(priority, sizeof(priority), "%s:%s",
			cfg->tlsPriority[0] == '\0' ? TCPV4_TLS_PRIORITY
						    : cfg->tlsPriority,
			TCPV4_TLS_VERSIONS);

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

	if (gnutls_priority_set_direct(conn->session, priority, &errPos)
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

/*	*	*	NODE-ID authentication	*	*	*	*/

/*	id-on-bundleEID, the PKIX Other Name Form RFC 9174 8.10 registers
 *	for a bundle endpoint ID.					*/
#define TCPV4_OID_BUNDLE_EID "1.3.6.1.5.5.7.8.11"

/*	Read one DER tag-length-value of the expected tag at *off.  On
 *	success *off is left at the first content octet and *vlen holds the
 *	content length.  Returns 0 on success, -1 otherwise.		*/

static int derTlv(const unsigned char *der, size_t len, size_t *off,
		unsigned char tag, size_t *vlen)
{
	size_t	      i = *off;
	size_t	      n;
	unsigned char b;

	if (i >= len || len - i < 2 || der[i] != tag)
	{
		return -1;
	}

	i++;
	b = der[i++];
	if (b < 0x80)
	{
		n = b;
	}
	else
	{
		unsigned int octets = b & 0x7F;

		if (octets == 0 || octets > sizeof(size_t) || len - i < octets)
		{
			return -1;
		}

		n = 0;
		while (octets-- > 0)
		{
			n = (n << 8) | der[i++];
		}
	}

	if (n > len - i)
	{
		return -1;
	}

	*off = i;
	*vlen = n;
	return 0;
}

/*	Extract the URI from a BundleEID otherName value.  RFC 9174
 *	4.4.2.1 encodes it as an IA5String; Appendix C shows it inside the
 *	[0] EXPLICIT wrapper of AnotherName's value field.  GnuTLS hands
 *	back the raw DER of that value for an OID it does not know, which
 *	across versions is either the wrapper or the IA5String alone, so
 *	accept both.  Returns 0 on success, -1 if the value is not an
 *	IA5String this code can read.					*/

static int bundleEidUri(const unsigned char *der, size_t len, char *into,
		size_t cap)
{
	size_t off = 0;
	size_t vlen;
	size_t end = len;

	if (derTlv(der, len, &off, 0xA0, &vlen) == 0)
	{
		end = off + vlen; /* Descend into the [0] wrapper.	*/
	}
	else
	{
		off = 0;
	}

	if (derTlv(der, end, &off, 0x16, &vlen) < 0) /* IA5String.	*/
	{
		return -1;
	}

	if (vlen == 0 || vlen >= cap)
	{
		return -1;
	}

	memcpy(into, der + off, vlen);
	into[vlen] = '\0';

	/*	A node ID is text; an embedded NUL would make the URI we
	 *	compare shorter than the one the certificate carries.	*/

	if (strlen(into) != vlen)
	{
		return -1;
	}

	return 0;
}

/*	RFC 9174 4.4.1: an entry whose value is some URI other than a node
 *	ID is ignored rather than counted as a failed NODE-ID.  A node ID
 *	is an endpoint ID that names a node and nothing on it: for ipn that
 *	is service number 0, for dtn an empty demux (RFC 9171 4.2.5).  A
 *	scheme this code has no rule for is left in play, so that an exact
 *	match still authenticates it.					*/

static int isNodeId(const char *uri)
{
	size_t len = strlen(uri);

	if (strncmp(uri, "ipn:", 4) == 0)
	{
		return len > 6 && strcmp(uri + len - 2, ".0") == 0;
	}

	if (strncmp(uri, "dtn:", 4) == 0)
	{
		return strcmp(uri, "dtn:none") == 0
				|| (len > 6 && uri[len - 1] == '/');
	}

	return 1;
}

int tcpv4TlsMatchNodeId(Tcpv4TlsConn *conn, const char *nodeId)
{
	const gnutls_datum_t *certs;
	gnutls_x509_crt_t     crt;
	unsigned int	      count = 0;
	unsigned int	      seq;
	int		      found = 0;
	int		      matched = 0;

	if (conn == NULL || nodeId == NULL || *nodeId == '\0')
	{
		return TCPV4_NODEID_ERROR;
	}

	certs = gnutls_certificate_get_peers(conn->session, &count);
	if (certs == NULL || count == 0)
	{
		return TCPV4_NODEID_ERROR;
	}

	if (gnutls_x509_crt_init(&crt) < 0)
	{
		return TCPV4_NODEID_ERROR;
	}

	/*	certs[0] is the peer's end-entity certificate; only that one
	 *	identifies the entity (RFC 9174 4.4.4.3).		*/

	if (gnutls_x509_crt_import(crt, &certs[0], GNUTLS_X509_FMT_DER) < 0)
	{
		gnutls_x509_crt_deinit(crt);
		return TCPV4_NODEID_ERROR;
	}

	for (seq = 0; !matched; seq++)
	{
		unsigned char value[512];
		char	      oid[128];
		char	      uri[TCPV4_MAX_NODEID_LEN];
		size_t	      valueLen = sizeof value;
		size_t	      oidLen = sizeof oid;
		unsigned int  type = 0;
		int	      rc;

		rc = gnutls_x509_crt_get_subject_alt_name2(crt, seq, value,
				&valueLen, &type, NULL);
		if (rc == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
		{
			break; /* End of the subjectAltName list.	*/
		}

		if (rc < 0 || type != GNUTLS_SAN_OTHERNAME)
		{
			/*	Too large to be a node ID, or some other
			 *	name form; either way, not a NODE-ID.	*/

			continue;
		}

		if (gnutls_x509_crt_get_subject_alt_othername_oid(crt, seq, oid,
				    &oidLen)
				< 0)
		{
			continue;
		}

		if (strcmp(oid, TCPV4_OID_BUNDLE_EID) != 0)
		{
			continue;
		}

		if (bundleEidUri(value, valueLen, uri, sizeof uri) < 0)
		{
			continue; /* Malformed; not a NODE-ID we can use.*/
		}

		if (!isNodeId(uri))
		{
			continue;
		}

		found = 1;
		if (strcmp(uri, nodeId) == 0)
		{
			matched = 1;
		}
	}

	gnutls_x509_crt_deinit(crt);
	if (matched)
	{
		return TCPV4_NODEID_SUCCESS;
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
		oK(gnutls_bye(conn->session, GNUTLS_SHUT_WR));
	}

	gnutls_deinit(conn->session);
	MRELEASE(conn);
}
