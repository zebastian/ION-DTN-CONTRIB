/*
	quictls_gnutls.c:	GnuTLS backend for the QUIC convergence
				layer (see quictls.h).
									*/

#include "quictls.h"
#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

struct QuicTlsCreds
{
	gnutls_certificate_credentials_t cred;
};

struct QuicTlsConn
{
	gnutls_session_t session;
};

int quicTlsRand(void *buf, size_t len)
{
	return gnutls_rnd(GNUTLS_RND_RANDOM, buf, len) == 0 ? 0 : -1;
}

QuicTlsCreds *quicTlsCredsNew(const QuicClaConfig *cfg, int isServer)
{
	QuicTlsCreds *creds = MTAKE(sizeof(QuicTlsCreds));

	if (creds == NULL)
	{
		return NULL;
	}

	if (gnutls_certificate_allocate_credentials(&creds->cred) != 0)
	{
		MRELEASE(creds);
		return NULL;
	}

	if (cfg->caFile[0] != '\0')
	{
		gnutls_certificate_set_x509_trust_file(creds->cred, cfg->caFile,
				GNUTLS_X509_FMT_PEM);
	}
	else if (!isServer)
	{
		gnutls_certificate_set_x509_system_trust(creds->cred);
	}

	if (cfg->certFile[0] != '\0' && cfg->keyFile[0] != '\0')
	{
		if (gnutls_certificate_set_x509_key_file(creds->cred,
				    cfg->certFile, cfg->keyFile,
				    GNUTLS_X509_FMT_PEM)
				!= 0
				&& isServer)
		{
			putErrmsg("quiccli: can't load cert/key.", NULL);
			gnutls_certificate_free_credentials(creds->cred);
			MRELEASE(creds);
			return NULL;
		}
	}

	return creds;
}

void quicTlsCredsFree(QuicTlsCreds *creds)
{
	if (creds == NULL)
	{
		return;
	}

	gnutls_certificate_free_credentials(creds->cred);
	MRELEASE(creds);
}

QuicTlsConn *quicTlsConnNew(const QuicClaConfig *cfg, QuicTlsCreds *creds,
		ngtcp2_crypto_conn_ref *connRef, int isServer)
{
	QuicTlsConn   *conn = MTAKE(sizeof(QuicTlsConn));
	gnutls_datum_t alpn;
	int	       rc;

	if (conn == NULL)
	{
		return NULL;
	}

	if (gnutls_init(&conn->session, isServer ? GNUTLS_SERVER : GNUTLS_CLIENT)
			!= 0)
	{
		MRELEASE(conn);
		return NULL;
	}

	rc = isServer
			? ngtcp2_crypto_gnutls_configure_server_session(
					  conn->session)
			: ngtcp2_crypto_gnutls_configure_client_session(
					  conn->session);
	if (rc != 0)
	{
		gnutls_deinit(conn->session);
		MRELEASE(conn);
		return NULL;
	}

	gnutls_set_default_priority(conn->session);
	gnutls_credentials_set(conn->session, GNUTLS_CRD_CERTIFICATE,
			creds->cred);

	if (!isServer)
	{
		gnutls_server_name_set(conn->session, GNUTLS_NAME_DNS, cfg->host,
				strlen(cfg->host));
		if (!cfg->noVerify)
		{
			gnutls_session_set_verify_cert(conn->session, cfg->host,
					0);
		}
	}

	alpn.data = (unsigned char *) cfg->alpn;
	alpn.size = strlen(cfg->alpn);
	gnutls_alpn_set_protocols(conn->session, &alpn, 1, 0);

	gnutls_session_set_ptr(conn->session, connRef);
	return conn;
}

void quicTlsConnFree(QuicTlsConn *conn)
{
	if (conn == NULL)
	{
		return;
	}

	gnutls_deinit(conn->session);
	MRELEASE(conn);
}

void *quicTlsNativeHandle(QuicTlsConn *conn)
{
	return conn->session;
}
