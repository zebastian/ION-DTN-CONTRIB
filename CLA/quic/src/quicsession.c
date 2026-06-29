/*
	quicsession.c:	ngtcp2 + GnuTLS QUIC engine for the QUIC CLA.
			Implements a single-connection client (quicclo) and
			a multi-connection server (quiccli) carrying
			length-prefixed bundles on one bidirectional stream
			per connection.
								*/

#include "quicsession.h"
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include "quicmsg.h"
#include "quictls.h"

#define QUIC_MAX_UDP 1452 /* Conservative QUIC datagram.	*/

typedef struct QuicConn
{
	struct QuicConn	       *next;
	QuicSession	       *owner;
	ngtcp2_conn	       *conn;
	QuicTlsConn	       *tls;
	ngtcp2_crypto_conn_ref	connRef;
	ngtcp2_cid		scid; /* our source CID (demux key).	*/
	struct sockaddr_storage remote;
	socklen_t		remoteLen;
	struct sockaddr_storage local;
	socklen_t		localLen;
	int64_t			streamId; /* data stream; -1 until open.	*/
	int			handshakeDone;
	int			failed;

	/*	QUICCL session state (draft-caini-dtn-quiccl).		*/
	int	      sessState;      /* QSS_*			*/
	int	      sessInitSent;   /* our SESS_INIT queued.	*/
	int	      termSent;	      /* our SESS_TERM queued.	*/
	uint16_t      keepalive;      /* negotiated, seconds.	*/
	uint64_t      peerSegmentMru; /* peer's advertised segment MRU.	*/
	uint64_t      peerTransferMru;
	ngtcp2_tstamp lastTx; /* last stream-data send (keepalive timer).*/

	/*	Stream-0 signalling send channel (conn-owned bytes).	*/
	unsigned char *sigTx;
	int	       sigTxLen;
	int	       sigTxOff;
	int	       sigTxCap;

	/*	Stream-0 signalling receive reassembly.			*/
	unsigned char *sigRx;
	int	       sigRxLen;
	int	       sigRxCap;

	/*	Client data-stream send (single in-flight framed bundle).*/
	const unsigned char *sendData;
	int		     sendLen;
	int		     sendOff;
	int		     sendDone;

	/*	Reassembly of the inbound data stream.			*/
	unsigned char *rxBuf;
	int	       rxCap;
	int	       rxLen;
} QuicConn;

/*	QUICCL session states.						*/
#define QSS_CONNECTING	  0 /* QUIC up, SESS_INIT not yet exchanged.	*/
#define QSS_ESTABLISHED	  1 /* SESS_INIT exchanged both ways.		*/
#define QSS_ENDING	  2 /* SESS_TERM exchanged; closing.		*/

/*	Stream 0 carries all signalling; bundle data uses a separate
 *	client-initiated bidirectional stream.				*/
#define QUICCL_SIG_STREAM 0

struct QuicSession
{
	int	      fd;
	int	      isServer;
	QuicClaConfig cfg;
	QuicTlsCreds *creds;

	/*	Client.							*/
	QuicConn       *client;
	pthread_t	ioThread;
	pthread_mutex_t mutex;
	pthread_cond_t	cond;
	int		running;
	int		wakePipe[2];

	/*	Server.							*/
	QuicConn    *conns;
	QuicBundleCb cb;
	void	    *cbUser;
};

/*	*	*	Time helpers	*	*	*	*	*/

static ngtcp2_tstamp quicNow(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ngtcp2_tstamp) ts.tv_sec * NGTCP2_SECONDS
			+ (ngtcp2_tstamp) ts.tv_nsec;
}

/*	*	*	ngtcp2 callbacks	*	*	*	*/

static ngtcp2_conn *getConnRef(ngtcp2_crypto_conn_ref *ref)
{
	QuicConn *qc = ref->user_data;

	return qc->conn;
}

static void randCb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
	(void) rand_ctx;
	oK(quicTlsRand(dest, destlen));
}

static int getNewCidCb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token,
		size_t cidlen, void *user_data)
{
	(void) conn;
	(void) user_data;
	if (quicTlsRand(cid->data, cidlen) != 0)
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	cid->datalen = cidlen;
	if (quicTlsRand(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 0)
	{
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int handshakeDoneCb(ngtcp2_conn *conn, void *user_data)
{
	QuicConn *qc = user_data;

	(void) conn;
	qc->handshakeDone = 1;
	return 0;
}

/*	*	*	QUICCL session layer	*	*	*	*/

/*	Append signalling bytes to the conn's stream-0 send channel.  The
 *	buffer is append-only for the connection's lifetime (signalling
 *	volume is tiny) so the bytes stay valid until ngtcp2 acks them.	*/

static int sigQueue(QuicConn *qc, const unsigned char *bytes, int len)
{
	QuicSession *s = qc->owner;
	int	     rc = 0;

	pthread_mutex_lock(&s->mutex);
	if (qc->sigTxLen + len > qc->sigTxCap)
	{
		int	       newCap = qc->sigTxCap ? qc->sigTxCap : 256;
		unsigned char *nb;

		while (newCap < qc->sigTxLen + len)
		{
			newCap *= 2;
		}

		nb = MTAKE(newCap);
		if (nb == NULL)
		{
			rc = -1;
		}
		else
		{
			if (qc->sigTxLen > 0)
			{
				memcpy(nb, qc->sigTx, qc->sigTxLen);
			}

			if (qc->sigTx)
			{
				MRELEASE(qc->sigTx);
			}

			qc->sigTx = nb;
			qc->sigTxCap = newCap;
		}
	}

	if (rc == 0)
	{
		memcpy(qc->sigTx + qc->sigTxLen, bytes, len);
		qc->sigTxLen += len;
	}

	pthread_mutex_unlock(&s->mutex);
	return rc;
}

/*	Build and queue this entity's SESS_INIT on stream 0.		*/

static int sendSessInit(QuicConn *qc)
{
	QuicSession  *s = qc->owner;
	QuicSessInit  init;
	unsigned char out[128];
	char	      nodeId[32];
	int	      n;

	memset(&init, 0, sizeof(init));

	/*	Offer a keepalive interval comfortably below the QUIC idle
	 *	timeout (cfg.idleSec) so the session stays live when idle.	*/

	init.keepalive = (uint16_t) (s->cfg.idleSec > 1 ? s->cfg.idleSec / 2 : 1);
	init.segmentMru = QUICCLA_BUFSZ;
	init.datagramMru = 0;
	init.transferMru = QUICCLA_BUFSZ;
	isprintf(nodeId, sizeof(nodeId), "ipn:" UVAST_FIELDSPEC ".0",
			getOwnFqnn());
	init.nodeId = (const uint8_t *) nodeId;
	init.nodeIdLen = (uint16_t) strlen(nodeId);

	n = quicMsgEncodeSessInit(out, sizeof(out), &init);
	if (n < 0)
	{
		return -1;
	}

	qc->sessInitSent = 1;
	qc->lastTx = quicNow();
	return sigQueue(qc, out, n);
}

/*	Adopt the negotiated session parameters from the peer's SESS_INIT
 *	(keepalive = min of the two; MRUs as advertised by the receiver).*/

static void sessNegotiate(QuicConn *qc, const QuicSessInit *peer)
{
	int	 idle = qc->owner->cfg.idleSec;
	uint16_t ours = (uint16_t) (idle > 1 ? idle / 2 : 1);

	qc->keepalive = peer->keepalive < ours ? peer->keepalive : ours;
	qc->peerSegmentMru = peer->segmentMru;
	qc->peerTransferMru = peer->transferMru;
}

static int handleSessInit(QuicConn *qc, const QuicSessInit *peer)
{
	QuicSession *s = qc->owner;

	sessNegotiate(qc, peer);

	/*	The passive entity (server) replies with its own SESS_INIT.*/

	if (s->isServer && !qc->sessInitSent)
	{
		if (sendSessInit(qc) < 0)
		{
			return -1;
		}
	}

	pthread_mutex_lock(&s->mutex);
	qc->sessState = QSS_ESTABLISHED;
	pthread_cond_broadcast(&s->cond);
	pthread_mutex_unlock(&s->mutex);
	return 0;
}

static int sendKeepalive(QuicConn *qc)
{
	unsigned char out[1];
	int	      n = quicMsgEncodeKeepalive(out, sizeof(out));

	return n < 0 ? -1 : sigQueue(qc, out, n);
}

static int sendSessTerm(QuicConn *qc, uint8_t reason, int reply)
{
	QuicSessTerm  term;
	unsigned char out[16];
	int	      n;

	memset(&term, 0, sizeof(term));
	term.flags = reply ? QMSG_TERM_FLAG_REPLY : 0;
	term.reason = reason;
	n = quicMsgEncodeSessTerm(out, sizeof(out), &term);
	if (n < 0)
	{
		return -1;
	}

	qc->termSent = 1;
	return sigQueue(qc, out, n);
}

static int sendMsgReject(QuicConn *qc, uint8_t rejectedType, uint8_t reason)
{
	QuicMsgReject rej;
	unsigned char out[8];
	int	      n;

	rej.rejectedType = rejectedType;
	rej.reason = reason;
	n = quicMsgEncodeMsgReject(out, sizeof(out), &rej);
	return n < 0 ? -1 : sigQueue(qc, out, n);
}

/*	Send a KEEPALIVE on stream 0 once the negotiated keepalive interval
 *	elapses with no stream-data transmission (i.e. the session is idle).
 *	Called once per I/O loop iteration.				*/

static void sessionTick(QuicConn *qc)
{
	ngtcp2_tstamp now = quicNow();

	if (qc->sessState == QSS_ESTABLISHED && qc->keepalive > 0
			&& now - qc->lastTx >= (ngtcp2_tstamp) qc->keepalive
							* NGTCP2_SECONDS)
	{
		oK(sendKeepalive(qc));
		qc->lastTx = now;
	}
}

/*	Parse and dispatch complete signalling messages buffered from
 *	stream 0.  Returns 0 on success, -1 on a fatal protocol error.	*/

static int sessParseSig(QuicConn *qc)
{
	int off = 0;

	while (off < qc->sigRxLen)
	{
		const uint8_t *p = qc->sigRx + off;
		int	       avail = qc->sigRxLen - off;
		int	       type = quicMsgType(p, avail);
		int	       n;

		if (type == QMSG_SESS_INIT)
		{
			QuicSessInit init;

			n = quicMsgDecodeSessInit(p, avail, &init);
			if (n == 0)
			{
				break; /* Need more octets.		*/
			}

			if (n < 0 || handleSessInit(qc, &init) < 0)
			{
				return -1;
			}
		}
		else if (type == QMSG_KEEPALIVE)
		{
			n = 1;
		}
		else if (type == QMSG_SESS_TERM)
		{
			QuicSessTerm term;

			n = quicMsgDecodeSessTerm(p, avail, &term);
			if (n == 0)
			{
				break;
			}

			if (n < 0)
			{
				return -1;
			}

			qc->sessState = QSS_ENDING;
			if (!qc->termSent)
			{
				oK(sendSessTerm(qc, QMSG_TERM_UNKNOWN, 1));
			}
		}
		else if (type == QMSG_MSG_REJECT)
		{
			QuicMsgReject rej;

			n = quicMsgDecodeMsgReject(p, avail, &rej);
			if (n == 0)
			{
				break;
			}

			if (n < 0)
			{
				return -1;
			}
		}
		else
		{
			/*	Unexpected/unknown message: reject and, since
			 *	we cannot determine its length to resync,
			 *	treat it as fatal.			*/

			oK(sendMsgReject(qc, (uint8_t) type,
					QMSG_REJECT_UNSUPPORTED));
			return -1;
		}

		off += n;
	}

	if (off > 0)
	{
		memmove(qc->sigRx, qc->sigRx + off, qc->sigRxLen - off);
		qc->sigRxLen -= off;
	}

	return 0;
}

/*	Append received stream-0 octets to the signalling reassembly
 *	buffer, then parse out whole messages.				*/

static int sessRecvSig(QuicConn *qc, const uint8_t *data, size_t datalen)
{
	if (qc->sigRxLen + (int) datalen > qc->sigRxCap)
	{
		int	       newCap = qc->sigRxCap ? qc->sigRxCap : 256;
		unsigned char *nb;

		while (newCap < qc->sigRxLen + (int) datalen)
		{
			newCap *= 2;
		}

		nb = MTAKE(newCap);
		if (nb == NULL)
		{
			return -1;
		}

		if (qc->sigRxLen > 0)
		{
			memcpy(nb, qc->sigRx, qc->sigRxLen);
		}

		if (qc->sigRx)
		{
			MRELEASE(qc->sigRx);
		}

		qc->sigRx = nb;
		qc->sigRxCap = newCap;
	}

	memcpy(qc->sigRx + qc->sigRxLen, data, datalen);
	qc->sigRxLen += (int) datalen;
	return sessParseSig(qc);
}

/*	Append received stream bytes and extract whole length-prefixed
 *	bundles, delivering each via the session callback.		*/

static int deliverBundles(QuicConn *qc)
{
	QuicSession *s = qc->owner;
	int	     off = 0;

	while (qc->rxLen - off >= QUIC_LEN_PREFIX)
	{
		unsigned char *p = qc->rxBuf + off;
		uint32_t blen = ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
				| ((uint32_t) p[2] << 8) | (uint32_t) p[3];

		if (blen == 0 || blen > QUICCLA_BUFSZ)
		{
			return -1; /* Framing error.		*/
		}

		if (qc->rxLen - off - QUIC_LEN_PREFIX < (int) blen)
		{
			break; /* Bundle not complete yet.	*/
		}

		if (s->cb && s->cb(s->cbUser, p + QUIC_LEN_PREFIX, (int) blen) < 0)
		{
			return -1;
		}

		off += QUIC_LEN_PREFIX + (int) blen;
	}

	if (off > 0)
	{
		memmove(qc->rxBuf, qc->rxBuf + off, qc->rxLen - off);
		qc->rxLen -= off;
	}

	return 0;
}

static int recvStreamDataCb(ngtcp2_conn *conn, uint32_t flags,
		int64_t stream_id, uint64_t offset, const uint8_t *data,
		size_t datalen, void *user_data, void *stream_user_data)
{
	QuicConn *qc = user_data;

	(void) conn;
	(void) flags;
	(void) offset;
	(void) stream_user_data;

	if (datalen > 0 && stream_id == QUICCL_SIG_STREAM)
	{
		/*	Stream 0 carries QUICCL signalling.		*/

		if (sessRecvSig(qc, data, datalen) < 0)
		{
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}
	}
	else if (datalen > 0)
	{
		/*	Any other stream carries bundle data.		*/

		if (qc->rxLen + (int) datalen > qc->rxCap)
		{
			int	       newCap = qc->rxCap * 2;
			unsigned char *nb;

			while (newCap < qc->rxLen + (int) datalen)
			{
				newCap *= 2;
			}

			nb = MTAKE(newCap);
			if (nb == NULL)
			{
				return NGTCP2_ERR_CALLBACK_FAILURE;
			}

			memcpy(nb, qc->rxBuf, qc->rxLen);
			MRELEASE(qc->rxBuf);
			qc->rxBuf = nb;
			qc->rxCap = newCap;
		}

		memcpy(qc->rxBuf + qc->rxLen, data, datalen);
		qc->rxLen += (int) datalen;

		if (deliverBundles(qc) < 0)
		{
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}
	}

	ngtcp2_conn_extend_max_offset(conn, datalen);
	ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
	return 0;
}

static int ackedOffsetCb(ngtcp2_conn *conn, int64_t stream_id, uint64_t offset,
		uint64_t datalen, void *user_data, void *stream_user_data)
{
	(void) conn;
	(void) stream_id;
	(void) offset;
	(void) datalen;
	(void) user_data;
	(void) stream_user_data;
	return 0;
}

static void setCallbacks(ngtcp2_callbacks *cb, int isServer)
{
	memset(cb, 0, sizeof(*cb));

	if (isServer)
	{
		cb->recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
	}
	else
	{
		cb->client_initial = ngtcp2_crypto_client_initial_cb;
		cb->recv_retry = ngtcp2_crypto_recv_retry_cb;
	}

	cb->recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
	cb->encrypt = ngtcp2_crypto_encrypt_cb;
	cb->decrypt = ngtcp2_crypto_decrypt_cb;
	cb->hp_mask = ngtcp2_crypto_hp_mask_cb;
	cb->update_key = ngtcp2_crypto_update_key_cb;
	cb->delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
	cb->delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
	cb->get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
	cb->version_negotiation = ngtcp2_crypto_version_negotiation_cb;

	cb->handshake_completed = handshakeDoneCb;
	cb->recv_stream_data = recvStreamDataCb;
	cb->acked_stream_data_offset = ackedOffsetCb;
	cb->rand = randCb;
	cb->get_new_connection_id = getNewCidCb;
}

static void defaultTransportParams(const QuicClaConfig *cfg,
		ngtcp2_transport_params		       *params)
{
	ngtcp2_transport_params_default(params);
	params->initial_max_streams_bidi = 8;
	params->initial_max_streams_uni = 0;
	params->initial_max_stream_data_bidi_local = QUICCLA_BUFSZ;
	params->initial_max_stream_data_bidi_remote = QUICCLA_BUFSZ;
	params->initial_max_data = QUICCLA_BUFSZ * 4;
	params->max_idle_timeout = (ngtcp2_tstamp) cfg->idleSec * NGTCP2_SECONDS;
}

/*	Wire the ngtcp2 conn-ref (used by the crypto layer to recover the
 *	ngtcp2_conn) and create the backend TLS session.		*/

static int setupTls(QuicSession *s, QuicConn *qc, int isServer)
{
	qc->connRef.get_conn = getConnRef;
	qc->connRef.user_data = qc;
	qc->tls = quicTlsConnNew(&s->cfg, s->creds, &qc->connRef, isServer);
	return qc->tls == NULL ? -1 : 0;
}

/*	*	*	UDP / packet I/O	*	*	*	*/

static void makePath(ngtcp2_path *path, ngtcp2_path_storage *ps, QuicConn *qc)
{
	ngtcp2_path_storage_init(ps, (struct sockaddr *) &qc->local, qc->localLen,
			(struct sockaddr *) &qc->remote, qc->remoteLen, NULL);
	*path = ps->path;
}

/*	Drain all packets ngtcp2 wants to send for this connection.	*/

static int writeConn(QuicConn *qc)
{
	QuicSession	   *s = qc->owner;
	uint8_t		    buf[QUIC_MAX_UDP];
	ngtcp2_path_storage ps;
	ngtcp2_pkt_info	    pi;
	ngtcp2_tstamp	    ts = quicNow();

	for (;;)
	{
		ngtcp2_ssize	     nwrite;
		ngtcp2_ssize	     pdatalen = -1;
		int64_t		     streamId = -1;
		ngtcp2_vec	     datav;
		ngtcp2_vec	    *pv = NULL;
		size_t		     pvcnt = 0;
		const unsigned char *curData = NULL;
		int		     curOff = 0;
		int		     curLen = 0;
		int		     chan = 0; /* 1 = signalling, 2 = data.	*/

		ngtcp2_path_storage_init(&ps, (struct sockaddr *) &qc->local,
				qc->localLen, (struct sockaddr *) &qc->remote,
				qc->remoteLen, NULL);

		/*	Pick the next channel to drain under the lock:
		 *	stream-0 signalling first (precedence), then the data
		 *	stream.  Both buffers are sender-thread-set.		*/

		pthread_mutex_lock(&s->mutex);
		if (qc->sigTxOff < qc->sigTxLen)
		{
			curData = qc->sigTx;
			curOff = qc->sigTxOff;
			curLen = qc->sigTxLen;
			streamId = QUICCL_SIG_STREAM;
			chan = 1;
		}
		else if (qc->sendData != NULL && qc->sendOff < qc->sendLen
				&& qc->streamId >= 0)
		{
			curData = qc->sendData;
			curOff = qc->sendOff;
			curLen = qc->sendLen;
			streamId = qc->streamId;
			chan = 2;
		}

		pthread_mutex_unlock(&s->mutex);

		if (chan != 0)
		{
			datav.base = (uint8_t *) curData + curOff;
			datav.len = curLen - curOff;
			pv = &datav;
			pvcnt = 1;
		}

		nwrite = ngtcp2_conn_writev_stream(qc->conn, &ps.path, &pi, buf,
				sizeof(buf), &pdatalen, 0, streamId, pv, pvcnt,
				ts);
		if (nwrite < 0)
		{
			writeMemoNote("[?] quic: writev_stream failed",
					(char *) ngtcp2_strerror((int) nwrite));
			qc->failed = 1;
			return -1;
		}

		if (pdatalen > 0)
		{
			pthread_mutex_lock(&s->mutex);
			if (chan == 1)
			{
				qc->sigTxOff += (int) pdatalen;
			}
			else if (chan == 2)
			{
				qc->sendOff += (int) pdatalen;
			}

			pthread_mutex_unlock(&s->mutex);
			qc->lastTx = ts; /* keepalive timer baseline.	*/
		}

		if (nwrite == 0)
		{
			break; /* Nothing more to send.		*/
		}

		if (sendto(s->fd, buf, nwrite, 0, (struct sockaddr *) &qc->remote,
				    qc->remoteLen)
				< 0)
		{
			if (errno == EAGAIN || errno == EWOULDBLOCK)
			{
				break;
			}

			qc->failed = 1;
			return -1;
		}
	}

	return 0;
}

static int feedConn(QuicConn *qc, const uint8_t *pkt, size_t pktlen)
{
	ngtcp2_path_storage ps;
	ngtcp2_pkt_info	    pi;
	int		    rc;

	memset(&pi, 0, sizeof(pi));
	ngtcp2_path_storage_init(&ps, (struct sockaddr *) &qc->local,
			qc->localLen, (struct sockaddr *) &qc->remote,
			qc->remoteLen, NULL);

	rc = ngtcp2_conn_read_pkt(qc->conn, &ps.path, &pi, pkt, pktlen,
			quicNow());
	if (rc != 0)
	{
		writeMemoNote("[?] quic: read_pkt failed",
				(char *) ngtcp2_strerror(rc));
		qc->failed = 1;
		return -1;
	}

	return 0;
}

static void freeConn(QuicConn *qc)
{
	if (qc == NULL)
	{
		return;
	}

	if (qc->conn)
	{
		ngtcp2_conn_del(qc->conn);
	}

	if (qc->tls)
	{
		quicTlsConnFree(qc->tls);
	}

	if (qc->rxBuf)
	{
		MRELEASE(qc->rxBuf);
	}

	if (qc->sigTx)
	{
		MRELEASE(qc->sigTx);
	}

	if (qc->sigRx)
	{
		MRELEASE(qc->sigRx);
	}

	MRELEASE(qc);
}

/*	*	*	Client	*	*	*	*	*	*/

static void *clientIo(void *parm);

QuicSession *quicClientStart(const QuicClaConfig *cfg)
{
	QuicSession	       *s;
	QuicConn	       *qc;
	struct addrinfo		hints;
	struct addrinfo	       *res = NULL;
	char			portStr[16];
	ngtcp2_cid		dcid;
	ngtcp2_cid		scid;
	ngtcp2_settings		settings;
	ngtcp2_transport_params params;
	ngtcp2_callbacks	callbacks;
	ngtcp2_path_storage	ps;
	int			deadline;

	s = MTAKE(sizeof(QuicSession));
	if (s == NULL)
	{
		return NULL;
	}

	memset(s, 0, sizeof(*s));
	s->cfg = *cfg;
	s->fd = -1;
	s->wakePipe[0] = s->wakePipe[1] = -1;
	pthread_mutex_init(&s->mutex, NULL);
	pthread_cond_init(&s->cond, NULL);

	qc = MTAKE(sizeof(QuicConn));
	if (qc == NULL)
	{
		MRELEASE(s);
		return NULL;
	}

	memset(qc, 0, sizeof(*qc));
	qc->owner = s;
	qc->streamId = -1;
	qc->rxCap = QUICCLA_BUFSZ;
	qc->rxBuf = MTAKE(qc->rxCap);
	if (qc->rxBuf == NULL)
	{
		MRELEASE(qc);
		MRELEASE(s);
		return NULL;
	}

	s->client = qc;

	isprintf(portStr, sizeof(portStr), "%d", cfg->port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	if (getaddrinfo(cfg->host, portStr, &hints, &res) != 0 || res == NULL)
	{
		putErrmsg("quicclo: can't resolve host.", cfg->host);
		goto fail;
	}

	s->fd = socket(res->ai_family, SOCK_DGRAM, 0);
	if (s->fd < 0 || connect(s->fd, res->ai_addr, res->ai_addrlen) < 0)
	{
		putSysErrmsg("quicclo: can't create/connect UDP socket", NULL);
		goto fail;
	}

	memcpy(&qc->remote, res->ai_addr, res->ai_addrlen);
	qc->remoteLen = res->ai_addrlen;
	qc->localLen = sizeof(qc->local);
	if (getsockname(s->fd, (struct sockaddr *) &qc->local, &qc->localLen) < 0)
	{
		putSysErrmsg("quicclo: getsockname failed", NULL);
		goto fail;
	}

	freeaddrinfo(res);
	res = NULL;

	s->creds = quicTlsCredsNew(cfg, 0);
	if (s->creds == NULL || setupTls(s, qc, 0) < 0)
	{
		putErrmsg("quicclo: TLS setup failed.", NULL);
		goto fail;
	}

	dcid.datalen = NGTCP2_MAX_CIDLEN;
	scid.datalen = NGTCP2_MAX_CIDLEN;
	oK(quicTlsRand(dcid.data, dcid.datalen));
	oK(quicTlsRand(scid.data, scid.datalen));
	memcpy(&qc->scid, &scid, sizeof(ngtcp2_cid));

	ngtcp2_settings_default(&settings);
	settings.initial_ts = quicNow();
	defaultTransportParams(cfg, &params);
	setCallbacks(&callbacks, 0);

	ngtcp2_path_storage_init(&ps, (struct sockaddr *) &qc->local,
			qc->localLen, (struct sockaddr *) &qc->remote,
			qc->remoteLen, NULL);

	if (ngtcp2_conn_client_new(&qc->conn, &dcid, &scid, &ps.path,
			    NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params,
			    NULL, qc)
			!= 0)
	{
		putErrmsg("quicclo: ngtcp2_conn_client_new failed.", NULL);
		goto fail;
	}

	ngtcp2_conn_set_tls_native_handle(qc->conn, quicTlsNativeHandle(qc->tls));

	if (pipe(s->wakePipe) < 0)
	{
		putSysErrmsg("quicclo: pipe failed", NULL);
		goto fail;
	}

	oK(fcntl(s->fd, F_SETFL, O_NONBLOCK));
	oK(fcntl(s->wakePipe[0], F_SETFL, O_NONBLOCK));
	oK(fcntl(s->wakePipe[1], F_SETFL, O_NONBLOCK));
	s->running = 1;

	if (pthread_begin(&s->ioThread, NULL, clientIo, s))
	{
		putSysErrmsg("quicclo: can't start I/O thread", NULL);
		goto fail;
	}

	/*	Wait for the QUIC handshake and the QUICCL SESS_INIT
	 *	exchange to complete (up to idle timeout).		*/

	deadline = cfg->idleSec * 1000;
	pthread_mutex_lock(&s->mutex);
	while (qc->sessState != QSS_ESTABLISHED && !qc->failed && deadline > 0)
	{
		struct timespec tw;

		clock_gettime(CLOCK_REALTIME, &tw);
		tw.tv_nsec += 100 * 1000000L;
		if (tw.tv_nsec >= 1000000000L)
		{
			tw.tv_sec += 1;
			tw.tv_nsec -= 1000000000L;
		}

		pthread_cond_timedwait(&s->cond, &s->mutex, &tw);
		deadline -= 100;
	}

	pthread_mutex_unlock(&s->mutex);

	if (qc->sessState != QSS_ESTABLISHED || qc->failed)
	{
		putErrmsg("quicclo: QUICCL session did not establish.", NULL);
		quicClientStop(s);
		return NULL;
	}

	writeMemo("[i] quic: QUICCL session established.");
	return s;

fail:
	if (res)
	{
		freeaddrinfo(res);
	}

	if (s->fd >= 0)
	{
		close(s->fd);
	}

	if (s->wakePipe[0] >= 0)
	{
		close(s->wakePipe[0]);
		close(s->wakePipe[1]);
	}

	freeConn(qc);
	pthread_mutex_destroy(&s->mutex);
	pthread_cond_destroy(&s->cond);
	MRELEASE(s);
	return NULL;
}

static void *clientIo(void *parm)
{
	QuicSession *s = parm;
	QuicConn    *qc = s->client;

	while (s->running && !qc->failed)
	{
		struct pollfd pfds[2];
		ngtcp2_tstamp expiry;
		int	      timeoutMs = 1000;
		uint8_t	      buf[2048];
		ssize_t	      n;
		int	      needOpen;

		/*	Once the QUIC handshake completes, open stream 0
		 *	(the first client bidi stream, == QUICCL_SIG_STREAM)
		 *	and send our SESS_INIT to begin the QUICCL session.	*/

		if (qc->handshakeDone && !qc->sessInitSent)
		{
			int64_t sid;

			if (ngtcp2_conn_open_bidi_stream(qc->conn, &sid, qc) != 0
					|| sendSessInit(qc) < 0)
			{
				qc->failed = 1;
				break;
			}
		}

		/*	Open the data stream (I/O thread owns the conn) once a
		 *	bundle is queued, then send any pending packets.	*/

		pthread_mutex_lock(&s->mutex);
		needOpen = (qc->sendData != NULL && qc->streamId < 0);
		pthread_mutex_unlock(&s->mutex);
		if (needOpen)
		{
			if (ngtcp2_conn_open_bidi_stream(qc->conn,
					    &qc->streamId, qc)
					!= 0)
			{
				qc->failed = 1;
				break;
			}
		}

		sessionTick(qc);
		oK(writeConn(qc));

		pthread_mutex_lock(&s->mutex);
		if (qc->sendData && qc->sendOff >= qc->sendLen)
		{
			qc->sendDone = 1;
		}

		pthread_cond_broadcast(&s->cond);
		pthread_mutex_unlock(&s->mutex);

		pfds[0].fd = s->fd;
		pfds[0].events = POLLIN;
		pfds[0].revents = 0;
		pfds[1].fd = s->wakePipe[0];
		pfds[1].events = POLLIN;
		pfds[1].revents = 0;

		expiry = ngtcp2_conn_get_expiry(qc->conn);
		if (expiry != UINT64_MAX)
		{
			ngtcp2_tstamp now = quicNow();

			if (expiry <= now)
			{
				timeoutMs = 0;
			}
			else
			{
				ngtcp2_tstamp d = (expiry - now)
						/ NGTCP2_MILLISECONDS;

				timeoutMs = d > 1000 ? 1000 : (int) d;
			}
		}

		if (poll(pfds, 2, timeoutMs) < 0 && errno != EINTR)
		{
			break;
		}

		if (pfds[1].revents & POLLIN)
		{
			char drain[64];

			while (read(s->wakePipe[0], drain, sizeof(drain)) > 0)
			{
				;
			}
		}

		while ((n = recv(s->fd, buf, sizeof(buf), 0)) > 0)
		{
			if (feedConn(qc, buf, n) < 0)
			{
				break;
			}
		}

		if (ngtcp2_conn_handle_expiry(qc->conn, quicNow()) != 0)
		{
			qc->failed = 1;
		}

		oK(writeConn(qc));

		pthread_mutex_lock(&s->mutex);
		if (qc->sendData && qc->sendOff >= qc->sendLen)
		{
			qc->sendDone = 1;
		}

		pthread_cond_broadcast(&s->cond);
		pthread_mutex_unlock(&s->mutex);
	}

	pthread_mutex_lock(&s->mutex);
	qc->failed = 1;
	pthread_cond_broadcast(&s->cond);
	pthread_mutex_unlock(&s->mutex);
	return NULL;
}

static void wakeIo(QuicSession *s)
{
	char b = 1;

	if (write(s->wakePipe[1], &b, 1) != 1)
	{
		; /* Wakeup is best-effort.			*/
	}
}

int quicClientSend(QuicSession *s, const unsigned char *bundle, int len)
{
	QuicConn      *qc = s->client;
	unsigned char *framed;
	int	       flen = QUIC_LEN_PREFIX + len;

	if (qc->failed || qc->sessState != QSS_ESTABLISHED)
	{
		return -1;
	}

	framed = MTAKE(flen);
	if (framed == NULL)
	{
		return -1;
	}

	framed[0] = (len >> 24) & 0xff;
	framed[1] = (len >> 16) & 0xff;
	framed[2] = (len >> 8) & 0xff;
	framed[3] = len & 0xff;
	memcpy(framed + QUIC_LEN_PREFIX, bundle, len);

	/*	Hand the bundle to the I/O thread; only that thread may
	 *	touch the (non-thread-safe) ngtcp2_conn, including opening
	 *	the stream.					*/

	pthread_mutex_lock(&s->mutex);
	qc->sendData = framed;
	qc->sendLen = flen;
	qc->sendOff = 0;
	qc->sendDone = 0;
	pthread_mutex_unlock(&s->mutex);

	wakeIo(s);

	pthread_mutex_lock(&s->mutex);
	while (!qc->sendDone && !qc->failed)
	{
		pthread_cond_wait(&s->cond, &s->mutex);
	}

	qc->sendData = NULL;
	pthread_mutex_unlock(&s->mutex);

	MRELEASE(framed);
	return qc->failed ? -1 : 0;
}

void quicClientStop(QuicSession *s)
{
	if (s == NULL)
	{
		return;
	}

	if (s->running)
	{
		/*	Cleanly terminate the QUICCL session: queue SESS_TERM
		 *	and let the I/O thread flush it before shutting down.	*/

		if (s->client && s->client->sessState == QSS_ESTABLISHED
				&& !s->client->termSent)
		{
			oK(sendSessTerm(s->client, QMSG_TERM_UNKNOWN, 0));
			wakeIo(s);
			microsnooze(200000);
		}

		s->running = 0;
		wakeIo(s);
		pthread_join(s->ioThread, NULL);
	}

	if (s->fd >= 0)
	{
		close(s->fd);
	}

	if (s->wakePipe[0] >= 0)
	{
		close(s->wakePipe[0]);
		close(s->wakePipe[1]);
	}

	freeConn(s->client);
	quicTlsCredsFree(s->creds);
	pthread_mutex_destroy(&s->mutex);
	pthread_cond_destroy(&s->cond);
	MRELEASE(s);
}

/*	*	*	Server	*	*	*	*	*	*/

QuicSession *quicServerStart(const QuicClaConfig *cfg)
{
	QuicSession	*s;
	struct addrinfo	 hints;
	struct addrinfo *res = NULL;
	char		 portStr[16];

	if (cfg->certFile[0] == '\0' || cfg->keyFile[0] == '\0')
	{
		putErrmsg("quiccli: -c cert and -k key are required.", NULL);
		return NULL;
	}

	s = MTAKE(sizeof(QuicSession));
	if (s == NULL)
	{
		return NULL;
	}

	memset(s, 0, sizeof(*s));
	s->isServer = 1;
	s->cfg = *cfg;
	s->fd = -1;
	pthread_mutex_init(&s->mutex, NULL);
	pthread_cond_init(&s->cond, NULL);

	s->creds = quicTlsCredsNew(cfg, 1);
	if (s->creds == NULL)
	{
		goto fail;
	}

	isprintf(portStr, sizeof(portStr), "%d", cfg->port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	if (getaddrinfo(cfg->host[0] ? cfg->host : NULL, portStr, &hints, &res) != 0
			|| res == NULL)
	{
		putErrmsg("quiccli: can't resolve bind address.", cfg->host);
		goto fail;
	}

	s->fd = socket(res->ai_family, SOCK_DGRAM, 0);
	if (s->fd < 0 || bind(s->fd, res->ai_addr, res->ai_addrlen) < 0)
	{
		putSysErrmsg("quiccli: can't bind UDP socket", NULL);
		goto fail;
	}

	freeaddrinfo(res);
	oK(fcntl(s->fd, F_SETFL, O_NONBLOCK));
	return s;

fail:
	if (res)
	{
		freeaddrinfo(res);
	}

	if (s->fd >= 0)
	{
		close(s->fd);
	}

	quicTlsCredsFree(s->creds);

	MRELEASE(s);
	return NULL;
}

static QuicConn *findConn(QuicSession *s, const uint8_t *dcid, size_t dcidlen)
{
	QuicConn *qc;

	for (qc = s->conns; qc != NULL; qc = qc->next)
	{
		if (qc->scid.datalen == dcidlen
				&& memcmp(qc->scid.data, dcid, dcidlen) == 0)
		{
			return qc;
		}
	}

	return NULL;
}

static QuicConn *acceptConn(QuicSession *s, const uint8_t *pkt, size_t pktlen,
		struct sockaddr *remote, socklen_t remoteLen)
{
	QuicConn	       *qc;
	ngtcp2_pkt_hd		hd;
	ngtcp2_cid		scid;
	ngtcp2_settings		settings;
	ngtcp2_transport_params params;
	ngtcp2_callbacks	callbacks;
	ngtcp2_path_storage	ps;

	if (ngtcp2_accept(&hd, pkt, pktlen) != 0)
	{
		return NULL; /* Not an acceptable Initial.		*/
	}

	qc = MTAKE(sizeof(QuicConn));
	if (qc == NULL)
	{
		return NULL;
	}

	memset(qc, 0, sizeof(*qc));
	qc->owner = s;
	qc->streamId = -1;
	qc->rxCap = QUICCLA_BUFSZ;
	qc->rxBuf = MTAKE(qc->rxCap);
	if (qc->rxBuf == NULL)
	{
		MRELEASE(qc);
		return NULL;
	}

	memcpy(&qc->remote, remote, remoteLen);
	qc->remoteLen = remoteLen;
	qc->localLen = sizeof(qc->local);
	oK(getsockname(s->fd, (struct sockaddr *) &qc->local, &qc->localLen));

	if (setupTls(s, qc, 1) < 0)
	{
		freeConn(qc);
		return NULL;
	}

	scid.datalen = NGTCP2_MAX_CIDLEN;
	oK(quicTlsRand(scid.data, scid.datalen));
	memcpy(&qc->scid, &scid, sizeof(ngtcp2_cid));

	ngtcp2_settings_default(&settings);
	settings.initial_ts = quicNow();
	defaultTransportParams(&s->cfg, &params);
	params.original_dcid = hd.dcid;
	setCallbacks(&callbacks, 1);

	ngtcp2_path_storage_init(&ps, (struct sockaddr *) &qc->local,
			qc->localLen, (struct sockaddr *) &qc->remote,
			qc->remoteLen, NULL);

	if (ngtcp2_conn_server_new(&qc->conn, &hd.scid, &scid, &ps.path,
			    hd.version, &callbacks, &settings, &params, NULL, qc)
			!= 0)
	{
		freeConn(qc);
		return NULL;
	}

	ngtcp2_conn_set_tls_native_handle(qc->conn, quicTlsNativeHandle(qc->tls));

	qc->next = s->conns;
	s->conns = qc;
	return qc;
}

static void removeConn(QuicSession *s, QuicConn *dead)
{
	QuicConn **pp;

	for (pp = &s->conns; *pp != NULL; pp = &(*pp)->next)
	{
		if (*pp == dead)
		{
			*pp = dead->next;
			break;
		}
	}

	freeConn(dead);
}

int quicServerRun(QuicSession *s, QuicBundleCb cb, void *user,
		volatile int *running)
{
	s->cb = cb;
	s->cbUser = user;

	while (*running)
	{
		struct pollfd		pfd;
		uint8_t			buf[2048];
		ssize_t			n;
		struct sockaddr_storage remote;
		socklen_t		remoteLen;
		QuicConn	       *qc;
		QuicConn	       *next;
		ngtcp2_version_cid	vc;
		int			timeoutMs = 1000;

		pfd.fd = s->fd;
		pfd.events = POLLIN;
		pfd.revents = 0;

		if (poll(&pfd, 1, timeoutMs) < 0 && errno != EINTR)
		{
			return -1;
		}

		remoteLen = sizeof(remote);
		while ((n = recvfrom(s->fd, buf, sizeof(buf), 0,
					(struct sockaddr *) &remote, &remoteLen))
				> 0)
		{
			if (ngtcp2_pkt_decode_version_cid(&vc, buf, n,
					    NGTCP2_MAX_CIDLEN)
					!= 0)
			{
				remoteLen = sizeof(remote);
				continue;
			}

			qc = findConn(s, vc.dcid, vc.dcidlen);
			if (qc == NULL)
			{
				qc = acceptConn(s, buf, n,
						(struct sockaddr *) &remote,
						remoteLen);
				if (qc == NULL)
				{
					remoteLen = sizeof(remote);
					continue;
				}
			}

			oK(feedConn(qc, buf, n));
			remoteLen = sizeof(remote);
		}

		for (qc = s->conns; qc != NULL; qc = next)
		{
			next = qc->next;
			if (!qc->failed)
			{
				if (ngtcp2_conn_handle_expiry(qc->conn, quicNow())
						!= 0)
				{
					qc->failed = 1;
				}
				else
				{
					sessionTick(qc);
					oK(writeConn(qc));
				}
			}

			if (qc->failed)
			{
				removeConn(s, qc);
			}
		}
	}

	return 0;
}

void quicServerStop(QuicSession *s)
{
	QuicConn *qc;
	QuicConn *next;

	if (s == NULL)
	{
		return;
	}

	/*	Cleanly terminate each established session with a SESS_TERM,
	 *	flushed inline since the server loop has already stopped.	*/

	for (qc = s->conns; qc != NULL; qc = qc->next)
	{
		if (!qc->failed && qc->sessState == QSS_ESTABLISHED
				&& !qc->termSent)
		{
			oK(sendSessTerm(qc, QMSG_TERM_UNKNOWN, 0));
			oK(writeConn(qc));
		}
	}

	for (qc = s->conns; qc != NULL; qc = next)
	{
		next = qc->next;
		freeConn(qc);
	}

	if (s->fd >= 0)
	{
		close(s->fd);
	}

	quicTlsCredsFree(s->creds);

	MRELEASE(s);
}
