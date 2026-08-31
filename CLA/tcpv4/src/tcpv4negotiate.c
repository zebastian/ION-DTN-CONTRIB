/*
	tcpv4negotiate.c: contact and session negotiation for the TCPCLv4
			session engine.

			The sequence a fresh socket goes through before it
			carries any bundle: the contact header exchange
			(RFC 9174 4.2, 4.3), the TLS handshake and the peer
			authentication that goes with it (4.4), and the
			SESS_INIT exchange that settles the session
			parameters and the peer's node ID (4.6, 4.7).

			The peer identity established here is what the rest
			of the engine routes on, so this unit is also where
			the NODE-ID authentication policy of 4.4.4.3 is
			applied.
								*/

#include "tcpv4sessint.h"
#include <string.h>

static int sendSessInit(Tcpv4Conn *conn)
{
	Tcpv4Engine  *e = conn->owner;
	Tcpv4SessInit init;
	uint8_t	      buf[64 + TCPV4_MAX_NODEID_LEN];
	int	      len;

	memset(&init, 0, sizeof(init));
	init.keepalive = (uint16_t) e->cfg.keepalive;
	init.segmentMru = (uint64_t) e->cfg.segmentMru;
	init.transferMru = (uint64_t) e->cfg.transferMru;
	init.nodeId = (const uint8_t *) e->nodeId;
	init.nodeIdLen = (uint16_t) strlen(e->nodeId);
	len = tcpv4MsgEncodeSessInit(buf, sizeof(buf), &init);
	if (len < 0)
	{
		return -1;
	}

	return tcpv4ConnSend(conn, buf, len);
}

/*	*	*	Contact and session negotiation	*	*	*/

/*	Exchange contact headers (RFC 9174 4.2, 4.3) and return the
 *	negotiated Enable TLS value in *enableTls.  Returns 0 on success,
 *	-1 when the connection is to be closed.				*/

static int exchangeContact(Tcpv4Conn *conn, int *enableTls)
{
	Tcpv4Engine *e = conn->owner;
	Tcpv4Contact ours;
	Tcpv4Contact peer;
	uint8_t	     buf[TMSG_CONTACT_LEN];
	int	     len;
	int	     canTls = (e->cfg.tlsPolicy != TCPV4_TLS_DISABLE);

	memset(&ours, 0, sizeof(ours));
	ours.version = TMSG_VERSION;
	ours.flags = canTls ? TMSG_CONTACT_CAN_TLS : 0;
	len = tcpv4MsgEncodeContact(buf, sizeof(buf), &ours);
	if (len < 0)
	{
		return -1;
	}

	/*	RFC 9174 4.1: the active entity sends first; the passive
	 *	entity replies only after a Contact Header arrives, so that
	 *	it commits no resources to an unknown peer.		*/

	if (conn->activeRole)
	{
		if (tcpv4ConnSend(conn, buf, len) < 0)
		{
			return -1;
		}
	}

	if (tcpv4ConnRecv(conn, buf, TMSG_CONTACT_LEN) != TMSG_CONTACT_LEN)
	{
		writeMemoNote("[i] tcpv4cla got no contact header from",
				conn->peerName);
		return -1;
	}

	if (tcpv4MsgDecodeContact(buf, TMSG_CONTACT_LEN, &peer) <= 0)
	{
		/*	RFC 9174 6.1: on a bad magic string, close the TCP
		 *	connection without sending SESS_TERM.		*/

		writeMemoNote("[?] tcpv4cla got a bad contact header from",
				conn->peerName);
		return -1;
	}

	if (!conn->activeRole)
	{
		len = tcpv4MsgEncodeContact(buf, sizeof(buf), &ours);
		if (len < 0 || tcpv4ConnSend(conn, buf, len) < 0)
		{
			return -1;
		}
	}

	if (peer.version != TMSG_VERSION)
	{
		if (conn->activeRole)
		{
			/*	RFC 9174 4.3: a lower version from the
			 *	passive entity closes the connection.	*/

			writeMemoNote("[?] tcpv4cla peer speaks another TCPCL"
				      " version",
					conn->peerName);
		}
		else
		{
			oK(tcpv4SendSessTerm(conn, TMSG_TERM_VERSION_MISMATCH, 0));
		}

		return -1;
	}

	/*	RFC 9174 4.3: Enable TLS is the logical AND of the two
	 *	CAN_TLS flags, then local policy is applied.		*/

	*enableTls = canTls && (peer.flags & TMSG_CONTACT_CAN_TLS);
	if (!*enableTls && e->cfg.tlsPolicy == TCPV4_TLS_REQUIRE)
	{
		writeMemoNote("[?] tcpv4cla requires TLS but peer cannot",
				conn->peerName);
		oK(tcpv4SendSessTerm(conn, TMSG_TERM_CONTACT_FAILURE, 0));
		return -1;
	}

	return 0;
}

/*	Parse "ipn:<node>[.<service>]" into a node number, or 0.		*/

static uvast nodeNbrFromNodeId(const char *nodeId)
{
	uvast node = 0;

	if (nodeId != NULL && strncmp(nodeId, "ipn:", 4) == 0)
	{
		oK(sscanf(nodeId + 4, UVAST_FIELDSPEC, &node));
	}

	return node;
}

/*	Apply the peer's SESS_INIT: negotiate the session parameters
 *	(RFC 9174 4.7) and adopt the peer's node ID (RFC 9174 4.6).
 *	Returns 0 on success, -1 when the session is unacceptable.	*/

static int applySessInit(Tcpv4Conn *conn, const Tcpv4SessInit *peer)
{
	Tcpv4Engine *e = conn->owner;
	uvast	     peerNode;
	size_t	     off = 0;
	Tcpv4ExtItem item;
	char	     claimed[TCPV4_MAX_NODEID_LEN] = {0};
	int	     authenticated = 0;
	int	     rc;

	if (peer->segmentMru == 0 || peer->transferMru == 0)
	{
		/*	RFC 9174 4.7: an unacceptable MRU ends the session
		 *	with "Contact Failure".				*/

		writeMemoNote("[?] tcpv4cla got an unusable MRU from",
				conn->peerName);
		oK(tcpv4SendSessTerm(conn, TMSG_TERM_CONTACT_FAILURE, 0));
		return -1;
	}

	/*	RFC 9174 4.8: an unknown session extension item marked
	 *	CRITICAL terminates the session with "Contact Failure".	*/

	while ((rc = tcpv4MsgNextExtItem(peer->sessExt, peer->sessExtLen, &off,
				&item))
			== 1)
	{
		if (item.flags & TMSG_EXT_CRITICAL)
		{
			writeMemoNote("[?] tcpv4cla got a critical session"
				      " extension it cannot handle from",
					conn->peerName);
			oK(tcpv4SendSessTerm(conn, TMSG_TERM_CONTACT_FAILURE, 0));
			return -1;
		}
	}

	if (rc < 0)
	{
		writeMemoNote("[?] tcpv4cla got a malformed session extension"
			      " list from",
				conn->peerName);
		oK(tcpv4SendSessTerm(conn, TMSG_TERM_CONTACT_FAILURE, 0));
		return -1;
	}

	if (peer->nodeIdLen > 0 && peer->nodeIdLen < TCPV4_MAX_NODEID_LEN)
	{
		memcpy(claimed, peer->nodeId, peer->nodeIdLen);
		claimed[peer->nodeIdLen] = '\0';
	}

	/*	RFC 9174 4.4.4.3: immediately before parameter negotiation,
	 *	validate the certificate NODE-ID against the node ID the peer
	 *	claims in its SESS_INIT.  Only a certificate that was itself
	 *	validated can authenticate anything, so -n (do not verify)
	 *	and a plaintext session leave the node ID unauthenticated.	*/

	if (conn->tls != NULL && !e->cfg.noVerify
			&& e->cfg.eidPolicy != TCPV4_EIDPOL_NONE
			&& claimed[0] != '\0')
	{
		switch (tcpv4TlsMatchNodeId(conn->tls, claimed))
		{
		case TCPV4_NODEID_SUCCESS:
			authenticated = 1;
			break;

		case TCPV4_NODEID_FAILURE:
			/*	NODE-IDs are present and none of them is the
			 *	node ID claimed: the peer is not who it says
			 *	it is.  Terminate, whatever the policy.	*/

			writeMemoNote("[?] tcpv4cla: peer's certificate does"
				      " not authenticate the node ID it"
				      " claims;",
					conn->peerName);
			oK(tcpv4SendSessTerm(conn, TMSG_TERM_CONTACT_FAILURE, 0));
			return -1;

		default: /* ABSENT, or no usable certificate.		*/
			if (e->cfg.eidPolicy == TCPV4_EIDPOL_REQUIRE)
			{
				writeMemoNote("[?] tcpv4cla: peer's certificate"
					      " carries no NODE-ID and policy"
					      " requires one;",
						conn->peerName);
				oK(tcpv4SendSessTerm(conn, TMSG_TERM_CONTACT_FAILURE,
						0));
				return -1;
			}

			break;
		}
	}

	peerNode = nodeNbrFromNodeId(claimed);

	pthread_mutex_lock(&e->mutex);
	conn->segmentMtu = peer->segmentMru;
	conn->transferMtu = peer->transferMru;
	conn->keepalive = (peer->keepalive < e->cfg.keepalive
					? peer->keepalive
					: e->cfg.keepalive);
	istrcpy(conn->peerNodeId, claimed, sizeof(conn->peerNodeId));
	conn->nodeIdAuthenticated = authenticated;

	if (authenticated)
	{
		/*	RFC 9174 4.6: the session is associated with the node
		 *	ID the peer actually gave, even if that is not the
		 *	one we dialled - now that the certificate says the
		 *	peer is entitled to it.				*/

		conn->peerNode = peerNode;
	}
	else if (conn->activeRole)
	{
		/*	We opened this session, so its node number came from
		 *	the egress plan and not from the wire.  Keep it -
		 *	unless the peer answers with a different node ID,
		 *	which nothing here can check and so nothing here
		 *	will route on.					*/

		if (peerNode != 0 && peerNode != conn->peerNode)
		{
			writeMemoNote("[?] tcpv4cla: peer claims an"
				      " unauthenticated node ID that is not"
				      " the one dialled; not routing to it;",
					conn->peerName);
			conn->peerNode = 0;
		}
	}
	else if (e->cfg.eidPolicy == TCPV4_EIDPOL_NONE && peerNode != 0)
	{
		/*	The operator has explicitly given up on authenticating
		 *	node IDs, so the session is associated with the node
		 *	ID the peer claims.  That is what lets a pair of nodes
		 *	share one connection instead of each dialling its own,
		 *	and trusting the claim is exactly the trade that -E
		 *	none names.					*/

		conn->peerNode = peerNode;
	}
	else
	{
		/*	An accepted session whose node ID is unauthenticated
		 *	never carries bundles outward (RFC 9174 7.9, "Threat:
		 *	BP Node Impersonation"): any peer could otherwise
		 *	name itself as some node and collect that node's
		 *	traffic.  It can still deliver bundles inward.	*/

		conn->peerNode = 0;
	}

	pthread_mutex_unlock(&e->mutex);
	return 0;
}

/*	Read the peer's SESS_INIT, which RFC 9174 4.6 makes the first
 *	message of the session.  Returns 0 on success, -1 otherwise.	*/

static int recvSessInit(Tcpv4Conn *conn)
{
	Tcpv4SessInit peer;
	uint8_t	     *buf;
	uint8_t	      fixed[21]; /* type, keepalive, 2 MRUs, node ID len.	*/
	uint16_t      nodeIdLen;
	uint32_t      extLen;
	int	      result = -1;
	int	      off;

	if (tcpv4ConnRecv(conn, fixed, 1) != 1)
	{
		return -1;
	}

	if (fixed[0] == TMSG_SESS_TERM)
	{
		writeMemoNote("[i] tcpv4cla peer refused the session",
				conn->peerName);
		return -1;
	}

	if (fixed[0] != TMSG_SESS_INIT)
	{
		oK(tcpv4SendMsgReject(conn, TMSG_REJECT_UNEXPECTED, fixed[0]));
		return -1;
	}

	if (tcpv4ConnRecv(conn, fixed + 1, 20) != 20)
	{
		return -1;
	}

	nodeIdLen = (uint16_t) ((fixed[19] << 8) | fixed[20]);
	if (nodeIdLen >= TCPV4_MAX_NODEID_LEN)
	{
		writeMemoNote("[?] tcpv4cla got an oversized node ID from",
				conn->peerName);
		return -1;
	}

	/*	The whole message is buffered so that the codec, not this
	 *	function, does the field parsing.			*/

	buf = MTAKE(sizeof(fixed) + nodeIdLen + 4 + TCPV4_MAX_EXT_LEN);
	if (buf == NULL)
	{
		putErrmsg("tcpv4cla: no memory for SESS_INIT.", NULL);
		return -1;
	}

	memcpy(buf, fixed, sizeof(fixed));
	off = sizeof(fixed);
	if (nodeIdLen > 0)
	{
		if (tcpv4ConnRecv(conn, buf + off, nodeIdLen) != nodeIdLen)
		{
			MRELEASE(buf);
			return -1;
		}

		off += nodeIdLen;
	}

	if (tcpv4ConnRecv(conn, buf + off, 4) != 4)
	{
		MRELEASE(buf);
		return -1;
	}

	extLen = ((uint32_t) buf[off] << 24) | ((uint32_t) buf[off + 1] << 16)
			| ((uint32_t) buf[off + 2] << 8)
			| (uint32_t) buf[off + 3];
	off += 4;
	if (extLen > TCPV4_MAX_EXT_LEN)
	{
		writeMemoNote("[?] tcpv4cla got an oversized session extension"
			      " list from",
				conn->peerName);
		MRELEASE(buf);
		return -1;
	}

	if (extLen > 0)
	{
		if (tcpv4ConnRecv(conn, buf + off, extLen) != (int) extLen)
		{
			MRELEASE(buf);
			return -1;
		}

		off += extLen;
	}

	if (tcpv4MsgDecodeSessInit(buf, off, &peer) == off)
	{
		result = applySessInit(conn, &peer);
	}
	else
	{
		writeMemoNote("[?] tcpv4cla got a malformed SESS_INIT from",
				conn->peerName);
	}

	MRELEASE(buf);
	return result;
}

/*	Run the whole session establishment sequence on a fresh socket.
 *	Returns 0 once the session is established, -1 otherwise.	*/

int tcpv4Establish(Tcpv4Conn *conn)
{
	Tcpv4Engine *e = conn->owner;
	int	     enableTls = 0;

	if (exchangeContact(conn, &enableTls) < 0)
	{
		return -1;
	}

	if (enableTls)
	{
		/*	RFC 9174 4.4.3: the active entity is the TLS
		 *	client, the passive entity the TLS server.	*/

		conn->tls = tcpv4TlsHandshake(&e->cfg,
				conn->activeRole ? e->clientCreds
						 : e->serverCreds,
				conn->sock, conn->activeRole ? 0 : 1,
				conn->peerName);
		if (conn->tls == NULL)
		{
			/*	RFC 9174 4.4.3: on handshake failure both
			 *	entities close the TCP connection; there is
			 *	no session yet to terminate.		*/

			return -1;
		}

		conn->peerAuthenticated = tcpv4TlsPeerAuthenticated(conn->tls);
	}

	/*	RFC 9174 4.4.3 has the active entity send SESS_INIT first;
	 *	both directions are independent, so send ours right away and
	 *	then read the peer's.					*/

	if (sendSessInit(conn) < 0 || recvSessInit(conn) < 0)
	{
		return -1;
	}

	pthread_mutex_lock(&e->mutex);
	conn->state = TCS_ESTABLISHED;
	conn->secSinceRx = 0;
	conn->secSinceTx = 0;
	conn->secSinceData = 0;
	pthread_cond_broadcast(&e->cond);
	pthread_mutex_unlock(&e->mutex);

	{
		char	    txt[512];
		const char *security;

		if (conn->tls == NULL)
		{
			security = "no TLS";
		}
		else if (!conn->peerAuthenticated)
		{
			security = "TLS, peer not verified";
		}
		else if (conn->nodeIdAuthenticated)
		{
			security = "TLS, node ID authenticated";
		}
		else
		{
			security = "TLS, node ID not authenticated";
		}

		isprintf(txt, sizeof(txt),
				"[i] tcpv4cla session established with '%s'"
				" (node '%s', %s, %s, keepalive %d s, segment"
				" MTU " UVAST_FIELDSPEC ").",
				conn->peerName,
				conn->peerNodeId[0] ? conn->peerNodeId
						   : "unknown",
				security,
				conn->peerNode == 0 ? "inbound only"
						    : "bidirectional",
				conn->keepalive, (uvast) conn->segmentMtu);
		writeMemo(txt);
	}

	return 0;
}
