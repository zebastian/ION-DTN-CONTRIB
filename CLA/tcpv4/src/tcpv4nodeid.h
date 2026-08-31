/*
	tcpv4nodeid.h:	node ID handling for the TCPCLv4 convergence layer.

			A TCPCLv4 peer names itself with a node ID in its
			SESS_INIT (RFC 9174 4.6), and that node ID is what
			the session engine keys sessions on: it decides
			which egress plan a session may carry bundles for,
			and it is what the certificate NODE-ID has to
			authenticate (4.4.4.3).

			Node IDs are EIDs, so comparing them is not quite
			string comparison: two spellings of the same ipn
			node ID ("ipn:5", "ipn:5.0", "ipn:0.5.0") name the
			same node.  Everything else compares literally.

			This unit is deliberately free of any dependency on
			ION or on the rest of the CLA, so that it can be
			unit tested on its own.
								*/

#ifndef TCPV4NODEID_H
#define TCPV4NODEID_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*	Parse an ipn node ID into its node part - the allocator and node
 *	number of RFC 9758, the service number being no part of a node's
 *	identity.  "ipn:5", "ipn:5.0" and "ipn:0.5.0" all yield
 *	allocator 0, node 5.  Returns 1 when nodeId is a well-formed ipn
 *	node ID, 0 when it is not (a dtn node ID, say, or malformed).	*/
int tcpv4NodeIdIpn(const char *nodeId, uint64_t *allocator, uint64_t *node);

/*	Non-zero when the two node IDs name the same node.  Two ipn node
 *	IDs are compared numerically, whatever their spelling; anything
 *	else is compared literally.  A NULL or empty node ID names no
 *	node and so matches nothing, itself included.			*/
int tcpv4NodeIdMatches(const char *a, const char *b);

/*	Non-zero when nodeId is present and non-empty.			*/
int tcpv4NodeIdIsSet(const char *nodeId);

#ifdef __cplusplus
}
#endif

#endif /* TCPV4NODEID_H */
