/*
	tcpv4nodeid_test.c:	unit tests for node ID comparison.
				Built and run via `make check`.

	A TCPCLv4 session is keyed on the peer's node ID (RFC 9174 4.6), so
	getting this comparison wrong either sends a node's traffic to
	somebody else or refuses to send it at all.
									*/

#include <assert.h>
#include <string.h>
#include "tcpv4nodeid.h"

static void test_ipn_parsing(void)
{
	uint64_t allocator;
	uint64_t node;

	/*	RFC 9758: "ipn:5" and "ipn:5.0" are the same node, and the
	 *	three-element form names the allocator explicitly.  The
	 *	service number is no part of a node's identity.		*/

	assert(tcpv4NodeIdIpn("ipn:5", &allocator, &node) == 1);
	assert(allocator == 0 && node == 5);

	assert(tcpv4NodeIdIpn("ipn:5.0", &allocator, &node) == 1);
	assert(allocator == 0 && node == 5);

	assert(tcpv4NodeIdIpn("ipn:5.42", &allocator, &node) == 1);
	assert(allocator == 0 && node == 5);

	assert(tcpv4NodeIdIpn("ipn:7.5.0", &allocator, &node) == 1);
	assert(allocator == 7 && node == 5);

	/*	The scheme name of a URI is case insensitive.		*/

	assert(tcpv4NodeIdIpn("IPN:5.0", &allocator, &node) == 1);
	assert(allocator == 0 && node == 5);

	/*	Anything that is not an ipn node ID is simply not one; it
	 *	is not an error, and it is not a match either.		*/

	assert(tcpv4NodeIdIpn("dtn://node/", &allocator, &node) == 0);
	assert(tcpv4NodeIdIpn("ipn:", &allocator, &node) == 0);
	assert(tcpv4NodeIdIpn("ipn:abc", &allocator, &node) == 0);
	assert(tcpv4NodeIdIpn("ipn:5.", &allocator, &node) == 0);
	assert(tcpv4NodeIdIpn("ipn:5.0.0.0", &allocator, &node) == 0);
	assert(tcpv4NodeIdIpn("ipn:5x", &allocator, &node) == 0);
	assert(tcpv4NodeIdIpn(NULL, &allocator, &node) == 0);
	assert(tcpv4NodeIdIpn("", &allocator, &node) == 0);

	/*	A component too large to hold is not a component we can
	 *	compare, so it is malformed rather than truncated.	*/

	assert(tcpv4NodeIdIpn("ipn:99999999999999999999999.0", &allocator,
				&node)
			== 0);
}

static void test_ipn_matching(void)
{
	/*	The same node, spelled every way ION and its peers spell
	 *	it, has to compare equal: an egress plan says "ipn:5.0"
	 *	while the peer's SESS_INIT may say "ipn:5".		*/

	assert(tcpv4NodeIdMatches("ipn:5", "ipn:5.0"));
	assert(tcpv4NodeIdMatches("ipn:5.0", "ipn:0.5.0"));
	assert(tcpv4NodeIdMatches("ipn:5.1", "ipn:5.2"));
	assert(tcpv4NodeIdMatches("IPN:5.0", "ipn:5.0"));

	assert(!tcpv4NodeIdMatches("ipn:5.0", "ipn:6.0"));
	assert(!tcpv4NodeIdMatches("ipn:0.5.0", "ipn:7.5.0"));
}

static void test_other_schemes(void)
{
	/*	No scheme-specific rule to apply outside ipn, so two node
	 *	IDs are the same node only if they are spelled the same.	*/

	assert(tcpv4NodeIdMatches("dtn://node/", "dtn://node/"));
	assert(!tcpv4NodeIdMatches("dtn://node/", "dtn://other/"));

	/*	An ipn node ID and a dtn one are never the same node, and
	 *	the malformed spelling of an ipn EID is not silently taken
	 *	for a literal string that happens to match.		*/

	assert(!tcpv4NodeIdMatches("ipn:5.0", "dtn://node/"));
	assert(tcpv4NodeIdMatches("ipn:bogus", "ipn:bogus"));
	assert(!tcpv4NodeIdMatches("ipn:bogus", "ipn:5.0"));
}

static void test_unset(void)
{
	/*	An unset node ID names no node, so it matches nothing -
	 *	itself included.  That is what keeps a session whose peer
	 *	could not be identified (RFC 9174 7.9) from being selected
	 *	to carry anybody's traffic.				*/

	assert(!tcpv4NodeIdIsSet(NULL));
	assert(!tcpv4NodeIdIsSet(""));
	assert(tcpv4NodeIdIsSet("ipn:5.0"));

	assert(!tcpv4NodeIdMatches("", ""));
	assert(!tcpv4NodeIdMatches("", "ipn:5.0"));
	assert(!tcpv4NodeIdMatches("ipn:5.0", ""));
	assert(!tcpv4NodeIdMatches(NULL, "ipn:5.0"));
	assert(!tcpv4NodeIdMatches("ipn:5.0", NULL));
}

int main(void)
{
	test_ipn_parsing();
	test_ipn_matching();
	test_other_schemes();
	test_unset();
	return 0;
}
