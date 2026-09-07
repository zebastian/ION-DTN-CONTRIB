/*
	tcpv4x509_test.c:	unit tests for the certificate decoding the
				TLS backends share.
				Built and run via `make check`.

	These few hundred octets of DER decide who a peer is allowed to be.
	A NODE-ID read wrongly either authenticates a claim it should not
	(RFC 9174 7.9) or refuses one it should, and an extension mistaken
	for absent turns a restriction into permission (RFC 5280 4.2.1.3).
									*/

#include <assert.h>
#include <string.h>
#include "tcpv4x509.h"

/*	The value of an id-on-bundleEID otherName as RFC 9174 Appendix C
 *	shows it: the [0] EXPLICIT wrapper around an IA5String.		*/

static const unsigned char wrappedEid[] = {
	0xA0, 0x09, 0x16, 0x07, 'i', 'p', 'n', ':', '1', '.', '0'
};

/*	The same node ID as some libraries hand it back: the IA5String
 *	alone, the wrapper already stripped.				*/

static const unsigned char bareEid[] = {
	0x16, 0x07, 'i', 'p', 'n', ':', '1', '.', '0'
};

static void test_bundle_eid(void)
{
	char uri[64];

	assert(tcpv4X509BundleEid(wrappedEid, sizeof wrappedEid, uri,
				sizeof uri)
			== 0);
	assert(strcmp(uri, "ipn:1.0") == 0);

	assert(tcpv4X509BundleEid(bareEid, sizeof bareEid, uri, sizeof uri)
			== 0);
	assert(strcmp(uri, "ipn:1.0") == 0);
}

static void test_bundle_eid_malformed(void)
{
	unsigned char der[16];
	char	      uri[64];

	/*	Some other string type, or a length that runs past the end
	 *	of the value, is not a node ID this code will hand on.	*/

	memcpy(der, bareEid, sizeof bareEid);
	der[0] = 0x0C;			/*	UTF8String.		*/
	assert(tcpv4X509BundleEid(der, sizeof bareEid, uri, sizeof uri) < 0);

	memcpy(der, bareEid, sizeof bareEid);
	der[1] = 0x20;			/*	Longer than the value.	*/
	assert(tcpv4X509BundleEid(der, sizeof bareEid, uri, sizeof uri) < 0);

	/*	An empty string names nothing.				*/

	der[0] = 0x16;
	der[1] = 0x00;
	assert(tcpv4X509BundleEid(der, 2, uri, sizeof uri) < 0);

	/*	A node ID is text: an embedded NUL would make the URI
	 *	compared here shorter than the one the certificate
	 *	carries, which is how one certificate authenticates two
	 *	different claims.					*/

	memcpy(der, bareEid, sizeof bareEid);
	der[5] = '\0';
	assert(tcpv4X509BundleEid(der, sizeof bareEid, uri, sizeof uri) < 0);

	/*	One that does not fit is refused rather than truncated.	*/

	assert(tcpv4X509BundleEid(bareEid, sizeof bareEid, uri, 4) < 0);

	assert(tcpv4X509BundleEid(NULL, 0, uri, sizeof uri) < 0);
}

static void test_is_node_id(void)
{
	/*	RFC 9174 4.4.1: a NODE-ID names a node and nothing on it,
	 *	which for ipn is service number 0 and for dtn an empty
	 *	demux (RFC 9171 4.2.5).  Anything else in the certificate
	 *	is some other EID, and is ignored rather than counted as a
	 *	NODE-ID that failed to match.				*/

	assert(tcpv4X509IsNodeId("ipn:1.0"));
	assert(tcpv4X509IsNodeId("ipn:2.3.0"));
	assert(!tcpv4X509IsNodeId("ipn:1.7"));

	assert(tcpv4X509IsNodeId("dtn://node/"));
	assert(tcpv4X509IsNodeId("dtn:none"));
	assert(!tcpv4X509IsNodeId("dtn://node/service"));

	/*	A scheme this code has no rule for is left in play, so
	 *	that an exact match still authenticates it.		*/

	assert(tcpv4X509IsNodeId("imc:1.2"));
	assert(!tcpv4X509IsNodeId(NULL));
}

/*	Two extensions, keyUsage (2.5.29.15) and basicConstraints
 *	(2.5.29.19), as they sit in a certificate's Extensions SEQUENCE -
 *	the first of them critical, so that the optional BOOLEAN is in the
 *	way of the walk.						*/

static const unsigned char extensions[] = {
	0x30, 0x0E,			/*	Extension SEQUENCE.	*/
		0x06, 0x03, 0x55, 0x1D, 0x0F,	/*	keyUsage.	*/
		0x01, 0x01, 0xFF,		/*	critical.	*/
		0x04, 0x04, 0x03, 0x02, 0x05, 0xA0,
	0x30, 0x0C,			/*	Extension SEQUENCE.	*/
		0x06, 0x03, 0x55, 0x1D, 0x13,	/* basicConstraints.	*/
		0x01, 0x01, 0xFF,		/*	critical.	*/
		0x04, 0x02, 0x30, 0x00
};

/*	The same two, wrapped in the Extensions SEQUENCE that holds them -
 *	which is the shape a library hands back when it kept the whole
 *	extension list rather than its entries.				*/

static const unsigned char wrappedExtensions[] = {
	0x30, 0x1E,			/*	Extensions SEQUENCE.	*/
	0x30, 0x0E,
		0x06, 0x03, 0x55, 0x1D, 0x0F,
		0x01, 0x01, 0xFF,
		0x04, 0x04, 0x03, 0x02, 0x05, 0xA0,
	0x30, 0x0C,
		0x06, 0x03, 0x55, 0x1D, 0x13,
		0x01, 0x01, 0xFF,
		0x04, 0x02, 0x30, 0x00
};

/*	One extension on its own, wrapper and all: the case that keeps the
 *	shapes from being told apart by length alone, since here the outer
 *	SEQUENCE and its one entry both span the whole buffer.		*/

static const unsigned char oneExtension[] = {
	0x30, 0x0E,			/*	Extension SEQUENCE.	*/
		0x06, 0x03, 0x55, 0x1D, 0x0F,	/*	keyUsage.	*/
		0x01, 0x01, 0xFF,
		0x04, 0x04, 0x03, 0x02, 0x05, 0xA0
};

static void test_has_extension(void)
{
	static const unsigned char keyUsage[] = { 0x55, 0x1D, 0x0F };
	static const unsigned char basicConstraints[] = { 0x55, 0x1D, 0x13 };
	static const unsigned char extKeyUsage[] = { 0x55, 0x1D, 0x25 };

	assert(tcpv4X509HasExtension(extensions, sizeof extensions, keyUsage,
				sizeof keyUsage));

	/*	The wrapped list answers the same, entry by entry, as the
	 *	bare one: a certificate does not become unrestricted
	 *	because its library kept one more layer of it.		*/

	assert(tcpv4X509HasExtension(wrappedExtensions,
				sizeof wrappedExtensions, keyUsage,
				sizeof keyUsage));
	assert(tcpv4X509HasExtension(wrappedExtensions,
				sizeof wrappedExtensions, basicConstraints,
				sizeof basicConstraints));
	assert(!tcpv4X509HasExtension(wrappedExtensions,
				sizeof wrappedExtensions, extKeyUsage,
				sizeof extKeyUsage));

	assert(tcpv4X509HasExtension(oneExtension, sizeof oneExtension,
				keyUsage, sizeof keyUsage));
	assert(!tcpv4X509HasExtension(oneExtension, sizeof oneExtension,
				extKeyUsage, sizeof extKeyUsage));

	/*	The one past the first is found too, so the walk really
	 *	steps over an entry rather than reading only the head of
	 *	the list.						*/

	assert(tcpv4X509HasExtension(extensions, sizeof extensions,
				basicConstraints, sizeof basicConstraints));

	/*	An extension that is not there is not there: this is what
	 *	tells "restricted to something else" from "unrestricted".	*/

	assert(!tcpv4X509HasExtension(extensions, sizeof extensions,
				extKeyUsage, sizeof extKeyUsage));

	/*	A certificate with no extensions at all, and a list this
	 *	code cannot walk, both answer "absent" rather than
	 *	wandering off the end of the buffer.			*/

	assert(!tcpv4X509HasExtension(NULL, 0, keyUsage, sizeof keyUsage));
	assert(!tcpv4X509HasExtension(extensions, 4, keyUsage,
				sizeof keyUsage));

	/*	An OID that merely begins like the one asked for is a
	 *	different OID.						*/

	assert(!tcpv4X509HasExtension(extensions, sizeof extensions, keyUsage,
				2));
}

int main(void)
{
	test_bundle_eid();
	test_bundle_eid_malformed();
	test_is_node_id();
	test_has_extension();
	return 0;
}
