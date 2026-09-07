/*
	tcpv4x509.h:	certificate decoding shared by the TLS backends of
			the TCPCLv4 convergence layer.

			RFC 9174 4.4.2 and 4.4.4 have an entity read things
			out of its peer's certificate that a TLS library
			will not read out for it: the node ID inside an
			id-on-bundleEID otherName (4.4.1), whether the URI
			it holds names a node at all, and - for a library
			whose API declines to say - whether an extension is
			present rather than merely permissive.  All three
			are DER decoding rather than cryptography, so they
			live here once rather than in every backend.

			This unit is deliberately free of any dependency on
			ION, on a TLS library, or on the rest of the CLA,
			so that it can be unit tested on its own.
								*/

#ifndef TCPV4X509_H
#define TCPV4X509_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*	Extract the URI from a BundleEID otherName value.  RFC 9174
 *	4.4.2.1 encodes it as an IA5String; Appendix C shows it inside the
 *	[0] EXPLICIT wrapper of AnotherName's value field.  A backend hands
 *	back the raw DER of that value for an OID its library does not
 *	know, which across libraries and versions is either the wrapper or
 *	the IA5String alone, so accept both.  Returns 0 on success, -1 if
 *	the value is not an IA5String this code can read.		*/
int tcpv4X509BundleEid(const unsigned char *der, size_t len, char *into,
		size_t cap);

/*	RFC 9174 4.4.1: an entry whose value is some URI other than a node
 *	ID is ignored rather than counted as a failed NODE-ID.  A node ID
 *	is an endpoint ID that names a node and nothing on it: for ipn that
 *	is service number 0, for dtn an empty demux (RFC 9171 4.2.5).  A
 *	scheme this code has no rule for is left in play, so that an exact
 *	match still authenticates it.  Returns non-zero when uri names a
 *	node.								*/
int tcpv4X509IsNodeId(const char *uri);

/*	Non-zero when the DER extension list der (the content of a
 *	certificate's Extensions SEQUENCE, each entry a SEQUENCE whose
 *	first element is the extension's OID) carries the extension named
 *	by oid, which is the OID's content octets - the encoding without
 *	its tag and length.  This answers "present?" where a backend's API
 *	answers only "permitted?", and RFC 5280 4.2.1.3 makes those
 *	different questions: an absent extension restricts nothing.	*/
int tcpv4X509HasExtension(const unsigned char *der, size_t len,
		const unsigned char *oid, size_t oidLen);

#ifdef __cplusplus
}
#endif

#endif /* TCPV4X509_H */
