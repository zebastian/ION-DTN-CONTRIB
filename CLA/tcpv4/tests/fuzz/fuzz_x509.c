/*
	fuzz_x509.c:	fuzz target for the certificate decoding the TLS
			backends share.

	The input is DER as a peer's certificate would carry it.  The
	BundleEID extraction must produce a terminated string or fail,
	and the extension lookup must stay inside the list it is given,
	whether the OID it looks for is a fixed one or is itself taken
	from the input.

	Built two ways: as a libFuzzer target (`make fuzz`), and against
	fuzz_replay.c to replay the checked-in corpus under `make check`.
									*/

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "tcpv4x509.h"

static const unsigned char keyUsageOid[] = {0x55, 0x1d, 0x0f};
static const unsigned char extKeyUsageOid[] = {0x55, 0x1d, 0x25};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len)
{
	unsigned char *der;
	char	      *text;
	char	       uri[256];
	size_t	       oidLen;

	/*	A copy of exactly len octets, so that a sanitizer sees any
	 *	read past the end of it.				*/

	der = malloc(len > 0 ? len : 1);
	assert(der != NULL);
	memcpy(der, data, len);

	if (tcpv4X509BundleEid(der, len, uri, sizeof(uri)) == 0)
	{
		assert(memchr(uri, '\0', sizeof(uri)) != NULL);
		(void) tcpv4X509IsNodeId(uri);
	}

	(void) tcpv4X509HasExtension(der, len, keyUsageOid,
			sizeof(keyUsageOid));
	(void) tcpv4X509HasExtension(der, len, extKeyUsageOid,
			sizeof(extKeyUsageOid));

	/*	The first octet gives the length of an OID that follows it;
	 *	the rest is the extension list to look for it in.	*/

	if (len > 1 && (size_t) der[0] < len - 1)
	{
		oidLen = der[0];
		(void) tcpv4X509HasExtension(der + 1 + oidLen,
				len - 1 - oidLen, der + 1, oidLen);
	}

	text = strndup((const char *) data, len);
	assert(text != NULL);
	(void) tcpv4X509IsNodeId(text);

	free(text);
	free(der);
	return 0;
}
