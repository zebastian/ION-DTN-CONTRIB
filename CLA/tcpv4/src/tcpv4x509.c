/*
	tcpv4x509.c:	certificate decoding shared by the TLS backends.
			See tcpv4x509.h.
								*/

#include "tcpv4x509.h"
#include <string.h>

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

int tcpv4X509BundleEid(const unsigned char *der, size_t len, char *into,
		size_t cap)
{
	size_t off = 0;
	size_t vlen;
	size_t end = len;

	if (der == NULL || into == NULL || cap == 0)
	{
		return -1;
	}

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

int tcpv4X509IsNodeId(const char *uri)
{
	size_t len;

	if (uri == NULL)
	{
		return 0;
	}

	len = strlen(uri);
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

int tcpv4X509HasExtension(const unsigned char *der, size_t len,
		const unsigned char *oid, size_t oidLen)
{
	size_t off = 0;
	size_t vlen;

	if (der == NULL || oid == NULL || oidLen == 0)
	{
		return 0;
	}

	/*	Extensions ::= SEQUENCE OF Extension, and a backend hands
	 *	back whichever of the two its library kept: the SEQUENCE
	 *	with its header, or the entries alone.  The two are told
	 *	apart by what comes first inside - an Extension begins with
	 *	its OID, the SEQUENCE with another SEQUENCE - so a caller
	 *	need not know which it has.				*/

	if (derTlv(der, len, &off, 0x30, &vlen) == 0 && off + vlen == len)
	{
		size_t inner = off;
		size_t ilen;

		if (derTlv(der, len, &inner, 0x30, &ilen) == 0)
		{
			der += off;
			len = vlen;
		}
	}

	off = 0;

	/*	Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER,
	 *	critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
	 *	(RFC 5280 4.1).  Only the OID is of interest here, so each
	 *	entry is entered far enough to read it and then skipped.	*/

	while (off < len)
	{
		size_t seqLen;
		size_t seqEnd;
		size_t idLen;

		if (derTlv(der, len, &off, 0x30, &seqLen) < 0)
		{
			return 0; /* Not a list this code can walk.	*/
		}

		seqEnd = off + seqLen;
		if (derTlv(der, seqEnd, &off, 0x06, &idLen) < 0)
		{
			return 0;
		}

		if (idLen == oidLen && memcmp(der + off, oid, oidLen) == 0)
		{
			return 1;
		}

		off = seqEnd;
	}

	return 0;
}
