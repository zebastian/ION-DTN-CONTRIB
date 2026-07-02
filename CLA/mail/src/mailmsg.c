/*	mailmsg.c:	encoding/framing core for the mail CLA.		*/

#include "mailmsg.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MAIL_BOUNDARY  "ION-BUNDLE-MAIL-SEPARATOR"
#define CRLF	       "\r\n"
#define DEFAULT_SUBJECT "ION-DTN Bundle"

static const char b64tab[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int	mailEncodingFromName(const char *name)
{
	if (name == NULL)			return -1;
	if (strcmp(name, "attach") == 0)	return MAIL_ENC_ATTACH;
	if (strcmp(name, "b64") == 0)		return MAIL_ENC_B64;
	if (strcmp(name, "raw") == 0)		return MAIL_ENC_RAW;
	return -1;
}

const char *mailEncodingName(int encoding)
{
	switch (encoding)
	{
	case MAIL_ENC_ATTACH:	return "attach";
	case MAIL_ENC_B64:	return "b64";
	case MAIL_ENC_RAW:	return "raw";
	default:		return "?";
	}
}

size_t	mailB64EncodedLen(size_t rawLen)
{
	return ((rawLen + 2) / 3) * 4 + 1;
}

int	mailB64Encode(const unsigned char *in, size_t inLen, char *out,
		size_t outCap)
{
	size_t	i;
	size_t	o = 0;
	size_t	rem;

	if (outCap < mailB64EncodedLen(inLen))
	{
		return -1;
	}

	for (i = 0; i + 3 <= inLen; i += 3)
	{
		unsigned v = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];

		out[o++] = b64tab[(v >> 18) & 0x3f];
		out[o++] = b64tab[(v >> 12) & 0x3f];
		out[o++] = b64tab[(v >> 6) & 0x3f];
		out[o++] = b64tab[v & 0x3f];
	}

	rem = inLen - i;
	if (rem == 1)
	{
		unsigned v = in[i] << 16;

		out[o++] = b64tab[(v >> 18) & 0x3f];
		out[o++] = b64tab[(v >> 12) & 0x3f];
		out[o++] = '=';
		out[o++] = '=';
	}
	else if (rem == 2)
	{
		unsigned v = (in[i] << 16) | (in[i + 1] << 8);

		out[o++] = b64tab[(v >> 18) & 0x3f];
		out[o++] = b64tab[(v >> 12) & 0x3f];
		out[o++] = b64tab[(v >> 6) & 0x3f];
		out[o++] = '=';
	}

	out[o] = '\0';
	return 0;
}

static int	b64val(int c)
{
	if (c >= 'A' && c <= 'Z')	return c - 'A';
	if (c >= 'a' && c <= 'z')	return c - 'a' + 26;
	if (c >= '0' && c <= '9')	return c - '0' + 52;
	if (c == '+')			return 62;
	if (c == '/')			return 63;
	return -1;
}

int	mailB64Decode(const char *in, size_t inLen, unsigned char *out,
		size_t outCap, size_t *outLen)
{
	unsigned	acc = 0;
	int		bits = 0;
	size_t		o = 0;
	size_t		i;

	for (i = 0; i < inLen; i++)
	{
		int	c = (unsigned char) in[i];
		int	v;

		if (c == '=')
		{
			break;
		}

		if (c == ' ' || c == '\r' || c == '\n' || c == '\t')
		{
			continue;
		}

		v = b64val(c);
		if (v < 0)
		{
			return -1;
		}

		acc = (acc << 6) | v;
		bits += 6;
		if (bits >= 8)
		{
			bits -= 8;
			if (o >= outCap)
			{
				return -1;
			}

			out[o++] = (unsigned char) ((acc >> bits) & 0xff);
		}
	}

	if (outLen)
	{
		*outLen = o;
	}

	return 0;
}

/*	*	*	Growable output buffer	*	*	*	*/

typedef struct
{
	char  *p;
	size_t len;
	size_t cap;
} Buf;

static int	bufEnsure(Buf *b, size_t extra)
{
	if (b->len + extra + 1 > b->cap)
	{
		size_t	ncap = b->cap ? b->cap : 1024;
		char   *np;

		while (ncap < b->len + extra + 1)
		{
			ncap *= 2;
		}

		np = realloc(b->p, ncap);
		if (np == NULL)
		{
			return -1;
		}

		b->p = np;
		b->cap = ncap;
	}

	return 0;
}

static int	bufAppend(Buf *b, const char *data, size_t n)
{
	if (bufEnsure(b, n) < 0)
	{
		return -1;
	}

	memcpy(b->p + b->len, data, n);
	b->len += n;
	b->p[b->len] = '\0';
	return 0;
}

static int	bufStr(Buf *b, const char *s)
{
	return bufAppend(b, s, strlen(s));
}

/*	Append base64 of a bundle, wrapped at 76 columns.		*/
static int	bufB64(Buf *b, const MailBundle *bundle)
{
	size_t	cap = mailB64EncodedLen(bundle->len);
	char   *enc = malloc(cap);
	size_t	i;
	size_t	enclen;
	int	rc = 0;

	if (enc == NULL)
	{
		return -1;
	}

	if (mailB64Encode(bundle->bytes, bundle->len, enc, cap) < 0)
	{
		free(enc);
		return -1;
	}

	enclen = strlen(enc);
	for (i = 0; i < enclen; i += 76)
	{
		size_t	n = enclen - i < 76 ? enclen - i : 76;

		if (bufAppend(b, enc + i, n) < 0 || bufStr(b, CRLF) < 0)
		{
			rc = -1;
			break;
		}
	}

	free(enc);
	return rc;
}

int	mailBuildMessage(const char *from, const char *to, const char *subject,
		int encoding, const MailBundle *bundles, size_t count,
		char **out, size_t *outLen)
{
	Buf	b;
	char	line[256];
	size_t	i;

	if (from == NULL || to == NULL || bundles == NULL || count == 0
			|| out == NULL || outLen == NULL)
	{
		return -1;
	}

	if (subject == NULL)
	{
		subject = DEFAULT_SUBJECT;
	}

	memset(&b, 0, sizeof(b));

	snprintf(line, sizeof(line), "From: %s" CRLF, from);
	if (bufStr(&b, line) < 0) goto fail;
	snprintf(line, sizeof(line), "To: %s" CRLF, to);
	if (bufStr(&b, line) < 0) goto fail;
	snprintf(line, sizeof(line), "Subject: %s" CRLF, subject);
	if (bufStr(&b, line) < 0) goto fail;
	if (bufStr(&b, "MIME-Version: 1.0" CRLF) < 0) goto fail;
	snprintf(line, sizeof(line), "%s: %s" CRLF, MAIL_HDR_ENCODING,
			mailEncodingName(encoding));
	if (bufStr(&b, line) < 0) goto fail;
	snprintf(line, sizeof(line), "%s: %zu" CRLF, MAIL_HDR_COUNT, count);
	if (bufStr(&b, line) < 0) goto fail;

	if (encoding == MAIL_ENC_ATTACH)
	{
		if (bufStr(&b, "Content-Type: multipart/mixed; boundary=\""
				MAIL_BOUNDARY "\"" CRLF CRLF) < 0) goto fail;

		for (i = 0; i < count; i++)
		{
			if (bufStr(&b, "--" MAIL_BOUNDARY CRLF) < 0) goto fail;
			snprintf(line, sizeof(line),
				"Content-Type: application/octet-stream; "
				"name=\"bundle%zu.bp\"" CRLF, i + 1);
			if (bufStr(&b, line) < 0) goto fail;
			if (bufStr(&b, "Content-Transfer-Encoding: base64"
					CRLF CRLF) < 0) goto fail;
			if (bufB64(&b, &bundles[i]) < 0) goto fail;
		}

		if (bufStr(&b, "--" MAIL_BOUNDARY "--" CRLF) < 0) goto fail;
	}
	else
	{
		if (bufStr(&b, "Content-Type: text/plain" CRLF CRLF) < 0)
			goto fail;

		for (i = 0; i < count; i++)
		{
			if (i > 0
			&& bufStr(&b, CRLF MAIL_SEPARATOR CRLF) < 0) goto fail;

			if (encoding == MAIL_ENC_B64)
			{
				if (bufB64(&b, &bundles[i]) < 0) goto fail;
			}
			else	/*	MAIL_ENC_RAW			*/
			{
				if (bufAppend(&b, (const char *) bundles[i].bytes,
						bundles[i].len) < 0) goto fail;
			}
		}
	}

	*out = b.p;
	*outLen = b.len;
	return 0;

fail:
	free(b.p);
	return -1;
}

/*	*	*	Parsing	*	*	*	*	*	*/

static const char *memfind(const char *hay, size_t haylen, const char *ndl,
		size_t ndllen)
{
	if (ndllen == 0 || haylen < ndllen)
	{
		return NULL;
	}

	for (; haylen >= ndllen; hay++, haylen--)
	{
		if (memcmp(hay, ndl, ndllen) == 0)
		{
			return hay;
		}
	}

	return NULL;
}

/*	Locate the start of the body (past the header/body blank line).	*/
static const char *bodyStart(const char *msg, size_t msgLen, size_t *bodyLen)
{
	const char *sep = memfind(msg, msgLen, CRLF CRLF, 4);
	size_t	    off;

	if (sep != NULL)
	{
		off = (sep - msg) + 4;
	}
	else if ((sep = memfind(msg, msgLen, "\n\n", 2)) != NULL)
	{
		off = (sep - msg) + 2;
	}
	else
	{
		off = 0;
	}

	*bodyLen = msgLen - off;
	return msg + off;
}

/*	Read the multipart boundary declared in the top headers.	*/
static int	findBoundary(const char *msg, size_t hdrLen, char *out,
		size_t outCap)
{
	const char *b = memfind(msg, hdrLen, "boundary=", 9);
	const char *p;
	size_t	    n = 0;

	if (b == NULL)
	{
		return -1;
	}

	p = b + 9;
	if (p < msg + hdrLen && *p == '"')
	{
		p++;
		while (p < msg + hdrLen && *p != '"' && n + 1 < outCap)
		{
			out[n++] = *p++;
		}
	}
	else
	{
		while (p < msg + hdrLen && *p != '\r' && *p != '\n'
				&& *p != ';' && *p != ' ' && n + 1 < outCap)
		{
			out[n++] = *p++;
		}
	}

	out[n] = '\0';
	return n > 0 ? 0 : -1;
}

static int	deliverB64(const char *chunk, size_t len, MailBundleCb cb,
		void *ctx)
{
	unsigned char  *raw;
	size_t		rawlen;
	int		rc;

	if (len == 0)
	{
		return 0;
	}

	raw = malloc(len);	/*	decoded is always smaller		*/
	if (raw == NULL)
	{
		return -1;
	}

	if (mailB64Decode(chunk, len, raw, len, &rawlen) < 0 || rawlen == 0)
	{
		free(raw);
		return 0;	/*	not a bundle; skip			*/
	}

	rc = cb(ctx, raw, rawlen);
	free(raw);
	return rc < 0 ? -1 : 1;
}

static int	parseAttach(const char *msg, size_t msgLen, MailBundleCb cb,
		void *ctx)
{
	char		boundary[128];
	char		delim[132];
	const char     *body;
	size_t		bodyLen;
	size_t		hdrLen;
	const char     *sep = memfind(msg, msgLen, CRLF CRLF, 4);
	const char     *p;
	const char     *end;
	size_t		dlen;
	int		count = 0;

	hdrLen = sep ? (size_t) (sep - msg) : msgLen;
	if (findBoundary(msg, hdrLen, boundary, sizeof(boundary)) < 0)
	{
		return 0;
	}

	snprintf(delim, sizeof(delim), "--%s", boundary);
	dlen = strlen(delim);
	body = bodyStart(msg, msgLen, &bodyLen);
	end = body + bodyLen;

	p = memfind(body, bodyLen, delim, dlen);
	while (p != NULL)
	{
		const char *partHdr = p + dlen;
		const char *partBody;
		const char *next;
		const char *hsep;
		int	    rc;

		if (partHdr + 2 <= end && partHdr[0] == '-' && partHdr[1] == '-')
		{
			break;		/*	closing delimiter		*/
		}

		hsep = memfind(partHdr, end - partHdr, CRLF CRLF, 4);
		if (hsep == NULL)
		{
			break;
		}

		partBody = hsep + 4;
		next = memfind(partBody, end - partBody, delim, dlen);
		if (next == NULL)
		{
			break;
		}

		/*	Trim the CRLF that precedes the next delimiter.	*/
		{
			const char *bend = next;

			if (bend - partBody >= 2 && bend[-2] == '\r'
					&& bend[-1] == '\n')
			{
				bend -= 2;
			}

			rc = deliverB64(partBody, bend - partBody, cb, ctx);
			if (rc < 0)
			{
				return -1;
			}

			if (rc > 0)
			{
				count++;
			}
		}

		p = next;
	}

	return count;
}

static int	parseBody(const char *msg, size_t msgLen, int encoding,
		MailBundleCb cb, void *ctx)
{
	const char     *body;
	size_t		bodyLen;
	const char     *p;
	const char     *end;
	int		count = 0;
	int		first = 1;

	body = bodyStart(msg, msgLen, &bodyLen);
	end = body + bodyLen;
	p = body;

	while (p < end)
	{
		const char *sep = memfind(p, end - p, MAIL_SEPARATOR,
				strlen(MAIL_SEPARATOR));
		const char *chunkEnd = sep ? sep : end;
		const char *chunk = p;
		size_t	    len;
		int	    rc;

		/*	Strip the delimiter-introduced CRLFs.		*/
		if (!first && chunkEnd - chunk >= 2 && chunk[0] == '\r'
				&& chunk[1] == '\n')
		{
			chunk += 2;
		}

		if (sep && chunkEnd - chunk >= 2 && chunkEnd[-2] == '\r'
				&& chunkEnd[-1] == '\n')
		{
			chunkEnd -= 2;
		}

		len = chunkEnd - chunk;
		if (encoding == MAIL_ENC_B64)
		{
			rc = deliverB64(chunk, len, cb, ctx);
			if (rc < 0)
			{
				return -1;
			}

			if (rc > 0)
			{
				count++;
			}
		}
		else if (len > 0)	/*	MAIL_ENC_RAW			*/
		{
			if (cb(ctx, (const unsigned char *) chunk, len) < 0)
			{
				return -1;
			}

			count++;
		}

		if (sep == NULL)
		{
			break;
		}

		p = sep + strlen(MAIL_SEPARATOR);
		first = 0;
	}

	return count;
}

int	mailParseMessage(const char *msg, size_t msgLen, int encoding,
		MailBundleCb cb, void *ctx)
{
	if (msg == NULL || cb == NULL)
	{
		return -1;
	}

	if (encoding == MAIL_ENC_ATTACH)
	{
		return parseAttach(msg, msgLen, cb, ctx);
	}

	return parseBody(msg, msgLen, encoding, cb, ctx);
}
