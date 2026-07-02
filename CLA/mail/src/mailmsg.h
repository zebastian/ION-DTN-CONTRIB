/*	mailmsg.h:	encoding/framing core for the mail CLA (no ION,
			no libcurl deps; unit-tested standalone).	*/

#ifndef MAILMSG_H
#define MAILMSG_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAIL_ENC_ATTACH 0 /*	one bundle per MIME attachment (default)	*/
#define MAIL_ENC_B64	1 /*	base64 blob(s) in body			*/
#define MAIL_ENC_RAW	2 /*	raw bundle bytes in body		*/

#define MAIL_SEPARATOR "--ION-BUNDLE-MAIL-SEPARATOR--"

#define MAIL_HDR_ENCODING "X-ION-Bundle-Encoding"
#define MAIL_HDR_COUNT	  "X-ION-Bundle-Count"

int	    mailEncodingFromName(const char *name);
const char *mailEncodingName(int encoding);

size_t	mailB64EncodedLen(size_t rawLen);
int	mailB64Encode(const unsigned char *in, size_t inLen, char *out,
		size_t outCap);
int	mailB64Decode(const char *in, size_t inLen, unsigned char *out,
		size_t outCap, size_t *outLen);

typedef struct
{
	const unsigned char *bytes;
	size_t		     len;
} MailBundle;

int	mailBuildMessage(const char *from, const char *to, const char *subject,
		int encoding, const MailBundle *bundles, size_t count,
		char **out, size_t *outLen);

typedef int (*MailBundleCb)(void *ctx, const unsigned char *bundle,
		size_t len);

int	mailParseMessage(const char *msg, size_t msgLen, int encoding,
		MailBundleCb cb, void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* MAILMSG_H */
