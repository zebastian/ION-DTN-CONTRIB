/*	mailcurl.h:	libcurl SMTP/POP3 transport for the mail CLA.	*/

#ifndef MAILCURL_H
#define MAILCURL_H

#include "mailcla.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int	mailCurlGlobalInit(void);
void	mailCurlGlobalCleanup(void);

/*	Parse "[user:pass@]host[:port]"; port set to 0 when absent, and
 *	user/pass filled only when a userinfo prefix is present.	*/
int	mailParseServerSpec(const char *spec, char *host, int *port,
		char *user, char *pass);

int	mailSmtpSend(const MailServer *srv, const char *from, const char *to,
		const char *msg, size_t msgLen, char *errbuf, size_t errcap);

/*	Returns 1 to delete the message, 0 to keep it, <0 to abort.	*/
typedef int (*MailMsgCb)(void *ctx, const char *msg, size_t len);

/*	Poll the mailbox once, invoking cb per message.  Returns the
 *	number of messages processed (>= 0), or -1 on transport error.	*/
int	mailPop3Poll(const MailServer *srv, MailMsgCb cb, void *ctx,
		char *errbuf, size_t errcap);

#ifdef __cplusplus
}
#endif

#endif /* MAILCURL_H */
