/*	mailcla.h:	common definitions for the mail CLA daemons.	*/

#ifndef MAILCLA_H
#define MAILCLA_H

#include "bpP.h"
#include "mailmsg.h"
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAILCLA_BUFSZ		(256 * 1024)
#define MAIL_MAX_HOST		256
#define MAIL_MAX_CRED		256
#define MAIL_MAX_PATH		1024
#define MAIL_MAX_ADDR		256
#define MAIL_DEFAULT_POLL	30
#define MAIL_DEFAULT_DIGEST_MAX	64
#define MAIL_MAX_RECONNECT_PAUSE 30

typedef struct
{
	char	host[MAIL_MAX_HOST];
	int	port;
	char	username[MAIL_MAX_CRED];
	char	password[MAIL_MAX_CRED];
	int	useSsl;		/*	implicit TLS (smtps/pop3s)	*/
	int	useTls;		/*	STARTTLS / STLS			*/
	char	caFile[MAIL_MAX_PATH];
	int	verifyPeer;
} MailServer;

typedef struct
{
	MailServer	server;
	char		sender[MAIL_MAX_ADDR];
	int		encoding;
	int		digestSecs;	/*	0 = send immediately	*/
	int		maxBundles;	/*	digest cap		*/
	long		maxBytes;	/*	digest cap, 0 = none	*/
} MailCloConfig;

typedef struct
{
	MailServer	server;
	int		encoding;
	int		pollSecs;
} MailCliConfig;

#ifdef __cplusplus
}
#endif

#endif /* MAILCLA_H */
