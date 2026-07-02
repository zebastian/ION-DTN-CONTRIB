/*	mailcurl.c:	libcurl SMTP/POP3 transport for the mail CLA.	*/

#include "mailcurl.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <curl/curl.h>

int	mailCurlGlobalInit(void)
{
	return curl_global_init(CURL_GLOBAL_DEFAULT) == 0 ? 0 : -1;
}

void	mailCurlGlobalCleanup(void)
{
	curl_global_cleanup();
}

int	mailParseServerSpec(const char *spec, char *host, int *port,
		char *user, char *pass)
{
	const char	*at = strchr(spec, '@');
	const char	*hostpart = spec;
	const char	*colon;

	if (at != NULL)		/*	userinfo present			*/
	{
		const char	*sep = memchr(spec, ':', at - spec);
		size_t		 ulen = (sep ? sep : at) - spec;

		if (ulen >= MAIL_MAX_CRED)
		{
			return -1;
		}

		memcpy(user, spec, ulen);
		user[ulen] = '\0';
		if (sep != NULL)
		{
			size_t	plen = at - (sep + 1);

			if (plen >= MAIL_MAX_CRED)
			{
				return -1;
			}

			memcpy(pass, sep + 1, plen);
			pass[plen] = '\0';
		}

		hostpart = at + 1;
	}

	colon = strrchr(hostpart, ':');
	if (colon != NULL)
	{
		size_t	hostLen = colon - hostpart;

		if (hostLen == 0 || hostLen >= MAIL_MAX_HOST)
		{
			return -1;
		}

		memcpy(host, hostpart, hostLen);
		host[hostLen] = '\0';
		*port = atoi(colon + 1);
		if (*port <= 0 || *port > 65535)
		{
			return -1;
		}
	}
	else
	{
		istrcpy(host, hostpart, MAIL_MAX_HOST);
		*port = 0;
	}

	return 0;
}

static void	applyTls(CURL *curl, const MailServer *srv)
{
	if (srv->useTls)
	{
		curl_easy_setopt(curl, CURLOPT_USE_SSL, (long) CURLUSESSL_ALL);
	}

	if (srv->caFile[0] != '\0')
	{
		curl_easy_setopt(curl, CURLOPT_CAINFO, srv->caFile);
	}

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,
			(long) (srv->verifyPeer ? 1 : 0));
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,
			(long) (srv->verifyPeer ? 2 : 0));

	if (srv->username[0] != '\0')
	{
		curl_easy_setopt(curl, CURLOPT_USERNAME, srv->username);
	}

	if (srv->password[0] != '\0')
	{
		curl_easy_setopt(curl, CURLOPT_PASSWORD, srv->password);
	}
}

/*	*	*	SMTP send	*	*	*	*	*/

typedef struct
{
	const char *data;
	size_t	    len;
	size_t	    off;
} Upload;

static size_t	readCb(char *buffer, size_t size, size_t nitems, void *p)
{
	Upload *u = (Upload *) p;
	size_t	room = size * nitems;
	size_t	n = u->len - u->off;

	if (n > room)
	{
		n = room;
	}

	if (n > 0)
	{
		memcpy(buffer, u->data + u->off, n);
		u->off += n;
	}

	return n;
}

int	mailSmtpSend(const MailServer *srv, const char *from, const char *to,
		const char *msg, size_t msgLen, char *errbuf, size_t errcap)
{
	CURL		*curl;
	CURLcode	 res;
	struct curl_slist *rcpts = NULL;
	char		 url[MAIL_MAX_HOST + 32];
	char		 fromAddr[MAIL_MAX_ADDR + 4];
	char		 toAddr[MAIL_MAX_ADDR + 4];
	char		 curlErr[CURL_ERROR_SIZE];
	Upload		 up;

	curl = curl_easy_init();
	if (curl == NULL)
	{
		return -1;
	}

	snprintf(url, sizeof(url), "%s://%s:%d",
			srv->useSsl ? "smtps" : "smtp", srv->host, srv->port);
	snprintf(fromAddr, sizeof(fromAddr), "<%s>", from);
	snprintf(toAddr, sizeof(toAddr), "<%s>", to);

	curlErr[0] = '\0';
	up.data = msg;
	up.len = msgLen;
	up.off = 0;

	rcpts = curl_slist_append(rcpts, toAddr);

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_MAIL_FROM, fromAddr);
	curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, rcpts);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, readCb);
	curl_easy_setopt(curl, CURLOPT_READDATA, &up);
	curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t) msgLen);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlErr);
	applyTls(curl, srv);

	res = curl_easy_perform(curl);

	curl_slist_free_all(rcpts);
	curl_easy_cleanup(curl);

	if (res != CURLE_OK)
	{
		if (errbuf && errcap > 0)
		{
			snprintf(errbuf, errcap, "%s",
				curlErr[0] ? curlErr : curl_easy_strerror(res));
		}

		return -1;
	}

	return 0;
}

/*	*	*	POP3 poll	*	*	*	*	*/

typedef struct
{
	char  *p;
	size_t len;
	size_t cap;
} DBuf;

static size_t	writeCb(char *ptr, size_t size, size_t nmemb, void *p)
{
	DBuf  *b = (DBuf *) p;
	size_t n = size * nmemb;

	if (b->len + n + 1 > b->cap)
	{
		size_t	ncap = b->cap ? b->cap : 4096;
		char   *np;

		while (ncap < b->len + n + 1)
		{
			ncap *= 2;
		}

		np = realloc(b->p, ncap);
		if (np == NULL)
		{
			return 0;
		}

		b->p = np;
		b->cap = ncap;
	}

	memcpy(b->p + b->len, ptr, n);
	b->len += n;
	b->p[b->len] = '\0';
	return n;
}

static void	dbufReset(DBuf *b)
{
	b->len = 0;
	if (b->p)
	{
		b->p[0] = '\0';
	}
}

int	mailPop3Poll(const MailServer *srv, MailMsgCb cb, void *ctx,
		char *errbuf, size_t errcap)
{
	CURL	   *curl;
	CURLcode	res;
	char		base[MAIL_MAX_HOST + 32];
	char		url[MAIL_MAX_HOST + 64];
	char		curlErr[CURL_ERROR_SIZE];
	DBuf		buf;
	char	       *line;
	char	       *saveptr = NULL;
	char	       *listing = NULL;
	int		processed = 0;
	int		rc = 0;

	curl = curl_easy_init();
	if (curl == NULL)
	{
		return -1;
	}

	memset(&buf, 0, sizeof(buf));
	curlErr[0] = '\0';
	snprintf(base, sizeof(base), "%s://%s:%d/",
			srv->useSsl ? "pop3s" : "pop3", srv->host, srv->port);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlErr);
	applyTls(curl, srv);

	/*	LIST: enumerate message numbers.			*/

	curl_easy_setopt(curl, CURLOPT_URL, base);
	res = curl_easy_perform(curl);
	if (res != CURLE_OK)
	{
		if (errbuf && errcap > 0)
		{
			snprintf(errbuf, errcap, "%s",
				curlErr[0] ? curlErr : curl_easy_strerror(res));
		}

		free(buf.p);
		curl_easy_cleanup(curl);
		return -1;
	}

	listing = buf.p ? strdup(buf.p) : NULL;

	for (line = listing ? strtok_r(listing, "\r\n", &saveptr) : NULL;
			line != NULL && rc == 0;
			line = strtok_r(NULL, "\r\n", &saveptr))
	{
		int	msgnum = atoi(line);
		int	action;

		if (msgnum <= 0)
		{
			continue;
		}

		/*	RETR message msgnum.				*/

		dbufReset(&buf);
		snprintf(url, sizeof(url), "%s%d", base, msgnum);
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, NULL);
		res = curl_easy_perform(curl);
		if (res != CURLE_OK)
		{
			continue;	/*	skip this message	*/
		}

		action = cb(ctx, buf.p ? buf.p : "", buf.len);
		if (action < 0)
		{
			rc = -1;
			break;
		}

		processed++;

		if (action > 0)	/*	delete				*/
		{
			char	dele[32];

			snprintf(dele, sizeof(dele), "DELE %d", msgnum);
			curl_easy_setopt(curl, CURLOPT_URL, base);
			curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, dele);
			curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
			curl_easy_perform(curl);
			curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
			curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, NULL);
		}
	}

	free(listing);
	free(buf.p);
	curl_easy_cleanup(curl);
	return rc < 0 ? -1 : processed;
}
