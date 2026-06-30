/*
	bpcmdd.c:	a Bundle Protocol command daemon.

	Listens on a BP endpoint.  For every delivered bundle it forks a
	user-supplied command, pipes the bundle payload to that command's
	standard input, and (unless disabled) returns whatever the command
	writes to its standard output back to the bundle's source EID as a
	reply bundle.

	One child process is spawned per bundle (fork-per-bundle); bundles
	are processed serially.  The child sees BP_SOURCE_EID, BP_DEST_EID
	and BP_PAYLOAD_LEN in its environment.

	Built against an installed ION-DTN; uses only ION's public bp.h API.

	Author: Sebastian Jennen
									*/

#include <bp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static BpSAP sap;
static Sdr   sdr;
static int   running = 1;

static const char usage[] =
		"Usage: bpcmdd [-n] [-t ttl] <own endpoint ID> <command> [arg ...]\n\n"
		"Listens on the given BP endpoint.  For each delivered bundle, forks\n"
		"<command>, pipes the bundle payload to its stdin, and returns its\n"
		"stdout to the bundle source as a reply bundle.\n\n"
		"  -n        do not send the command's stdout back to the source\n"
		"  -t ttl    reply bundle lifetime in seconds (default 86400)\n\n"
		"The command sees BP_SOURCE_EID, BP_DEST_EID and BP_PAYLOAD_LEN in its\n"
		"environment.  Its stderr is inherited (appears on bpcmdd's stderr).\n";

static void handleQuit(int signum)
{
	/*	Tell the compiler that we are not using 'signum'.	*/
	(void) signum;

	isignal(SIGINT, handleQuit);
	PUTS("BP reception interrupted.");
	fflush(NULL);
	running = 0;
	bp_interrupt(sap);
}

/*	Reads the entire payload of a delivered bundle into a freshly
 *	malloc'd buffer.  Returns the buffer (caller frees) and sets
 *	*length, or NULL on failure.  A zero-length payload yields a
 *	1-byte buffer and *length == 0.				*/

static char *readPayload(Object adu, int *length)
{
	ZcoReader reader;
	vast	  contentLength;
	char	 *buffer;
	int	  len;

	CHKNULL(sdr_begin_xn(sdr));
	contentLength = zco_source_data_length(sdr, adu);
	sdr_exit_xn(sdr);
	if (contentLength < 0)
	{
		putErrmsg("bpcmdd can't get payload length.", NULL);
		return NULL;
	}

	buffer = MTAKE(contentLength == 0 ? 1 : (size_t) contentLength);
	if (buffer == NULL)
	{
		putErrmsg("bpcmdd can't allocate payload buffer.", NULL);
		return NULL;
	}

	if (contentLength > 0)
	{
		zco_start_receiving(adu, &reader);
		CHKNULL(sdr_begin_xn(sdr));
		len = zco_receive_source(sdr, &reader, contentLength, buffer);
		if (sdr_end_xn(sdr) < 0 || len < 0)
		{
			putErrmsg("bpcmdd can't read payload.", NULL);
			MRELEASE(buffer);
			return NULL;
		}
	}

	*length = (int) contentLength;
	return buffer;
}

/*	Forks the command, feeds it the payload on stdin (via a dedicated
 *	feeder child to avoid stdin/stdout pipe deadlock), and collects
 *	its stdout into a malloc'd buffer.  Returns the command's exit
 *	code (or -1 if it could not be run); *replyBuf / *replyLen receive
 *	the captured stdout (caller frees *replyBuf when non-NULL).	*/

static int runCommand(char **cmdArgv, char *payload, int payloadLen,
		char *srcEid, char *ownEid, char **replyBuf, int *replyLen)
{
	int    inPipe[2];
	int    outPipe[2];
	pid_t  cmdPid;
	pid_t  feederPid;
	char   lenStr[32];
	size_t cap = 4096;
	size_t len = 0;
	char  *buffer;
	int    status;

	*replyBuf = NULL;
	*replyLen = 0;

	if (pipe(inPipe) < 0)
	{
		putSysErrmsg("bpcmdd can't create stdin pipe.", NULL);
		return -1;
	}

	if (pipe(outPipe) < 0)
	{
		putSysErrmsg("bpcmdd can't create stdout pipe.", NULL);
		close(inPipe[0]);
		close(inPipe[1]);
		return -1;
	}

	cmdPid = fork();
	if (cmdPid == 0) /*	Command child.	*/
	{
		dup2(inPipe[0], STDIN_FILENO);
		dup2(outPipe[1], STDOUT_FILENO);
		close(inPipe[0]);
		close(inPipe[1]);
		close(outPipe[0]);
		close(outPipe[1]);
		if (srcEid)
		{
			setenv("BP_SOURCE_EID", srcEid, 1);
		}

		setenv("BP_DEST_EID", ownEid, 1);
		isprintf(lenStr, sizeof lenStr, "%d", payloadLen);
		setenv("BP_PAYLOAD_LEN", lenStr, 1);
		execvp(cmdArgv[0], cmdArgv);
		_exit(127); /*	exec failed.	*/
	}

	if (cmdPid < 0)
	{
		putSysErrmsg("bpcmdd can't fork command.", cmdArgv[0]);
		close(inPipe[0]);
		close(inPipe[1]);
		close(outPipe[0]);
		close(outPipe[1]);
		return -1;
	}

	close(inPipe[0]);
	close(outPipe[1]);

	feederPid = fork();
	if (feederPid == 0) /*	Feeder child.	*/
	{
		int off = 0;
		int n;

		close(outPipe[0]);
		while (off < payloadLen)
		{
			n = write(inPipe[1], payload + off, payloadLen - off);
			if (n < 0)
			{
				if (errno == EINTR)
				{
					continue;
				}

				break; /*	e.g. EPIPE.	*/
			}

			off += n;
		}

		close(inPipe[1]);
		_exit(0);
	}

	close(inPipe[1]);
	if (feederPid < 0)
	{
		putSysErrmsg("bpcmdd can't fork payload feeder.", NULL);
		/*	Command child still drains stdin to EOF on close.*/
	}

	buffer = malloc(cap);
	if (buffer == NULL)
	{
		putErrmsg("bpcmdd can't allocate stdout buffer.", NULL);
		close(outPipe[0]);
	}
	else
	{
		for (;;)
		{
			ssize_t n;

			if (len == cap)
			{
				char *bigger;

				cap *= 2;
				bigger = realloc(buffer, cap);
				if (bigger == NULL)
				{
					putErrmsg("bpcmdd out of memory for "
						  "stdout.",
							NULL);
					free(buffer);
					buffer = NULL;
					break;
				}

				buffer = bigger;
			}

			n = read(outPipe[0], buffer + len, cap - len);
			if (n < 0)
			{
				if (errno == EINTR)
				{
					continue;
				}

				break;
			}

			if (n == 0)
			{
				break; /*	EOF.		*/
			}

			len += n;
		}

		close(outPipe[0]);
	}

	while (waitpid(cmdPid, &status, 0) < 0 && errno == EINTR)
	{
		continue;
	}

	if (feederPid > 0)
	{
		while (waitpid(feederPid, NULL, 0) < 0 && errno == EINTR)
		{
			continue;
		}
	}

	*replyBuf = buffer;
	*replyLen = (int) len;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/*	Sends the captured stdout back to the bundle source as a reply
 *	bundle.								*/

static void sendReply(char *destEid, char *data, int dataLen, int replyTtl)
{
	Object payload;
	Object zco;
	Object newBundle;

	CHKVOID(sdr_begin_xn(sdr));
	payload = sdr_malloc(sdr, dataLen);
	if (payload)
	{
		sdr_write(sdr, payload, data, dataLen);
	}

	if (sdr_end_xn(sdr) < 0 || payload == 0)
	{
		putErrmsg("bpcmdd can't allocate reply payload.", NULL);
		return;
	}

	zco = ionCreateZco(ZcoSdrSource, payload, 0, dataLen, BP_STD_PRIORITY,
			0, ZcoOutbound, NULL);
	if (zco == 0 || zco == (Object) ERROR)
	{
		putErrmsg("bpcmdd can't create reply ZCO.", NULL);
		return;
	}

	if (bp_send(sap, destEid, NULL, replyTtl, BP_STD_PRIORITY,
			    NoCustodyRequested, 0, 0, NULL, zco, &newBundle) <= 0)
	{
		putErrmsg("bpcmdd can't send reply bundle.", destEid);
		CHKVOID(sdr_begin_xn(sdr));
		zco_destroy(sdr, zco);
		if (sdr_end_xn(sdr) < 0)
		{
			putErrmsg("bpcmdd can't destroy reply ZCO.", NULL);
		}
	}
}

int main(int argc, char **argv)
{
	int	   reply = 1;
	int	   replyTtl = 86400;
	char	  *ownEid;
	char	 **cmdArgv;
	BpDelivery dlv;
	int	   c;

	while ((c = getopt(argc, argv, "nt:")) != -1)
	{
		switch (c)
		{
		case 'n':
			reply = 0;
			break;

		case 't':
			replyTtl = atoi(optarg);
			if (replyTtl <= 0)
			{
				PUTS("bpcmdd: ttl must be a positive integer.");
				return 1;
			}

			break;

		default:
			PUTS(usage);
			return 1;
		}
	}

	if (optind + 1 >= argc) /*	Need EID + command.*/
	{
		PUTS(usage);
		return 1;
	}

	ownEid = argv[optind];
	cmdArgv = &argv[optind + 1];

	setlinebuf(stdout);
	isignal(SIGPIPE, SIG_IGN);

	if (bp_attach() < 0)
	{
		putErrmsg("bpcmdd can't attach to BP.", NULL);
		return 1;
	}

	if (bp_open(ownEid, &sap) < 0)
	{
		putErrmsg("bpcmdd can't open own endpoint.", ownEid);
		bp_detach();
		return 1;
	}

	sdr = bp_get_sdr();
	isignal(SIGINT, handleQuit);

	while (running)
	{
		char *payload;
		int   payloadLen = 0;
		char *replyBuf;
		int   replyLen;

		if (bp_receive(sap, &dlv, BP_BLOCKING) < 0)
		{
			putErrmsg("bpcmdd bundle reception failed.", NULL);
			running = 0;
			continue;
		}

		if (dlv.result == BpReceptionInterrupted || dlv.adu == 0)
		{
			bp_release_delivery(&dlv, 1);
			continue;
		}

		if (dlv.result == BpEndpointStopped)
		{
			bp_release_delivery(&dlv, 1);
			break;
		}

		if (dlv.result != BpPayloadPresent)
		{
			bp_release_delivery(&dlv, 1);
			continue;
		}

		payload = readPayload(dlv.adu, &payloadLen);
		if (payload == NULL)
		{
			bp_release_delivery(&dlv, 1);
			continue;
		}

		oK(runCommand(cmdArgv, payload, payloadLen, dlv.bundleSourceEid,
				ownEid, &replyBuf, &replyLen));
		MRELEASE(payload);

		if (reply && replyBuf && replyLen > 0 && dlv.bundleSourceEid &&
				strcmp(dlv.bundleSourceEid, "dtn:none") != 0)
		{
			sendReply(dlv.bundleSourceEid, replyBuf, replyLen,
					replyTtl);
		}

		if (replyBuf)
		{
			free(replyBuf);
		}

		bp_release_delivery(&dlv, 1);
	}

	bp_close(sap);
	writeErrmsgMemos();
	PUTS("Stopping bpcmdd.");
	fflush(NULL);
	bp_detach();
	return 0;
}
