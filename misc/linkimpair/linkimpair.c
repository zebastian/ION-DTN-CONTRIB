/*
 *	linkimpair.c - NFQUEUE link impairment daemon for ION-DTN benchmarks.
 *
 *	Holds packets that iptables has queued to NFQUEUE and releases them
 *	one one-way delay later, dropping a configurable share of them on the
 *	way.  That turns a loopback (or any) link into one with the round-trip
 *	time and loss rate a deployment would actually see, which is what a
 *	convergence layer's retransmission, flow control and congestion
 *	control behaviour depends on.
 *
 *	The delay is one-way: impairing both directions of a link (the usual
 *	iptables rule pair) makes the round-trip time twice -d.
 *
 *	Packets are released in the order they arrived, so jitter spreads
 *	arrival times without reordering; a reordering link is a different
 *	experiment and is deliberately not simulated here.
 *
 *	Modelled on owlt_delay.c from the ION-DTN simulator, which delays per
 *	destination to model light time; this one impairs whatever the queue
 *	is fed and adds loss, for benchmarking rather than for simulation.
 *
 *	Needs CAP_NET_ADMIN (run as root), and an iptables rule feeding the
 *	queue; see impair-link.
 *
 *	Usage:
 *	  linkimpair [-q queue] [-d delay_ms] [-j jitter_ms] [-l loss_pct]
 *		     [-s seed] [-v]
 */

#include <arpa/inet.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/libnfnetlink.h>
#include <linux/netfilter.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PKT_BUF_SIZE  (64 * 1024)
#define NL_RCVBUF_SIZE (4 * 1024 * 1024)

/*	One packet held until its delivery deadline.			*/
struct pending {
	uint32_t	id;
	struct timespec due;
	struct pending *next;
};

static struct pending *head = NULL;
static struct pending *tail = NULL;

static struct nfq_q_handle *qh = NULL;
static volatile int	    running = 1;

static long delayMs = 0;
static long jitterMs = 0;
static long lossPct = 0;
static int  verbose = 0;

static unsigned long long nPassed = 0;
static unsigned long long nDelayed = 0;
static unsigned long long nDropped = 0;

static void sigHandler(int sig)
{
	(void) sig;
	running = 0;
}

static void nowMonotonic(struct timespec *ts)
{
	clock_gettime(CLOCK_MONOTONIC, ts);
}

static int isDue(const struct timespec *due, const struct timespec *now)
{
	if (due->tv_sec != now->tv_sec) {
		return due->tv_sec < now->tv_sec;
	}

	return due->tv_nsec <= now->tv_nsec;
}

static void addMillis(struct timespec *ts, long ms)
{
	ts->tv_sec += ms / 1000;
	ts->tv_nsec += (ms % 1000) * 1000000L;
	if (ts->tv_nsec >= 1000000000L) {
		ts->tv_sec += 1;
		ts->tv_nsec -= 1000000000L;
	}
}

/*	Milliseconds until the head of the queue is due, for the poll timeout;
 *	-1 (wait indefinitely) when nothing is held.			*/
static int msUntilDue(void)
{
	struct timespec now;
	long		ms;

	if (head == NULL) {
		return -1;
	}

	nowMonotonic(&now);
	ms = (head->due.tv_sec - now.tv_sec) * 1000
			+ (head->due.tv_nsec - now.tv_nsec) / 1000000L;
	return ms > 0 ? (int) ms : 0;
}

/*	The delay this packet serves: -d, plus a uniform 0..-j of jitter.  */
static long packetDelay(void)
{
	long ms = delayMs;

	if (jitterMs > 0) {
		ms += random() % (jitterMs + 1);
	}

	return ms;
}

static int queueCb(struct nfq_q_handle *q, struct nfgenmsg *nfmsg,
		struct nfq_data *nfa, void *data)
{
	struct nfqnl_msg_packet_hdr *ph;
	struct pending		    *pkt;
	uint32_t		     id;
	long			     ms;

	(void) nfmsg;
	(void) data;

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph == NULL) {
		return 0;
	}

	id = ntohl(ph->packet_id);

	if (lossPct > 0 && (random() % 100) < lossPct) {
		nDropped++;
		return nfq_set_verdict(q, id, NF_DROP, 0, NULL);
	}

	ms = packetDelay();
	if (ms <= 0) {
		nPassed++;
		return nfq_set_verdict(q, id, NF_ACCEPT, 0, NULL);
	}

	pkt = malloc(sizeof(struct pending));
	if (pkt == NULL) {
		/*	Cannot hold it: pass it rather than lose it to an
		 *	allocation failure, and say so.			*/

		nPassed++;
		fprintf(stderr, "linkimpair: out of memory, packet passed\n");
		return nfq_set_verdict(q, id, NF_ACCEPT, 0, NULL);
	}

	pkt->id = id;
	pkt->next = NULL;
	nowMonotonic(&pkt->due);
	addMillis(&pkt->due, ms);

	if (tail != NULL) {
		tail->next = pkt;
	} else {
		head = pkt;
	}

	tail = pkt;
	nDelayed++;
	return 0; /* Verdict comes later, when it falls due.		*/
}

/*	Release every packet whose deadline has passed, oldest first.	*/
static void releaseDue(void)
{
	struct timespec now;

	nowMonotonic(&now);
	while (head != NULL && isDue(&head->due, &now)) {
		struct pending *pkt = head;

		head = pkt->next;
		if (head == NULL) {
			tail = NULL;
		}

		nfq_set_verdict(qh, pkt->id, NF_ACCEPT, 0, NULL);
		free(pkt);
	}
}

/*	Every queued packet must be given a verdict, or the kernel holds it
 *	until the queue overflows, so release what is left on the way out. */
static void releaseAll(void)
{
	while (head != NULL) {
		struct pending *pkt = head;

		head = pkt->next;
		nfq_set_verdict(qh, pkt->id, NF_ACCEPT, 0, NULL);
		free(pkt);
	}

	tail = NULL;
}

static void usage(void)
{
	fprintf(stderr,
			"Usage: linkimpair [-q queue] [-d delay_ms] "
			"[-j jitter_ms] [-l loss_pct] [-s seed] [-v]\n"
			"  -q  NFQUEUE number to bind (default 1)\n"
			"  -d  one-way delay, milliseconds (default 0)\n"
			"  -j  extra uniform jitter, 0..j ms (default 0)\n"
			"  -l  packets dropped, percent (default 0)\n"
			"  -s  seed for loss and jitter (default 1)\n"
			"  -v  report the packet counts on exit\n");
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	int		   queueNum = 1;
	unsigned int	   seed = 1;
	int		   fd;
	int		   i;
	char		   buf[PKT_BUF_SIZE] __attribute__((aligned));

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-q") == 0 && i + 1 < argc) {
			queueNum = atoi(argv[++i]);
		} else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
			delayMs = atol(argv[++i]);
		} else if (strcmp(argv[i], "-j") == 0 && i + 1 < argc) {
			jitterMs = atol(argv[++i]);
		} else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
			lossPct = atol(argv[++i]);
		} else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
			seed = (unsigned int) atoi(argv[++i]);
		} else if (strcmp(argv[i], "-v") == 0) {
			verbose = 1;
		} else {
			usage();
			return 1;
		}
	}

	if (delayMs < 0 || jitterMs < 0 || lossPct < 0 || lossPct > 100) {
		usage();
		return 1;
	}

	srandom(seed);
	signal(SIGTERM, sigHandler);
	signal(SIGINT, sigHandler);

	h = nfq_open();
	if (h == NULL) {
		perror("linkimpair: nfq_open (needs CAP_NET_ADMIN)");
		return 1;
	}

	qh = nfq_create_queue(h, queueNum, &queueCb, NULL);
	if (qh == NULL) {
		perror("linkimpair: nfq_create_queue");
		nfq_close(h);
		return 1;
	}

	/*	The packet itself is never inspected, only held, so ask the
	 *	kernel for the metadata alone.				*/

	if (nfq_set_mode(qh, NFQNL_COPY_META, 0) < 0) {
		perror("linkimpair: nfq_set_mode");
		nfq_destroy_queue(qh);
		nfq_close(h);
		return 1;
	}

	nfq_set_queue_maxlen(qh, 65535);
	nfnl_rcvbufsiz(nfq_nfnlh(h), NL_RCVBUF_SIZE);

	fprintf(stderr,
			"linkimpair: queue %d, one-way delay %ld ms "
			"(+0..%ld jitter), loss %ld%%\n",
			queueNum, delayMs, jitterMs, lossPct);

	fd = nfq_fd(h);
	while (running) {
		struct pollfd pfd;
		int	      rv;

		pfd.fd = fd;
		pfd.events = POLLIN;
		pfd.revents = 0;

		/*	Sleep no longer than the next packet is due, so it
		 *	leaves on time.					*/

		rv = poll(&pfd, 1, msUntilDue());
		if (rv < 0 && errno != EINTR) {
			perror("linkimpair: poll");
			break;
		}

		if (rv > 0 && (pfd.revents & POLLIN)) {
			int n = recv(fd, buf, sizeof(buf), 0);

			if (n >= 0) {
				nfq_handle_packet(h, buf, n);
			} else if (errno == ENOBUFS) {
				/*	The kernel outran us; packets were
				 *	lost, which for a loss test merely
				 *	adds to the loss.		*/

				fprintf(stderr, "linkimpair: ENOBUFS\n");
			} else if (errno != EINTR) {
				perror("linkimpair: recv");
				break;
			}
		}

		releaseDue();
	}

	releaseAll();

	if (verbose) {
		fprintf(stderr,
				"linkimpair: passed %llu, delayed %llu, "
				"dropped %llu\n",
				nPassed, nDelayed, nDropped);
	}

	nfq_destroy_queue(qh);
	nfq_close(h);
	return 0;
}
