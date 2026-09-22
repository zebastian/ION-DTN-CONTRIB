/*
	bptun.c:	IP over Bundle Protocol, through a TUN device.

	bptun owns a TUN network interface and a BP endpoint.  Every IP
	packet the kernel routes into the interface is sent as the payload
	of one bundle to the endpoint of the bptun serving the packet's
	destination, as a route table of address prefixes says; every
	bundle delivered to the endpoint is written into the interface as
	a packet.  Applications on either side use the interface like any
	other IP link - a slow, lossy one that keeps working across
	disruptions for as long as the bundles' lifetime allows.

	The interface is left for the operator to configure (address,
	MTU, up) with "ip", as for any tunnel device, unless -a and -m
	are given, which do the IPv4 case here.  The MTU is what bounds
	the size of a bundle: one packet is one bundle.

	Payload format.  The first byte of every payload names its
	format, so that the format can grow (batching several packets
	into one bundle is the intent) without a flag day:

		0x01	BPTUN_FORMAT_PACKET	one IP packet follows

	A payload whose first byte names no format this bptun knows is
	dropped and counted, never written to the interface.

	Built against an installed ION-DTN; uses only ION's public API.

	Author: Sebastian Jennen
									*/
#include <bp.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include "bptun_route.h"

#define	BPTUN_DEFAULT_LIFETIME	(300)
#define	BPTUN_MAX_PACKET	(65535)
#define	BPTUN_NO_ROUTE_NOTES	(10)	/*	Then only counted.	*/

/*	Payload format bytes (see the header comment).			*/
#define	BPTUN_FORMAT_PACKET	(0x01)
#define	BPTUN_HEADER_LEN	(1)
#define	BPTUN_MAX_PAYLOAD	(BPTUN_HEADER_LEN + BPTUN_MAX_PACKET)

typedef struct
{
	unsigned long	packetsIn;	/*	Read from the TUN.	*/
	unsigned long	bundlesOut;
	unsigned long	bytesOut;
	unsigned long	noRoute;	/*	Packets without a route.*/
	unsigned long	sendFailed;
	unsigned long	bundlesIn;
	unsigned long	bytesIn;
	unsigned long	oversize;	/*	Bundles too big to write.*/
	unsigned long	badFormat;	/*	Payloads of no known format.*/
	unsigned long	writeFailed;
} BptunStats;

static BpSAP		sap;
static Sdr		sdr;
static volatile sig_atomic_t	running = 1;
static volatile sig_atomic_t	statsWanted = 0;
static int		tunFd = -1;
static char		ifName[IFNAMSIZ];
static BptunRouteTable	routes;
static BptunStats	stats;
static pthread_mutex_t	statsLock = PTHREAD_MUTEX_INITIALIZER;

/*	Both flags are written from a signal handler, which is why they
 *	are sig_atomic_t, but also across threads: the receiver thread
 *	reads 'running' for as long as it runs while the main thread (or
 *	a handler on either thread) clears it, and SIGUSR1 may be delivered
 *	to the receiver thread while the forwarding loop is reading
 *	'statsWanted'.  Every access therefore goes through a relaxed
 *	atomic one: each loop acts on a whole cycle rather than on the
 *	instant of the write, and the join at shutdown is what orders
 *	everything else.					*/

#define	BPTUN_GET(flag)		__atomic_load_n(&(flag), __ATOMIC_RELAXED)
#define	BPTUN_SET(flag, v)	__atomic_store_n(&(flag), (v), \
				__ATOMIC_RELAXED)

static const char	usage[] =
"Usage: bptun [-i <interface>] [-a <IPv4 address>/<prefix length>]\n"
"             [-m <MTU>] [-l <lifetime>] [-p bulk|std|expedited] [-c]\n"
"             [-u <user>] <own endpoint ID> <route> [<route> ...]\n"
"\n"
"  A route is <address>[/<prefix length>]=<EID>, an IPv4 or IPv6 prefix\n"
"  (a bare address is a host route) and the endpoint of the bptun that\n"
"  serves it, or default=<EID> for everything else.\n"
"\n"
"  -i  name of the TUN interface to create (default: bptun%d, chosen\n"
"      by the kernel and reported in the log)\n"
"  -a  configure the interface with this IPv4 address and bring it up;\n"
"      without it, configure the interface yourself with ip(8)\n"
"  -m  set the interface MTU (bounds the size of a bundle)\n"
"  -l  bundle lifetime in seconds (default 300)\n"
"  -p  bundle priority (default std)\n"
"  -c  request custody transfer\n"
"  -u  run as this user once the interface is open\n"
"\n"
"  SIGUSR1 logs the packet and bundle counters; SIGINT/SIGTERM stop.\n";

static void	handleQuit(int signum)
{
	(void) signum;
	BPTUN_SET(running, 0);
	if (sap)
	{
		bp_interrupt(sap);
	}
}

static void	handleStats(int signum)
{
	(void) signum;
	BPTUN_SET(statsWanted, 1);
}

static void	logStats(void)
{
	BptunStats	s;
	char		text[256];

	pthread_mutex_lock(&statsLock);
	s = stats;
	pthread_mutex_unlock(&statsLock);
	snprintf(text, sizeof text, "%s: in %lu packets -> %lu bundles "
			"(%lu bytes, %lu unroutable, %lu send failures); "
			"out %lu bundles -> packets (%lu bytes, %lu oversize, "
			"%lu unknown format, %lu write failures)", ifName,
			s.packetsIn, s.bundlesOut, s.bytesOut, s.noRoute,
			s.sendFailed, s.bundlesIn, s.bytesIn, s.oversize,
			s.badFormat, s.writeFailed);
	writeMemoNote("[i] bptun counters", text);
}

#define	COUNT(field, n)	do { pthread_mutex_lock(&statsLock); \
				stats.field += (n); \
				pthread_mutex_unlock(&statsLock); } while (0)

/*	*	*	The interface	*	*	*	*	*	*/

/*	Creates the TUN interface, named as asked or as the kernel
 *	chooses, and returns its file descriptor.			*/

static int	openTun(const char *wantedName)
{
	struct ifreq	ifr;
	int		fd;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0)
	{
		putSysErrmsg("bptun can't open /dev/net/tun", NULL);
		return -1;
	}

	memset(&ifr, 0, sizeof ifr);
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	if (wantedName)
	{
		istrcpy(ifr.ifr_name, wantedName, IFNAMSIZ);
	}

	if (ioctl(fd, TUNSETIFF, &ifr) < 0)
	{
		putSysErrmsg("bptun can't create TUN interface (needs "
				"CAP_NET_ADMIN)", wantedName ? wantedName
				: "bptun%d");
		close(fd);
		return -1;
	}

	istrcpy(ifName, ifr.ifr_name, sizeof ifName);
	return fd;
}

/*	The -a and -m cases: address, netmask, MTU and up, through the
 *	classic ioctls, so that no other tool is needed for the common
 *	IPv4 point-to-point setup.					*/

static int	configureTun(const char *addrSpec, int mtu)
{
	int			sock;
	struct ifreq		ifr;
	struct sockaddr_in	*sin;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		putSysErrmsg("bptun can't open a socket to configure "
				"the interface", NULL);
		return -1;
	}

	memset(&ifr, 0, sizeof ifr);
	istrcpy(ifr.ifr_name, ifName, IFNAMSIZ);
	if (addrSpec)
	{
		char		text[INET_ADDRSTRLEN];
		const char	*slash = strchr(addrSpec, '/');
		size_t		len = slash ? (size_t) (slash - addrSpec)
					    : strlen(addrSpec);
		int		prefixLen = slash ? atoi(slash + 1) : 32;
		unsigned long	mask;

		if (len == 0 || len >= sizeof text || prefixLen < 0
		|| prefixLen > 32)
		{
			putErrmsg("bptun: -a wants <IPv4 address>/<prefix "
					"length>.", addrSpec);
			close(sock);
			return -1;
		}

		memcpy(text, addrSpec, len);
		text[len] = '\0';
		sin = (struct sockaddr_in *) &ifr.ifr_addr;
		sin->sin_family = AF_INET;
		if (inet_pton(AF_INET, text, &sin->sin_addr) != 1)
		{
			putErrmsg("bptun: -a wants an IPv4 address.", text);
			close(sock);
			return -1;
		}

		if (ioctl(sock, SIOCSIFADDR, &ifr) < 0)
		{
			putSysErrmsg("bptun can't set interface address",
					text);
			close(sock);
			return -1;
		}

		mask = prefixLen ? 0xffffffffUL << (32 - prefixLen) : 0;
		sin = (struct sockaddr_in *) &ifr.ifr_netmask;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = htonl(mask);
		if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0)
		{
			putSysErrmsg("bptun can't set interface netmask",
					addrSpec);
			close(sock);
			return -1;
		}
	}

	if (mtu > 0)
	{
		ifr.ifr_mtu = mtu;
		if (ioctl(sock, SIOCSIFMTU, &ifr) < 0)
		{
			putSysErrmsg("bptun can't set interface MTU", NULL);
			close(sock);
			return -1;
		}
	}

	if (addrSpec)
	{
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0)
		{
			putSysErrmsg("bptun can't read interface flags", NULL);
			close(sock);
			return -1;
		}

		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0)
		{
			putSysErrmsg("bptun can't bring the interface up",
					NULL);
			close(sock);
			return -1;
		}
	}

	close(sock);
	return 0;
}

static int	dropPrivileges(const char *user)
{
	struct passwd	*pw = getpwnam(user);

	if (pw == NULL)
	{
		putErrmsg("bptun: no such user.", user);
		return -1;
	}

	if (setgroups(0, NULL) < 0 || setgid(pw->pw_gid) < 0
	|| setuid(pw->pw_uid) < 0)
	{
		putSysErrmsg("bptun can't drop privileges", user);
		return -1;
	}

	return 0;
}

/*	*	*	TUN -> BP	*	*	*	*	*	*/

/*	'payloadBytes' is the format byte followed by the packet.	*/

static int	sendPayload(const unsigned char *payloadBytes, int length,
			const char *destEid, int lifetime, int priority,
			BpCustodySwitch custody)
{
	Object	payload;
	Object	zco;
	Object	newBundle;

	CHKERR(sdr_begin_xn(sdr));
	payload = sdr_malloc(sdr, length);
	if (payload)
	{
		sdr_write(sdr, payload, (char *) payloadBytes, length);
	}

	if (sdr_end_xn(sdr) < 0 || payload == 0)
	{
		putErrmsg("bptun can't allocate bundle payload.", NULL);
		return -1;
	}

	zco = ionCreateZco(ZcoSdrSource, payload, 0, length,
			(unsigned char) priority, 0, ZcoOutbound, NULL);
	if (zco == 0 || zco == (Object) ERROR)
	{
		putErrmsg("bptun can't create bundle ZCO.", NULL);
		return -1;
	}

	if (bp_send(sap, (char *) destEid, NULL, lifetime, priority, custody,
			0, 0, NULL, zco, &newBundle) <= 0)
	{
		putErrmsg("bptun can't send bundle.", destEid);
		CHKERR(sdr_begin_xn(sdr));
		zco_destroy(sdr, zco);
		if (sdr_end_xn(sdr) < 0)
		{
			putErrmsg("bptun can't destroy bundle ZCO.", NULL);
		}

		return -1;
	}

	return 0;
}

/*	Reads packets off the interface until told to stop, sending each
 *	to the node its destination routes to.  poll() with a timeout
 *	keeps the loop responsive to the stop and stats signals, which
 *	a blocking read would sit through.  The packet is read in behind
 *	the format byte, so the payload is sent without a copy.		*/

static void	forwardPackets(int lifetime, int priority,
			BpCustodySwitch custody)
{
	unsigned char	*payload;
	unsigned char	*packet;
	struct pollfd	pfd;
	int		length;
	const char	*destEid;
	int		noRouteNotes = 0;

	payload = MTAKE(BPTUN_MAX_PAYLOAD);
	if (payload == NULL)
	{
		putErrmsg("bptun can't allocate packet buffer.", NULL);
		BPTUN_SET(running, 0);
		return;
	}

	payload[0] = BPTUN_FORMAT_PACKET;
	packet = payload + BPTUN_HEADER_LEN;
	pfd.fd = tunFd;
	pfd.events = POLLIN;
	while (BPTUN_GET(running))
	{
		if (BPTUN_GET(statsWanted))
		{
			BPTUN_SET(statsWanted, 0);
			logStats();
		}

		if (poll(&pfd, 1, 1000) <= 0)
		{
			continue;	/*	Timeout or EINTR.	*/
		}

		length = (int) read(tunFd, packet, BPTUN_MAX_PACKET);
		if (length < 0)
		{
			if (errno == EINTR || errno == EAGAIN)
			{
				continue;
			}

			putSysErrmsg("bptun can't read from the interface",
					ifName);
			BPTUN_SET(running, 0);
			break;
		}

		COUNT(packetsIn, 1);
		destEid = bptunRouteLookup(&routes, packet, (size_t) length);
		if (destEid == NULL)
		{
			COUNT(noRoute, 1);
			if (noRouteNotes < BPTUN_NO_ROUTE_NOTES)
			{
				noRouteNotes++;
				writeMemoNote("[?] bptun: no route for a "
						"packet, dropped; more of "
						"these are only counted",
						ifName);
			}

			continue;
		}

		if (sendPayload(payload, BPTUN_HEADER_LEN + length, destEid,
				lifetime, priority, custody) < 0)
		{
			COUNT(sendFailed, 1);
			continue;
		}

		COUNT(bundlesOut, 1);
		COUNT(bytesOut, (unsigned long) length);
	}

	MRELEASE(payload);
}

/*	*	*	BP -> TUN	*	*	*	*	*	*/

/*	The receiving thread: each delivered bundle's payload, after its
 *	format byte, is written to the interface as one packet.  Whether
 *	it is one is the kernel's to judge; a payload of a format this
 *	bptun does not know, or too big for a packet, is dropped and
 *	counted.							*/

static void	*receiveBundles(void *arg)
{
	unsigned char	*payload;
	BpDelivery	dlv;
	ZcoReader	reader;
	vast		length;
	int		got;

	(void) arg;
	payload = MTAKE(BPTUN_MAX_PAYLOAD);
	if (payload == NULL)
	{
		putErrmsg("bptun can't allocate receive buffer.", NULL);
		BPTUN_SET(running, 0);
		return NULL;
	}

	while (BPTUN_GET(running))
	{
		if (bp_receive(sap, &dlv, BP_BLOCKING) < 0)
		{
			putErrmsg("bptun bundle reception failed.", NULL);
			BPTUN_SET(running, 0);
			break;
		}

		if (dlv.result == BpEndpointStopped)
		{
			bp_release_delivery(&dlv, 1);
			BPTUN_SET(running, 0);
			break;
		}

		if (dlv.result != BpPayloadPresent || dlv.adu == 0)
		{
			bp_release_delivery(&dlv, 1);
			continue;	/*	Interrupted, or nothing.*/
		}

		COUNT(bundlesIn, 1);
		if (sdr_begin_xn(sdr) == 0)
		{
			bp_release_delivery(&dlv, 1);
			BPTUN_SET(running, 0);
			break;
		}

		length = zco_source_data_length(sdr, dlv.adu);
		if (length < BPTUN_HEADER_LEN + 1 || length > BPTUN_MAX_PAYLOAD)
		{
			sdr_exit_xn(sdr);
			bp_release_delivery(&dlv, 1);
			COUNT(oversize, 1);
			continue;
		}

		zco_start_receiving(dlv.adu, &reader);
		got = zco_receive_source(sdr, &reader, length, (char *) payload);
		if (sdr_end_xn(sdr) < 0 || got != (int) length)
		{
			putErrmsg("bptun can't read bundle payload.", NULL);
			bp_release_delivery(&dlv, 1);
			BPTUN_SET(running, 0);
			break;
		}

		bp_release_delivery(&dlv, 1);
		if (payload[0] != BPTUN_FORMAT_PACKET)
		{
			COUNT(badFormat, 1);
			continue;	/*	Not for this bptun.	*/
		}

		length -= BPTUN_HEADER_LEN;
		if (write(tunFd, payload + BPTUN_HEADER_LEN, (size_t) length)
				!= (ssize_t) length)
		{
			COUNT(writeFailed, 1);
			continue;	/*	Kernel refused it.	*/
		}

		COUNT(bytesIn, (unsigned long) length);
	}

	MRELEASE(payload);
	return NULL;
}

/*	*	*	Main	*	*	*	*	*	*	*/

static int	parsePriority(const char *text, int *priority)
{
	if (strcmp(text, "bulk") == 0)
	{
		*priority = BP_BULK_PRIORITY;
	}
	else if (strcmp(text, "std") == 0)
	{
		*priority = BP_STD_PRIORITY;
	}
	else if (strcmp(text, "expedited") == 0)
	{
		*priority = BP_EXPEDITED_PRIORITY;
	}
	else
	{
		return -1;
	}

	return 0;
}

int	main(int argc, char **argv)
{
	const char	*wantedName = NULL;
	const char	*addrSpec = NULL;
	const char	*runAs = NULL;
	int		mtu = 0;
	int		lifetime = BPTUN_DEFAULT_LIFETIME;
	int		priority = BP_STD_PRIORITY;
	BpCustodySwitch	custody = NoCustodyRequested;
	char		*ownEid;
	int		opt;
	int		i;
	pthread_t	receiver;
	int		exitCode = 0;

	while ((opt = getopt(argc, argv, "i:a:m:l:p:cu:h")) != -1)
	{
		switch (opt)
		{
		case 'i':
			wantedName = optarg;
			break;

		case 'a':
			addrSpec = optarg;
			break;

		case 'm':
			mtu = atoi(optarg);
			if (mtu < 68 || mtu > BPTUN_MAX_PACKET)
			{
				fprintf(stderr, "bptun: -m wants 68..%d\n",
						BPTUN_MAX_PACKET);
				return 1;
			}

			break;

		case 'l':
			lifetime = atoi(optarg);
			if (lifetime < 1)
			{
				fprintf(stderr, "bptun: -l wants seconds > 0\n");
				return 1;
			}

			break;

		case 'p':
			if (parsePriority(optarg, &priority) < 0)
			{
				fprintf(stderr, "bptun: -p wants bulk, std or "
						"expedited\n");
				return 1;
			}

			break;

		case 'c':
			custody = SourceCustodyRequired;
			break;

		case 'u':
			runAs = optarg;
			break;

		default:
			fputs(usage, stderr);
			return opt == 'h' ? 0 : 1;
		}
	}

	if (argc - optind < 2)
	{
		fputs(usage, stderr);
		return 1;
	}

	ownEid = argv[optind];
	for (i = optind + 1; i < argc; i++)
	{
		const char	*errText;

		if (bptunRouteAdd(&routes, argv[i], &errText) < 0)
		{
			fprintf(stderr, "bptun: route '%s': %s\n", argv[i],
					errText);
			bptunRouteTableFree(&routes);
			return 1;
		}
	}

	if (bp_attach() < 0)
	{
		putErrmsg("bptun can't attach to BP.", NULL);
		bptunRouteTableFree(&routes);
		return 1;
	}

	tunFd = openTun(wantedName);
	if (tunFd < 0 || configureTun(addrSpec, mtu) < 0
	|| (runAs && dropPrivileges(runAs) < 0))
	{
		exitCode = 1;
		goto done;
	}

	if (bp_open(ownEid, &sap) < 0)
	{
		putErrmsg("bptun can't open own endpoint.", ownEid);
		exitCode = 1;
		goto done;
	}

	sdr = bp_get_sdr();
	isignal(SIGINT, handleQuit);
	isignal(SIGTERM, handleQuit);
	isignal(SIGUSR1, handleStats);
	isignal(SIGPIPE, SIG_IGN);
	if (pthread_begin(&receiver, NULL, receiveBundles, NULL) < 0)
	{
		putSysErrmsg("bptun can't start receiver thread", NULL);
		exitCode = 1;
		goto done;
	}

	{
		char	text[IFNAMSIZ + 64];

		snprintf(text, sizeof text, "%s, endpoint %s, %d route(s)",
				ifName, ownEid, routes.count);
		writeMemoNote("[i] bptun is running", text);
	}

	forwardPackets(lifetime, priority, custody);
	BPTUN_SET(running, 0);
	bp_interrupt(sap);
	pthread_join(receiver, NULL);
	logStats();

done:
	if (sap)
	{
		bp_close(sap);
	}

	if (tunFd >= 0)
	{
		close(tunFd);
	}

	bptunRouteTableFree(&routes);
	writeErrmsgMemos();
	writeMemo("[i] bptun has ended.");
	bp_detach();
	return exitCode;
}
