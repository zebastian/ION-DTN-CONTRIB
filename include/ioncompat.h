/*
 *	ioncompat.h -- the few pieces of ION's public API that the
 *	contributions use and that ION releases before 4.1.4 do not
 *	have, supplied here for those releases (see README in this
 *	directory).  On 4.1.4 and later this header only includes the
 *	ION headers that provide them.
 *
 *	Each piece is keyed on a macro the ION header that introduced
 *	it defines, not on a release number, so an ION that has the
 *	feature is always taken at its word:
 *
 *	  getOwnFqnn/putFqn        FQN_MAX_LENGTH       ion.h   4.1.4
 *	  cbor signed integers     CborNegativeInteger  cbor.h  4.1.4
 *	  ion_network.h            ION_CONTRIB_HAVE_ION_NETWORK_H (configure)
 *
 *	Whether ion_network.h exists is configure's to say, since that is
 *	a property of the ION prefix rather than of the compiler's include
 *	path, on which some other ION might answer.  cbor.h itself is not
 *	installed before 4.1.3s; configure adds include/compat when it is
 *	missing.
 */
#ifndef IONCOMPAT_H
#define IONCOMPAT_H

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "ion.h"
#include "cbor.h"

#ifdef ION_CONTRIB_HAVE_ION_NETWORK_H	/*	configure found it.	*/
#include "ion_network.h"
#endif

/*	*	*	Fully qualified node numbers	*	*	*	*/

#ifndef FQN_MAX_LENGTH
/*	Before the IPN naming transition of 4.1.4 a node number is the
 *	whole of its name: no allocator, nothing to delimit.		*/
#define	FQN_MAX_LENGTH	(22)

static inline uvast	getOwnFqnn(void)
{
	return getOwnNodeNbr();
}

static inline void	putFqn(char *toBuffer, uvast fqn)
{
	CHKVOID(toBuffer);
	isprintf(toBuffer, FQN_MAX_LENGTH, UVAST_FIELDSPEC, fqn);
}
#endif	/*	FQN_MAX_LENGTH	*/

/*	*	*	CBOR signed integers	*	*	*	*	*/

#ifndef CborNegativeInteger
#define	CborNegativeInteger	1

/*	A negative integer is major type 1 carrying (-1 - value), with
 *	the same head byte as the unsigned encoding of that magnitude
 *	but for the major type bits; the encoder therefore writes the
 *	magnitude as unsigned and rewrites the head.  The decoder reads
 *	the head and argument itself, since ION's cbor_decode_integer
 *	refuses major type 1.  Both return what 4.1.4's do: bytes
 *	written, and bytes read or 0 on a decoding error.		*/

static inline int	cbor_encode_signed_int(vast value,
				unsigned char **cursor)
{
	unsigned char	*head;
	int		length;

	CHKZERO(cursor && *cursor);
	if (value >= 0)
	{
		return cbor_encode_integer((uvast) value, cursor);
	}

	head = *cursor;
	length = cbor_encode_integer((uvast) (-1 - value), cursor);
	if (length > 0)
	{
		*head |= (CborNegativeInteger << 5);
	}

	return length;
}

static inline int	cbor_decode_signed_int(vast *value,
				unsigned char **cursor,
				unsigned int *bytesBuffered)
{
	unsigned char	*cur;
	int		majorType;
	int		additionalInfo;
	int		argLength;
	uvast		magnitude;
	int		i;

	CHKZERO(value && cursor && *cursor && bytesBuffered);
	if (*bytesBuffered < 1)
	{
		return 0;
	}

	cur = *cursor;
	majorType = *cur >> 5;
	additionalInfo = *cur & 0x1f;
	if (majorType != CborUnsignedInteger
			&& majorType != CborNegativeInteger)
	{
		writeMemo("[?] CBOR error: not integer (signed).");
		return 0;
	}

	if (additionalInfo < 24)
	{
		argLength = 0;
		magnitude = additionalInfo;
	}
	else if (additionalInfo <= 27)
	{
		argLength = 1 << (additionalInfo - 24);
		if (*bytesBuffered < (unsigned int) (1 + argLength))
		{
			writeMemo("[?] CBOR signed integer decode failed.");
			return 0;
		}

		magnitude = 0;
		for (i = 1; i <= argLength; i++)
		{
			magnitude = (magnitude << 8) | cur[i];
		}
	}
	else
	{
		writeMemo("[?] CBOR signed integer decode failed.");
		return 0;
	}

	if (majorType == CborNegativeInteger)
	{
		*value = (vast) -1 - (vast) magnitude;
	}
	else
	{
		*value = (vast) magnitude;
	}

	*cursor += 1 + argLength;
	*bytesBuffered -= 1 + argLength;
	return 1 + argLength;
}
#endif	/*	CborNegativeInteger	*/

/*	*	*	Dual-stack network helpers	*	*	*	*/

#ifndef ION_NETWORK_H
#define	ION_NETWORK_H

/*	What ion_network.h of 4.1.4 offers, reduced to the calls the
 *	contributions make, with the same structures and the same
 *	getaddrinfo-based resolution, so a host:port, [v6]:port or
 *	bare name resolves the same way on an older ION.  The address
 *	cache and the UDP variants are not reproduced.			*/

#define	MAX_FQDN_LEN			255
#define	INET6_ADDR_WITH_PORT_STRLEN	(INET6_ADDRSTRLEN + 10)

typedef struct
{
	struct sockaddr_storage	addr;
	socklen_t		addr_len;
	int			family;		/*	AF_INET or AF_INET6.	*/
} IonNetworkAddress;

typedef struct
{
	char		hostname[MAX_FQDN_LEN + 1];
	char		service[16];
	unsigned short	port;
	int		family_hint;		/*	AF_UNSPEC, AF_INET(6).	*/
	int		is_numeric_host;
} IonEndpointSpec;

static inline int	ioncompat_isNumericAddress(const char *text,
				int family)
{
	unsigned char	buf[sizeof(struct in6_addr)];

	return inet_pton(family, text, buf) == 1;
}

static inline int	parseNetworkEndpoint(const char *endpoint,
				IonEndpointSpec *spec)
{
	const char	*open;
	const char	*close;
	const char	*colon;
	size_t		hostLen;

	if (endpoint == NULL || spec == NULL)
	{
		return -1;
	}

	memset(spec, 0, sizeof(IonEndpointSpec));
	spec->family_hint = AF_UNSPEC;
	open = strchr(endpoint, '[');
	close = strchr(endpoint, ']');
	if (open && close && open < close)	/*	[v6]:port	*/
	{
		hostLen = close - open - 1;
		if (hostLen >= sizeof(spec->hostname))
		{
			return -1;
		}

		memcpy(spec->hostname, open + 1, hostLen);
		spec->hostname[hostLen] = '\0';
		spec->family_hint = AF_INET6;
		spec->is_numeric_host = ioncompat_isNumericAddress(
				spec->hostname, AF_INET6);
		colon = strchr(close, ':');
	}
	else if (ioncompat_isNumericAddress(endpoint, AF_INET6))
	{
		istrcpy(spec->hostname, endpoint, sizeof(spec->hostname));
		spec->family_hint = AF_INET6;
		spec->is_numeric_host = 1;
		colon = NULL;			/*	Bare v6, no port.	*/
	}
	else
	{
		colon = strrchr(endpoint, ':');
		hostLen = colon ? (size_t) (colon - endpoint)
				: strlen(endpoint);
		if (hostLen >= sizeof(spec->hostname))
		{
			return -1;
		}

		memcpy(spec->hostname, endpoint, hostLen);
		spec->hostname[hostLen] = '\0';
		spec->is_numeric_host = ioncompat_isNumericAddress(
				spec->hostname, AF_INET)
				|| ioncompat_isNumericAddress(spec->hostname,
				AF_INET6);
	}

	if (colon)
	{
		istrcpy(spec->service, colon + 1, sizeof(spec->service));
		spec->port = (unsigned short) strtoul(colon + 1, NULL, 10);
	}

	if (strcmp(spec->hostname, "@") == 0)
	{
		getNameOfHost(spec->hostname, sizeof(spec->hostname));
		spec->is_numeric_host = 0;
	}

	return 0;
}

static inline int	resolveNetworkAddressTCP(const IonEndpointSpec *spec,
				IonNetworkAddress *result)
{
	struct addrinfo	hints;
	struct addrinfo	*res;
	struct addrinfo	*rp;
	const char	*service;
	int		status;
	int		testSock;

	if (spec == NULL || result == NULL)
	{
		return -1;
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = spec->family_hint;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_ADDRCONFIG;
	if (spec->is_numeric_host)
	{
		hints.ai_flags |= AI_NUMERICHOST;
	}

	service = spec->service[0] ? spec->service : "4556";
	status = getaddrinfo(spec->hostname, service, &hints, &res);
	if (status != 0)
	{
		putErrmsg("Network address resolution failed",
				(char *) gai_strerror(status));
		return -1;
	}

	for (rp = res; rp != NULL; rp = rp->ai_next)
	{
		testSock = socket(rp->ai_family, rp->ai_socktype,
				rp->ai_protocol);
		if (testSock < 0)
		{
			continue;	/*	Family unusable here.	*/
		}

		closesocket(testSock);
		memcpy(&result->addr, rp->ai_addr, rp->ai_addrlen);
		result->addr_len = rp->ai_addrlen;
		result->family = rp->ai_family;
		freeaddrinfo(res);
		return 0;
	}

	freeaddrinfo(res);
	putErrmsg("No usable addresses found", (char *) spec->hostname);
	return -1;
}

static inline const char	*formatNetworkAddress(
				const IonNetworkAddress *addr, char *buffer,
				size_t buflen)
{
	char	text[INET6_ADDRSTRLEN];

	if (addr == NULL || buffer == NULL)
	{
		return "invalid";
	}

	if (addr->family == AF_INET)
	{
		const struct sockaddr_in	*sin =
				(const struct sockaddr_in *) &addr->addr;

		inet_ntop(AF_INET, &sin->sin_addr, text, sizeof text);
		snprintf(buffer, buflen, "%s:%u", text, ntohs(sin->sin_port));
	}
	else if (addr->family == AF_INET6)
	{
		const struct sockaddr_in6	*sin6 =
				(const struct sockaddr_in6 *) &addr->addr;

		inet_ntop(AF_INET6, &sin6->sin6_addr, text, sizeof text);
		snprintf(buffer, buflen, "[%s]:%u", text,
				ntohs(sin6->sin6_port));
	}
	else
	{
		snprintf(buffer, buflen, "unknown_family_%d", addr->family);
	}

	return buffer;
}

static inline int	createNetworkSocket(int socket_type,
				const IonNetworkAddress *local_addr,
				int *socket_fd)
{
	int	sock;
	int	on = 1;

	if (local_addr == NULL || socket_fd == NULL)
	{
		return -1;
	}

	sock = socket(local_addr->family, socket_type,
			socket_type == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP);
	if (sock < 0)
	{
		putSysErrmsg("Can't create network socket", NULL);
		return -1;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &on,
			sizeof on) < 0)
	{
		closesocket(sock);
		putSysErrmsg("Can't make network socket reusable", NULL);
		return -1;
	}

	if (local_addr->family == AF_INET6)
	{
		setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on);
	}

	if (bind(sock, (const struct sockaddr *) &local_addr->addr,
			local_addr->addr_len) < 0)
	{
		closesocket(sock);
		putSysErrmsg("Can't bind network socket", NULL);
		return -1;
	}

	*socket_fd = sock;
	return 0;
}

/*	Returns 1 with *sock connected, 0 when the peer is unreachable
 *	(*sock is -1), -1 on failure, as itcp_connect_dualstack does.	*/

static inline int	itcp_connect_dualstack(char *socketSpec,
				unsigned short defaultPort, int *sock,
				IonNetworkAddress *remoteAddr)
{
	IonEndpointSpec		spec;
	IonNetworkAddress	addr;
	char			text[INET6_ADDR_WITH_PORT_STRLEN];

	CHKERR(socketSpec);
	CHKERR(sock);
	*sock = -1;
	if (*socketSpec == '\0')
	{
		return 0;		/*	Don't try to connect.	*/
	}

	if (parseNetworkEndpoint(socketSpec, &spec) < 0)
	{
		putErrmsg("Can't parse socket specification", socketSpec);
		return -1;
	}

	if (spec.port == 0)
	{
		spec.port = defaultPort;
		snprintf(spec.service, sizeof spec.service, "%hu",
				defaultPort);
	}

	if (resolveNetworkAddressTCP(&spec, &addr) < 0)
	{
		putErrmsg("Can't resolve TCP address", socketSpec);
		return -1;
	}

	*sock = socket(addr.family, SOCK_STREAM, IPPROTO_TCP);
	if (*sock < 0)
	{
		formatNetworkAddress(&addr, text, sizeof text);
		putSysErrmsg("Can't open TCP socket", text);
		return -1;
	}

	if (connect(*sock, (struct sockaddr *) &addr.addr, addr.addr_len) < 0)
	{
		closesocket(*sock);
		*sock = -1;
		return 0;
	}

	if (remoteAddr != NULL)
	{
		*remoteAddr = addr;
	}

	return 1;
}
#endif	/*	ION_NETWORK_H	*/

#endif	/*	IONCOMPAT_H	*/
