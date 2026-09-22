/*
	bptun_route.c:	the route table of bptun (see bptun_route.h).

	Author: Sebastian Jennen
									*/
#include "bptun_route.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define	IPV4_DEST_OFFSET	(16)
#define	IPV6_DEST_OFFSET	(24)

static int	addRoute(BptunRouteTable *table, int family,
			const unsigned char *addr, int prefixLen,
			const char *eid)
{
	BptunRoute	*route;
	int		addrLen = family == AF_INET ? 4 : 16;

	if (table->count == table->capacity)
	{
		int		capacity = table->capacity ? table->capacity * 2
							   : 8;
		BptunRoute	*routes = realloc(table->routes,
					capacity * sizeof(BptunRoute));

		if (routes == NULL)
		{
			return -1;
		}

		table->routes = routes;
		table->capacity = capacity;
	}

	route = &table->routes[table->count];
	memset(route, 0, sizeof *route);
	route->family = family;
	memcpy(route->addr, addr, addrLen);
	route->prefixLen = prefixLen;
	strcpy(route->eid, eid);
	table->count++;
	return 0;
}

int	bptunRouteAdd(BptunRouteTable *table, const char *spec,
		const char **errText)
{
	const char	*equals;
	const char	*slash;
	const char	*eid;
	char		addrText[INET6_ADDRSTRLEN];
	size_t		addrTextLen;
	unsigned char	addr[16];
	int		family;
	int		maxPrefix;
	int		prefixLen;
	char		*end;
	const char	*err = "bad route";

	if (errText == NULL)
	{
		errText = &err;
	}

	equals = strchr(spec, '=');
	if (equals == NULL || equals[1] == '\0')
	{
		*errText = "a route is <address>[/<prefix length>]=<EID>";
		return -1;
	}

	eid = equals + 1;
	if (strlen(eid) > BPTUN_MAX_EID_LEN)
	{
		*errText = "EID too long";
		return -1;
	}

	if (equals - spec == 7 && strncmp(spec, "default", 7) == 0)
	{
		static const unsigned char	zero[16];

		if (addRoute(table, AF_INET, zero, 0, eid) < 0
		|| addRoute(table, AF_INET6, zero, 0, eid) < 0)
		{
			*errText = "out of memory";
			return -1;
		}

		return 0;
	}

	slash = memchr(spec, '/', equals - spec);
	addrTextLen = (slash ? slash : equals) - spec;
	if (addrTextLen == 0 || addrTextLen >= sizeof addrText)
	{
		*errText = "bad address";
		return -1;
	}

	memcpy(addrText, spec, addrTextLen);
	addrText[addrTextLen] = '\0';
	if (inet_pton(AF_INET, addrText, addr) == 1)
	{
		family = AF_INET;
		maxPrefix = 32;
	}
	else if (inet_pton(AF_INET6, addrText, addr) == 1)
	{
		family = AF_INET6;
		maxPrefix = 128;
	}
	else
	{
		*errText = "bad address";
		return -1;
	}

	if (slash)
	{
		prefixLen = (int) strtol(slash + 1, &end, 10);
		if (end == slash + 1 || end != equals || prefixLen < 0
		|| prefixLen > maxPrefix)
		{
			*errText = "bad prefix length";
			return -1;
		}
	}
	else
	{
		prefixLen = maxPrefix;	/*	A host route.		*/
	}

	if (addRoute(table, family, addr, prefixLen, eid) < 0)
	{
		*errText = "out of memory";
		return -1;
	}

	return 0;
}

/*	True if the first prefixLen bits of a and b agree.		*/

static int	prefixMatches(const unsigned char *a, const unsigned char *b,
			int prefixLen)
{
	int	wholeBytes = prefixLen / 8;
	int	restBits = prefixLen % 8;

	if (memcmp(a, b, wholeBytes) != 0)
	{
		return 0;
	}

	if (restBits == 0)
	{
		return 1;
	}

	return ((a[wholeBytes] ^ b[wholeBytes]) & (0xff << (8 - restBits)))
			== 0;
}

const char	*bptunRouteLookup(const BptunRouteTable *table,
			const unsigned char *packet, size_t length)
{
	int			family;
	const unsigned char	*dest;
	const BptunRoute	*best = NULL;
	int			i;

	if (length < 1)
	{
		return NULL;
	}

	switch (packet[0] >> 4)
	{
	case 4:
		if (length < IPV4_DEST_OFFSET + 4)
		{
			return NULL;
		}

		family = AF_INET;
		dest = packet + IPV4_DEST_OFFSET;
		break;

	case 6:
		if (length < IPV6_DEST_OFFSET + 16)
		{
			return NULL;
		}

		family = AF_INET6;
		dest = packet + IPV6_DEST_OFFSET;
		break;

	default:
		return NULL;
	}

	for (i = 0; i < table->count; i++)
	{
		const BptunRoute	*route = &table->routes[i];

		if (route->family != family
		|| !prefixMatches(route->addr, dest, route->prefixLen))
		{
			continue;
		}

		if (best == NULL || route->prefixLen > best->prefixLen)
		{
			best = route;
		}
	}

	return best ? best->eid : NULL;
}

void	bptunRouteTableFree(BptunRouteTable *table)
{
	free(table->routes);
	table->routes = NULL;
	table->count = 0;
	table->capacity = 0;
}
