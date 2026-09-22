/*
	bptun_route.h:	the route table of bptun, mapping the destination
			address of an IP packet to the endpoint ID of the
			node whose bptun should receive it.

	A route is a prefix and an EID.  Lookup is longest-prefix-match
	within the packet's address family, which the packet's version
	nibble names, so IPv4 and IPv6 routes coexist in one table.

	No ION dependency, so that the table can be unit-tested alone.

	Author: Sebastian Jennen
									*/
#ifndef BPTUN_ROUTE_H
#define BPTUN_ROUTE_H

#include <stddef.h>

#define	BPTUN_MAX_EID_LEN	(255)

typedef struct
{
	int		family;		/*	AF_INET or AF_INET6.	*/
	unsigned char	addr[16];	/*	Network order.		*/
	int		prefixLen;
	char		eid[BPTUN_MAX_EID_LEN + 1];
} BptunRoute;

typedef struct
{
	BptunRoute	*routes;
	int		count;
	int		capacity;
} BptunRouteTable;

/*	Adds the route given as "<address>[/<prefix length>]=<EID>", an
 *	IPv4 or IPv6 address, or as "default=<EID>", which routes both
 *	families.  Returns 0, or -1 for a spec it cannot read or memory
 *	it cannot get; *errText then names the problem.			*/

extern int	bptunRouteAdd(BptunRouteTable *table, const char *spec,
			const char **errText);

/*	Returns the EID for the destination of the IP packet at 'packet',
 *	or NULL if no route covers it (or the packet is too short to
 *	carry a destination address).					*/

extern const char	*bptunRouteLookup(const BptunRouteTable *table,
				const unsigned char *packet, size_t length);

extern void	bptunRouteTableFree(BptunRouteTable *table);

#endif	/*	BPTUN_ROUTE_H	*/
