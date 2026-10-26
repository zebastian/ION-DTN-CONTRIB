/*
	fuzz_route.c:	fuzz target for bptun's route table.

	The input is route specs, one per line, then a blank line, then
	an IP packet.  The specs are what an operator writes; the packet
	is whatever the kernel routes into the TUN device, which a remote
	host can shape.  Adding a spec either succeeds or says why not;
	looking a packet up must read no further than the packet and give
	back one of the table's own EIDs or none; the link-local check
	must read no further than the packet either.

	Built two ways: as a libFuzzer target (`make fuzz`), and against
	fuzz_replay.c to replay the checked-in corpus under `make check`.
									*/

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "bptun_route.h"

#define MAX_SPECS 8

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len)
{
	BptunRouteTable	     table;
	const uint8_t	    *cursor = data;
	const uint8_t	    *end = data + len;
	const uint8_t	    *nl;
	const char	    *errText;
	const char	    *eid;
	unsigned char	    *packet;
	size_t		     packetLen;
	char		    *spec;
	int		     specs = 0;
	int		     i;
	int		     found;

	memset(&table, 0, sizeof(table));

	/*	Specs up to the first blank line.			*/

	while (cursor < end && specs < MAX_SPECS)
	{
		nl = memchr(cursor, '\n', (size_t) (end - cursor));
		if (nl == NULL || nl == cursor)
		{
			break;
		}

		spec = strndup((const char *) cursor, (size_t) (nl - cursor));
		assert(spec != NULL);
		errText = NULL;
		if (bptunRouteAdd(&table, spec, &errText) < 0)
		{
			assert(errText != NULL);
		}

		free(spec);
		cursor = nl + 1;
		specs++;
	}

	if (cursor < end && *cursor == '\n')
	{
		cursor++;
	}

	/*	The rest is the packet, copied to exactly its length so
	 *	that a sanitizer sees any read past it.			*/

	packetLen = (size_t) (end - cursor);
	packet = malloc(packetLen > 0 ? packetLen : 1);
	assert(packet != NULL);
	memcpy(packet, cursor, packetLen);

	eid = bptunRouteLookup(&table, packet, packetLen);
	if (eid != NULL)
	{
		found = 0;
		for (i = 0; i < table.count; i++)
		{
			if (eid == table.routes[i].eid)
			{
				found = 1;
			}
		}

		assert(found);
	}

	(void) bptunIsLinkLocal(packet, packetLen);

	free(packet);
	bptunRouteTableFree(&table);
	return 0;
}
