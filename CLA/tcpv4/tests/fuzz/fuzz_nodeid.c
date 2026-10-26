/*
	fuzz_nodeid.c:	fuzz target for node ID parsing and comparison.

	The input is two node IDs separated by a newline.  Comparison
	must be symmetric, an ipn node ID must match itself, and a node
	ID that passes the SESS_INIT well-formedness check must hold no
	octet that could shorten it or reach the log as a control
	character.

	Built two ways: as a libFuzzer target (`make fuzz`), and against
	fuzz_replay.c to replay the checked-in corpus under `make check`.
									*/

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "tcpv4nodeid.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len)
{
	const uint8_t *sep = memchr(data, '\n', len);
	size_t	       lenA = sep ? (size_t) (sep - data) : len;
	char	      *a;
	char	      *b;
	uint64_t       allocator;
	uint64_t       node;
	size_t	       i;

	if (tcpv4NodeIdIsWellFormed(data, len))
	{
		for (i = 0; i < len; i++)
		{
			assert(data[i] > 0x20 && data[i] < 0x7f);
		}
	}

	a = strndup((const char *) data, lenA);
	b = sep ? strndup((const char *) sep + 1, len - lenA - 1)
		: strdup("");
	assert(a != NULL && b != NULL);

	(void) tcpv4NodeIdIpn(a, &allocator, &node);
	assert(!tcpv4NodeIdMatches(a, b) == !tcpv4NodeIdMatches(b, a));
	if (tcpv4NodeIdIpn(a, &allocator, &node))
	{
		assert(tcpv4NodeIdMatches(a, a));
	}

	free(a);
	free(b);
	return 0;
}
