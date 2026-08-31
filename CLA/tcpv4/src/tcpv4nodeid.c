/*
	tcpv4nodeid.c:	node ID handling for the TCPCLv4 convergence layer.
			See tcpv4nodeid.h.
								*/

#include "tcpv4nodeid.h"
#include <string.h>
#include <strings.h>	/* strncasecmp			*/

/*	Read one unsigned decimal component, stopping at '.' or at the end
 *	of the string.  Returns the character after the component, or NULL
 *	when there is no well-formed component there.			*/

static const char *readComponent(const char *cursor, uint64_t *value)
{
	uint64_t n = 0;
	int	 digits = 0;

	while (*cursor >= '0' && *cursor <= '9')
	{
		/*	A component that would overflow is not a component
		 *	we can compare, so treat it as malformed.	*/

		if (n > (UINT64_MAX - (uint64_t) (*cursor - '0')) / 10)
		{
			return NULL;
		}

		n = (n * 10) + (uint64_t) (*cursor - '0');
		cursor++;
		digits++;
	}

	if (digits == 0)
	{
		return NULL;
	}

	*value = n;
	return cursor;
}

int tcpv4NodeIdIpn(const char *nodeId, uint64_t *allocator, uint64_t *node)
{
	uint64_t    parts[3];
	const char *cursor;
	int	    count = 0;

	if (!tcpv4NodeIdIsSet(nodeId))
	{
		return 0;
	}

	/*	The scheme name of a URI is case insensitive.		*/

	if (strncasecmp(nodeId, "ipn:", 4) != 0)
	{
		return 0;
	}

	cursor = nodeId + 4;
	while (count < 3)
	{
		cursor = readComponent(cursor, &parts[count]);
		if (cursor == NULL)
		{
			return 0;
		}

		count++;
		if (*cursor != '.')
		{
			break;
		}

		cursor++;
	}

	if (*cursor != '\0') /*	Trailing rubbish, or a fourth component.	*/
	{
		return 0;
	}

	/*	RFC 9758: the two-element form is the default allocator,
	 *	and a bare node number has no service number either.  The
	 *	last component of a fully spelled EID is the service, which
	 *	is no part of the node's identity.			*/

	switch (count)
	{
	case 1:
		*allocator = 0;
		*node = parts[0];
		break;

	case 2:
		*allocator = 0;
		*node = parts[0];
		break;

	default:
		*allocator = parts[0];
		*node = parts[1];
		break;
	}

	return 1;
}

int tcpv4NodeIdIsSet(const char *nodeId)
{
	return nodeId != NULL && nodeId[0] != '\0';
}

int tcpv4NodeIdMatches(const char *a, const char *b)
{
	uint64_t allocA;
	uint64_t nodeA;
	uint64_t allocB;
	uint64_t nodeB;
	int	 ipnA;
	int	 ipnB;

	if (!tcpv4NodeIdIsSet(a) || !tcpv4NodeIdIsSet(b))
	{
		return 0;
	}

	ipnA = tcpv4NodeIdIpn(a, &allocA, &nodeA);
	ipnB = tcpv4NodeIdIpn(b, &allocB, &nodeB);
	if (ipnA && ipnB)
	{
		return allocA == allocB && nodeA == nodeB;
	}

	if (ipnA != ipnB) /*	One is ipn and the other is not.	*/
	{
		return 0;
	}

	/*	Not an ipn node ID: no scheme-specific rule to apply, so
	 *	the two are the same node only if they are spelled the
	 *	same way.						*/

	return strcmp(a, b) == 0;
}
