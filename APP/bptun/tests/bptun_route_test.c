/*
	bptun_route_test.c:	unit test of bptun's route table.  Needs no
				ION; run by "make check".
									*/
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bptun_route.h"

static int	failures = 0;

#define	CHECK(cond)	do { if (!(cond)) { failures++; \
			printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
			} } while (0)

/*	A minimal IPv4 header with the given destination.		*/

static size_t	v4Packet(unsigned char *buf, const char *dest)
{
	memset(buf, 0, 20);
	buf[0] = 0x45;
	inet_pton(AF_INET, dest, buf + 16);
	return 20;
}

static size_t	v6Packet(unsigned char *buf, const char *dest)
{
	memset(buf, 0, 40);
	buf[0] = 0x60;
	inet_pton(AF_INET6, dest, buf + 24);
	return 40;
}

static const char	*lookup(BptunRouteTable *t, size_t (*mk)(unsigned char *,
				const char *), const char *dest)
{
	unsigned char	buf[64];
	size_t		len = mk(buf, dest);

	return bptunRouteLookup(t, buf, len);
}

static int	streq(const char *a, const char *b)
{
	return a != NULL && b != NULL && strcmp(a, b) == 0;
}

int	main(void)
{
	BptunRouteTable	t;
	const char	*err;
	unsigned char	buf[64];

	memset(&t, 0, sizeof t);

	/*	Parsing.						*/

	CHECK(bptunRouteAdd(&t, "10.42.0.2=ipn:2.7", &err) == 0);
	CHECK(bptunRouteAdd(&t, "10.42.0.0/24=ipn:3.7", &err) == 0);
	CHECK(bptunRouteAdd(&t, "10.0.0.0/8=ipn:4.7", &err) == 0);
	CHECK(bptunRouteAdd(&t, "fd00:42::2=ipn:5.7", &err) == 0);
	CHECK(bptunRouteAdd(&t, "fd00:42::/64=ipn:6.7", &err) == 0);
	CHECK(t.count == 5);
	CHECK(bptunRouteAdd(&t, "default=ipn:9.7", &err) == 0);
	CHECK(t.count == 7);		/*	Both families.		*/

	CHECK(bptunRouteAdd(&t, "10.42.0.2", &err) < 0);
	CHECK(bptunRouteAdd(&t, "10.42.0.2=", &err) < 0);
	CHECK(bptunRouteAdd(&t, "=ipn:1.1", &err) < 0);
	CHECK(bptunRouteAdd(&t, "10.42.0.256=ipn:1.1", &err) < 0);
	CHECK(bptunRouteAdd(&t, "10.42.0.0/33=ipn:1.1", &err) < 0);
	CHECK(bptunRouteAdd(&t, "10.42.0.0/x=ipn:1.1", &err) < 0);
	CHECK(bptunRouteAdd(&t, "fd00::/129=ipn:1.1", &err) < 0);
	CHECK(bptunRouteAdd(&t, "nonsense=ipn:1.1", &err) < 0);
	CHECK(t.count == 7);		/*	Rejections add nothing.	*/

	/*	Longest prefix wins, per family.			*/

	CHECK(streq(lookup(&t, v4Packet, "10.42.0.2"), "ipn:2.7"));
	CHECK(streq(lookup(&t, v4Packet, "10.42.0.3"), "ipn:3.7"));
	CHECK(streq(lookup(&t, v4Packet, "10.1.2.3"), "ipn:4.7"));
	CHECK(streq(lookup(&t, v4Packet, "192.168.1.1"), "ipn:9.7"));
	CHECK(streq(lookup(&t, v6Packet, "fd00:42::2"), "ipn:5.7"));
	CHECK(streq(lookup(&t, v6Packet, "fd00:42::3"), "ipn:6.7"));
	CHECK(streq(lookup(&t, v6Packet, "fd00:43::1"), "ipn:9.7"));

	/*	Prefix bits that do not end on a byte boundary.		*/

	bptunRouteTableFree(&t);
	CHECK(bptunRouteAdd(&t, "10.42.0.128/25=ipn:2.7", &err) == 0);
	CHECK(bptunRouteAdd(&t, "10.42.0.0/25=ipn:3.7", &err) == 0);
	CHECK(streq(lookup(&t, v4Packet, "10.42.0.129"), "ipn:2.7"));
	CHECK(streq(lookup(&t, v4Packet, "10.42.0.127"), "ipn:3.7"));
	CHECK(lookup(&t, v4Packet, "10.42.1.1") == NULL);

	/*	Packets that carry no usable destination.		*/

	CHECK(bptunRouteLookup(&t, buf, 0) == NULL);
	buf[0] = 0x45;
	CHECK(bptunRouteLookup(&t, buf, 19) == NULL);	/*	Short.	*/
	buf[0] = 0x60;
	CHECK(bptunRouteLookup(&t, buf, 39) == NULL);
	buf[0] = 0x00;
	CHECK(bptunRouteLookup(&t, buf, 64) == NULL);	/*	Not IP.	*/

	/*	Growth past the initial capacity.			*/

	bptunRouteTableFree(&t);
	{
		int	i;
		char	spec[64];

		for (i = 0; i < 40; i++)
		{
			snprintf(spec, sizeof spec, "10.%d.0.0/16=ipn:%d.7",
					i, i + 1);
			CHECK(bptunRouteAdd(&t, spec, &err) == 0);
		}

		CHECK(t.count == 40);
		CHECK(streq(lookup(&t, v4Packet, "10.39.1.1"), "ipn:40.7"));
	}

	bptunRouteTableFree(&t);
	CHECK(t.routes == NULL && t.count == 0);

	if (failures)
	{
		printf("%d check(s) failed\n", failures);
		return 1;
	}

	puts("bptun_route_test: all checks passed");
	return 0;
}
