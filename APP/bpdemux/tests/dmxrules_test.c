/*	dmxrules_test.c:	unit tests for bpdemux's rules (no ION).	*/

#include "dmxrules.h"

#include <stdio.h>
#include <string.h>

static int	failures = 0;

#define CHECK(cond, what)						\
	do								\
	{								\
		if (!(cond))						\
		{							\
			printf("FAIL %s:%d: %s\n", __FILE__, __LINE__,	\
					what);				\
			failures++;					\
		}							\
	} while (0)

static void	testNumbers(void)
{
	uint32_t	label;
	uint64_t	svc;
	uint64_t	node;

	CHECK(dmxParseLabel("1", &label) == 0 && label == 1, "label 1");
	CHECK(dmxParseLabel("42", &label) == 0 && label == 42, "label 42");
	CHECK(dmxParseLabel("4294967295", &label) == 0
			&& label == 4294967295U, "label max");
	CHECK(dmxParseLabel("0", &label) < 0, "label 0 is no label");
	CHECK(dmxParseLabel("4294967296", &label) < 0, "label overflow");
	CHECK(dmxParseLabel("042", &label) < 0, "leading zero");
	CHECK(dmxParseLabel("-1", &label) < 0, "sign");
	CHECK(dmxParseLabel("4x", &label) < 0, "junk");
	CHECK(dmxParseLabel("", &label) < 0, "empty");
	CHECK(dmxParseLabel(NULL, &label) < 0, "null");

	CHECK(dmxParseService("705", &svc) == 0 && svc == 705, "svc");
	CHECK(dmxParseService("0", &svc) < 0, "svc 0 is admin");
	CHECK(dmxParseService("9223372036854775807", &svc) == 0,
			"svc 2^63-1");
	CHECK(dmxParseService("9223372036854775808", &svc) < 0,
			"svc 2^63");
	CHECK(dmxParseService("99999999999999999999", &svc) < 0,
			"svc way too big");

	CHECK(dmxParseIpnEid("ipn:1.1", &node, &svc) == 0 && node == 1
			&& svc == 1, "eid");
	CHECK(dmxParseIpnEid("ipn:12.705", &node, &svc) == 0 && node == 12
			&& svc == 705, "eid 2");
	CHECK(dmxParseIpnEid("ipn:1.0", &node, &svc) < 0, "eid admin svc");
	CHECK(dmxParseIpnEid("ipn:0.1", &node, &svc) < 0, "eid node 0");
	CHECK(dmxParseIpnEid("ipn:1", &node, &svc) < 0, "eid no service");
	CHECK(dmxParseIpnEid("ipn:1.2.3", &node, &svc) < 0, "eid 3 parts");
	CHECK(dmxParseIpnEid("dtn://a/b", &node, &svc) < 0, "eid dtn");
	CHECK(dmxParseIpnEid("ipn:.1", &node, &svc) < 0, "eid empty node");
}

static void	testNames(void)
{
	char	name[DMX_NAME_LEN + 1];

	CHECK(dmxParseName("cherry", name) == 0
			&& strcmp(name, "cherry") == 0, "name");
	CHECK(dmxParseName("a-b_c.9", name) == 0, "name chars");
	CHECK(dmxParseName("7up", name) == 0, "name leading digit");
	CHECK(dmxParseName("42", name) < 0, "all digits");
	CHECK(dmxParseName("has space", name) < 0, "space");
	CHECK(dmxParseName("", name) < 0, "empty name");
	CHECK(dmxParseName("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", name) == 0,
			"31 chars");
	CHECK(dmxParseName("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", name) < 0,
			"32 chars");
	CHECK(dmxParseName("k\xc3\xbcr", name) < 0, "non-ASCII");
}

static void	testRules(void)
{
	DmxRule		rules[4];
	DmxRule		r;
	const char	*why = NULL;
	char		*named[] = { "42", "705", "cherry" };
	char		*unnamed[] = { "43", "706" };
	char		*bad[] = { "44", "0" };
	char		*four[] = { "1", "2", "x", "y" };
	char		buf[80];
	uint64_t	svc;

	CHECK(dmxParseRule(3, named, &rules[0], &why) == 0, "named rule");
	CHECK(rules[0].label == 42 && rules[0].svc == 705
			&& strcmp(rules[0].name, "cherry") == 0, "named fields");
	CHECK(dmxParseRule(2, unnamed, &rules[1], &why) == 0,
			"unnamed rule");
	CHECK(rules[1].name[0] == '\0', "unnamed has no name");
	CHECK(dmxParseRule(2, bad, &r, &why) < 0 && why, "service 0");
	CHECK(dmxParseRule(4, four, &r, &why) < 0, "too many words");
	CHECK(dmxParseRule(1, named, &r, &why) < 0, "too few words");

	dmxFormatRule(&rules[0], buf, sizeof buf);
	CHECK(strcmp(buf, "42 705 cherry") == 0, "format named");
	dmxFormatRule(&rules[1], buf, sizeof buf);
	CHECK(strcmp(buf, "43 706") == 0, "format unnamed");

	CHECK(dmxFindLabel(rules, 2, 43) == 1, "find label");
	CHECK(dmxFindLabel(rules, 2, 99) == -1, "no label");
	CHECK(dmxFindRef(rules, 2, "cherry") == 0, "find by name");
	CHECK(dmxFindRef(rules, 2, "42") == 0, "find by number");
	CHECK(dmxFindRef(rules, 2, "apple") == -1, "no name");

	/*	Checks against the table.				*/

	r = rules[0];
	CHECK(dmxCheckRule(rules, 2, -1, &r, 1, &why) < 0,
			"duplicate label refused");
	r.label = 50;
	CHECK(dmxCheckRule(rules, 2, -1, &r, 1, &why) < 0,
			"duplicate name refused");
	r.name[0] = '\0';
	CHECK(dmxCheckRule(rules, 2, -1, &r, 1, &why) == 0,
			"new unnamed rule ok");
	r.svc = 1;
	CHECK(dmxCheckRule(rules, 2, -1, &r, 1, &why) < 0,
			"target = demux endpoint refused");
	r = rules[0];
	r.svc = 706;
	CHECK(dmxCheckRule(rules, 2, 0, &r, 1, &why) == 0,
			"change of itself ok");

	/*	Resolution.						*/

	CHECK(dmxResolve(rules, 2, 42, 799, &svc) == DmxToRule && svc == 705,
			"label 42 -> 705");
	CHECK(dmxResolve(rules, 2, 43, 799, &svc) == DmxToRule && svc == 706,
			"label 43 -> 706");
	CHECK(dmxResolve(rules, 2, 99, 799, &svc) == DmxToDefault
			&& svc == 799, "unknown -> default");
	CHECK(dmxResolve(rules, 2, 0, 799, &svc) == DmxToDefault
			&& svc == 799, "no label -> default");
	CHECK(dmxResolve(rules, 2, 99, 0, &svc) == DmxToNowhere,
			"unknown, no default -> nowhere");
	CHECK(dmxResolve(rules, 0, 42, 0, &svc) == DmxToNowhere,
			"empty table");
}

int	main(void)
{
	testNumbers();
	testNames();
	testRules();
	if (failures)
	{
		printf("%d failures\n", failures);
		return 1;
	}

	printf("dmxrules_test: all passed\n");
	return 0;
}
