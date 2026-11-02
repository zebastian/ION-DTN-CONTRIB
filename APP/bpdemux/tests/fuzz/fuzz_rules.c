/*
	fuzz_rules.c:	libFuzzer target for bpdemux's rules.

	The input is lines of words, as bpdemuxadmin reads them.  Each
	line is fed to the parsers: "1 <eid>", "a label ..." and
	"c label ..." build a table; any other line is looked up as a
	label or name.  Whatever parses must format and parse back to
	the same rule, the table must keep its invariants (no label or
	name twice, no target equal to the demux service), and every
	label must resolve to a rule's service or the default.
									*/

#include "dmxrules.h"

#include <stdlib.h>
#include <string.h>

#define MAX_INPUT	4096
#define MAX_WORDS	8
#define MAX_TABLE	64

static void	check(int cond)
{
	if (!cond)
	{
		abort();
	}
}

static int	split(char *line, char **words)
{
	int	n = 0;
	char	*save = NULL;
	char	*w;

	for (w = strtok_r(line, " \t\r", &save); w && n < MAX_WORDS;
			w = strtok_r(NULL, " \t\r", &save))
	{
		words[n++] = w;
	}

	return n;
}

static void	roundTrip(const DmxRule *rule)
{
	char		buf[96];
	char		*words[MAX_WORDS];
	DmxRule		again;
	const char	*why;
	int		n;

	dmxFormatRule(rule, buf, sizeof buf);
	n = split(buf, words);
	check(dmxParseRule(n, words, &again, &why) == 0);
	check(again.label == rule->label && again.svc == rule->svc);
	check(strcmp(again.name, rule->name) == 0);
}

static void	invariants(const DmxRule *table, int count, uint64_t ownSvc,
			uint64_t defaultSvc)
{
	uint64_t	svc;
	int		i;
	int		j;

	for (i = 0; i < count; i++)
	{
		check(table[i].label != 0 && table[i].svc != 0);
		check(table[i].svc != ownSvc);
		for (j = i + 1; j < count; j++)
		{
			check(table[i].label != table[j].label);
			check(table[i].name[0] == '\0'
				|| strcmp(table[i].name, table[j].name) != 0);
		}

		check(dmxResolve(table, count, table[i].label, defaultSvc,
				&svc) == DmxToRule && svc == table[i].svc);
		check(dmxFindRef(table, count, table[i].name[0]
				? table[i].name : "0") == (table[i].name[0]
				? i : -1));
	}
}

int	LLVMFuzzerTestOneInput(const unsigned char *data, size_t size)
{
	char		text[MAX_INPUT + 1];
	char		*line;
	char		*save = NULL;
	char		*words[MAX_WORDS];
	DmxRule		table[MAX_TABLE];
	DmxRule		rule;
	const char	*why;
	uint64_t	ownNode = 0;
	uint64_t	ownSvc = 1;
	uint64_t	defaultSvc = 0;
	uint64_t	svc;
	uint32_t	label;
	int		count = 0;
	int		n;
	int		i;

	if (size > MAX_INPUT)
	{
		return 0;
	}

	memcpy(text, data, size);
	text[size] = '\0';
	for (line = strtok_r(text, "\n", &save); line;
			line = strtok_r(NULL, "\n", &save))
	{
		n = split(line, words);
		if (n == 0)
		{
			continue;
		}

		if (strcmp(words[0], "1") == 0 && n >= 2)
		{
			if (dmxParseIpnEid(words[1], &ownNode, &ownSvc) == 0)
			{
				check(ownNode != 0 && ownSvc != 0);
				count = 0;
			}

			continue;
		}

		if (strcmp(words[0], "s") == 0 && n == 2)
		{
			if (dmxParseService(words[1], &svc) == 0
					&& svc != ownSvc)
			{
				defaultSvc = svc;
			}

			continue;
		}

		if ((words[0][0] == 'a' || words[0][0] == 'c') && n >= 2
				&& strcmp(words[1], "label") == 0)
		{
			if (dmxParseRule(n - 2, words + 2, &rule, &why) < 0)
			{
				check(why != NULL);
				continue;
			}

			roundTrip(&rule);
			i = words[0][0] == 'c'
				? dmxFindLabel(table, count, rule.label) : -1;
			if (dmxCheckRule(table, count, i, &rule, ownSvc, &why)
					< 0 || (i < 0 && count == MAX_TABLE))
			{
				continue;
			}

			if (i >= 0)
			{
				table[i] = rule;
			}
			else
			{
				table[count++] = rule;
			}

			continue;
		}

		/*	Anything else: a label or a name to look up.	*/

		i = dmxFindRef(table, count, words[0]);
		check(i >= -1 && i < count);
		if (dmxParseLabel(words[0], &label) == 0)
		{
			DmxResult	r = dmxResolve(table, count, label,
						defaultSvc, &svc);

			check(r != DmxToRule || (i >= 0
					&& svc == table[i].svc));
			check(r != DmxToDefault || svc == defaultSvc);
			check(r != DmxToNowhere || defaultSvc == 0);
		}
	}

	invariants(table, count, ownSvc, defaultSvc);
	return 0;
}
