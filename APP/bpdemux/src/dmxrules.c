/*	dmxrules.c:	demux rules of bpdemux (see dmxrules.h).	*/

#include "dmxrules.h"

#include <stdio.h>
#include <string.h>

/*	Decimal digits only, no sign, no leading zeros beyond "0",
 *	value <= max.							*/
static int	parseDecimal(const char *text, uint64_t max, uint64_t *value)
{
	uint64_t	v = 0;
	const char	*p;

	if (text == NULL || *text == '\0' || strlen(text) > 20)
	{
		return -1;
	}

	if (text[0] == '0' && text[1] != '\0')
	{
		return -1;
	}

	for (p = text; *p; p++)
	{
		if (*p < '0' || *p > '9')
		{
			return -1;
		}

		if (v > (max - (uint64_t) (*p - '0')) / 10)
		{
			return -1;
		}

		v = v * 10 + (uint64_t) (*p - '0');
	}

	*value = v;
	return 0;
}

int	dmxParseLabel(const char *text, uint32_t *label)
{
	uint64_t	v;

	if (parseDecimal(text, 0xffffffffULL, &v) < 0 || v == 0)
	{
		return -1;
	}

	*label = (uint32_t) v;
	return 0;
}

int	dmxParseService(const char *text, uint64_t *svc)
{
	uint64_t	v;

	if (parseDecimal(text, 0x7fffffffffffffffULL, &v) < 0 || v == 0)
	{
		return -1;
	}

	*svc = v;
	return 0;
}

int	dmxParseName(const char *text, char name[DMX_NAME_LEN + 1])
{
	size_t		len;
	size_t		i;
	int		allDigits = 1;
	char		c;

	if (text == NULL)
	{
		return -1;
	}

	len = strlen(text);
	if (len == 0 || len > DMX_NAME_LEN)
	{
		return -1;
	}

	for (i = 0; i < len; i++)
	{
		c = text[i];
		if (c >= '0' && c <= '9')
		{
			continue;
		}

		allDigits = 0;
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
				|| c == '_' || c == '.' || c == '-'))
		{
			return -1;
		}
	}

	if (allDigits)
	{
		return -1;
	}

	memcpy(name, text, len);
	name[len] = '\0';
	return 0;
}

int	dmxParseIpnEid(const char *text, uint64_t *node, uint64_t *svc)
{
	char		buf[48];
	char		*dot;
	uint64_t	n;
	uint64_t	s;

	if (text == NULL || strncmp(text, "ipn:", 4) != 0
			|| strlen(text + 4) >= sizeof buf)
	{
		return -1;
	}

	strcpy(buf, text + 4);
	dot = strchr(buf, '.');
	if (dot == NULL)
	{
		return -1;
	}

	*dot++ = '\0';
	if (parseDecimal(buf, 0x7fffffffffffffffULL, &n) < 0 || n == 0
			|| dmxParseService(dot, &s) < 0)
	{
		return -1;
	}

	*node = n;
	*svc = s;
	return 0;
}

int	dmxParseRule(int argc, char **argv, DmxRule *rule, const char **why)
{
	DmxRule	r;

	memset(&r, 0, sizeof r);
	if (argc < 2 || argc > 3)
	{
		*why = "usage: <label> <service> [name]";
		return -1;
	}

	if (dmxParseLabel(argv[0], &r.label) < 0)
	{
		*why = "label must be a number from 1 to 4294967295";
		return -1;
	}

	if (dmxParseService(argv[1], &r.svc) < 0)
	{
		*why = "service must be a number of 1 or more";
		return -1;
	}

	if (argc == 3 && dmxParseName(argv[2], r.name) < 0)
	{
		*why = "name: up to 31 of A-Z a-z 0-9 _ . -, not all digits";
		return -1;
	}

	*rule = r;
	return 0;
}

int	dmxFindLabel(const DmxRule *rules, int count, uint32_t label)
{
	int	i;

	for (i = 0; i < count; i++)
	{
		if (rules[i].label == label)
		{
			return i;
		}
	}

	return -1;
}

int	dmxFindRef(const DmxRule *rules, int count, const char *ref)
{
	uint32_t	label;
	int		i;

	if (dmxParseLabel(ref, &label) == 0)
	{
		return dmxFindLabel(rules, count, label);
	}

	for (i = 0; i < count; i++)
	{
		if (rules[i].name[0] && strcmp(rules[i].name, ref) == 0)
		{
			return i;
		}
	}

	return -1;
}

int	dmxCheckRule(const DmxRule *rules, int count, int self,
		const DmxRule *rule, uint64_t ownSvc, const char **why)
{
	int	i;

	if (rule->label == 0 || rule->svc == 0)
	{
		*why = "label and service must be 1 or more";
		return -1;
	}

	if (rule->svc == ownSvc)
	{
		*why = "target is the demux endpoint itself";
		return -1;
	}

	for (i = 0; i < count; i++)
	{
		if (i == self)
		{
			continue;
		}

		if (rules[i].label == rule->label)
		{
			*why = "a rule for this label exists already";
			return -1;
		}

		if (rule->name[0] && strcmp(rules[i].name, rule->name) == 0)
		{
			*why = "a rule of this name exists already";
			return -1;
		}
	}

	if (self < 0 && count >= DMX_MAX_RULES)
	{
		*why = "too many rules";
		return -1;
	}

	return 0;
}

DmxResult	dmxResolve(const DmxRule *rules, int count, uint32_t label,
			uint64_t defaultSvc, uint64_t *svc)
{
	int	i;

	if (label != 0)
	{
		i = dmxFindLabel(rules, count, label);
		if (i >= 0)
		{
			*svc = rules[i].svc;
			return DmxToRule;
		}
	}

	if (defaultSvc != 0)
	{
		*svc = defaultSvc;
		return DmxToDefault;
	}

	*svc = 0;
	return DmxToNowhere;
}

void	dmxFormatRule(const DmxRule *rule, char *buf, size_t size)
{
	if (rule->name[0])
	{
		snprintf(buf, size, "%lu %llu %s", (unsigned long) rule->label,
				(unsigned long long) rule->svc, rule->name);
	}
	else
	{
		snprintf(buf, size, "%lu %llu", (unsigned long) rule->label,
				(unsigned long long) rule->svc);
	}
}
