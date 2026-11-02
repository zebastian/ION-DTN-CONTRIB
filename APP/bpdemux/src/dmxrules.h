/*	dmxrules.h:	the demux rules of bpdemux: a bundle's data label
			picks the local service it is delivered to.  Plain
			C, no ION, so the tests and the fuzzer build with
			the source dir alone.				*/

#ifndef DMXRULES_H
#define DMXRULES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*	A rule's optional display name: [A-Za-z0-9_.-], not all digits
 *	(so that it never reads as a label).				*/
#define	DMX_NAME_LEN		31

/*	The most rules one demux endpoint takes.			*/
#define	DMX_MAX_RULES		1024

typedef struct
{
	uint32_t	label;		/*	1 .. 2^32-1; 0 = none	*/
	uint64_t	svc;		/*	target service number	*/
	char		name[DMX_NAME_LEN + 1];	/*	"" = unnamed	*/
} DmxRule;

/*	Where a bundle goes.						*/
typedef enum
{
	DmxToRule = 0,		/*	its label's rule		*/
	DmxToDefault,		/*	no rule for it: the default	*/
	DmxToNowhere		/*	no rule and no default		*/
} DmxResult;

/*	Each returns 0 on success, -1 if the text is not valid.	*/

/*	A data label: decimal, 1 .. 4294967295.			*/
int	dmxParseLabel(const char *text, uint32_t *label);

/*	A service number: decimal, 1 .. 2^63-1.  Service 0 is the
 *	node's administrative endpoint and never a target.		*/
int	dmxParseService(const char *text, uint64_t *svc);

/*	A display name, as described above; copied to name.		*/
int	dmxParseName(const char *text, char name[DMX_NAME_LEN + 1]);

/*	An ipn EID "ipn:<node>.<service>", node >= 1, service >= 1.	*/
int	dmxParseIpnEid(const char *text, uint64_t *node, uint64_t *svc);

/*	The words of "a label" / "c label": <label> <service> [name].
 *	On failure *why says what is wrong.				*/
int	dmxParseRule(int argc, char **argv, DmxRule *rule, const char **why);

/*	Finds the rule for a label in rules[0 .. count-1]: its index,
 *	or -1.								*/
int	dmxFindLabel(const DmxRule *rules, int count, uint32_t label);

/*	Finds a rule by its label number or its name: its index, or -1.	*/
int	dmxFindRef(const DmxRule *rules, int count, const char *ref);

/*	Checks a rule against the table it is to join (or change,
 *	when self is its index; -1 when it is new) and the demux
 *	endpoint's own service: no label twice, no name twice, no
 *	target that is the demux endpoint itself.  0, or -1 with
 *	*why.								*/
int	dmxCheckRule(const DmxRule *rules, int count, int self,
		const DmxRule *rule, uint64_t ownSvc, const char **why);

/*	Picks the service for a bundle with this label (0: none).
 *	defaultSvc 0 means no default.					*/
DmxResult	dmxResolve(const DmxRule *rules, int count, uint32_t label,
			uint64_t defaultSvc, uint64_t *svc);

/*	The rule as the command that recreates it, minus "a label ":
 *	"42 705 cherry" or "43 706".					*/
void	dmxFormatRule(const DmxRule *rule, char *buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* DMXRULES_H */
