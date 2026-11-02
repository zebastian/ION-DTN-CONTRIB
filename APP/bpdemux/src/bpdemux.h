/*	bpdemux.h:	definitions shared by bpdemuxd and bpdemuxadmin.

	A demux endpoint's rules live in the SDR, cataloged under one
	name per node.  bpdemuxd reads them for every batch of bundles
	it moves, so a change made by bpdemuxadmin applies to the next
	bundle.								*/

#ifndef BPDEMUX_H
#define BPDEMUX_H

#include "bpP.h"
#include "dmxrules.h"

#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(BPP_BUNDLE_LAYOUT_EXACT)
#error "bpdemux reads and rewrites ION's Bundle record and needs a bpP.h copy of the installed release (ION 4.1.4 or 4.2.x); see include/README."
#endif

#define	BPDEMUX_DB_NAME		"bpdemux"
#define	BPDEMUX_DB_VERSION	1

typedef struct
{
	int		version;	/*	BPDEMUX_DB_VERSION	*/
	uvast		ownNode;	/*	the demux endpoint's	*/
	uvast		ownSvc;		/*	ipn:<ownNode>.<ownSvc>	*/
	uvast		defaultSvc;	/*	0: none			*/
	unsigned int	changeCount;	/*	bumped on every change	*/
	Object		rules;		/*	SDR list of DmxRule	*/
} DmxDb;

/*	ION keeps an ipn service number in an unsigned long, which is
 *	32 bits on some targets (e.g. ARMv7).				*/
static inline int	dmxServiceFits(uint64_t svc)
{
	return svc <= (uint64_t) ULONG_MAX;
}

#ifdef __cplusplus
}
#endif

#endif /* BPDEMUX_H */
