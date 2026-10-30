/*	zclcla.h:	common definitions for the zcl CLA daemons.	*/

#ifndef ZCLCLA_H
#define ZCLCLA_H

#include "bpP.h"
#include "zclcodec.h"
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

/*	zclo moves carriers by reading ION's Bundle record, whose layout
 *	include/bpP.h knows exactly only for some releases; of those,
 *	the ones with BP_VERSION are 4.1.4 and later.			*/

#if !defined (BPP_BUNDLE_LAYOUT_EXACT) || !defined (BP_VERSION)
#error "The zcl CLA needs ION-DTN 4.1.4 or later."
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define	ZCL_PROTOCOL		"zcl"

#define	ZCL_DEFAULT_WINDOW_MS	20
#define	ZCL_DEFAULT_FLUSH_BYTES	(64 * 1024)
#define	ZCL_DEFAULT_CHUNK_BYTES	(512 * 1024)
#define	ZCL_DEFAULT_CHUNK_MS	5000
#define	ZCL_DEFAULT_LIFETIME	86400

static inline uint64_t	zclNowMs(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}

/*	Wall-clock milliseconds since 1970, for bundle expiry.		*/
static inline uint64_t	zclWallMs(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}

/*	The DTN epoch, 2000-01-01T00:00:00Z, in Unix milliseconds.	*/
#define	ZCL_DTN_EPOCH_MS	946684800000ULL

/*	Reads a non-negative decimal option value; -1 if it is not one.	*/
static inline long long	zclParseCount(const char *text)
{
	char		*end;
	long long	v;

	if (text == NULL || *text < '0' || *text > '9')
	{
		return -1;
	}

	v = strtoll(text, &end, 10);
	return *end == '\0' ? v : -1;
}

#ifdef __cplusplus
}
#endif

#endif /* ZCLCLA_H */
