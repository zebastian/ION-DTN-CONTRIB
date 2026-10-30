/*	quotacl.h:	definitions shared by quotaclo and quotaadmin.	*/

#ifndef QUOTACL_H
#define QUOTACL_H

#include "bpP.h"
#include "quotarules.h"
#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	QUOTACL_PROTOCOL	"quota"

/*	The rules live in the SDR, cataloged under this name.		*/
#define	QUOTACL_DB_NAME		"quotacl"
#define	QUOTACL_DB_VERSION	1

typedef struct
{
	int		version;	/*	QUOTACL_DB_VERSION	*/

	/*	Bumped by quotaadmin on every change; quotaclo reloads
	 *	its rules when it sees a new value.			*/

	unsigned int	changeCount;

	/*	Bumped by quotaadmin's "i rule"; quotaclo answers by
	 *	writing its state file at once, recording the value
	 *	it served in the file's header.				*/

	unsigned int	infoRequest;
	Object		rules;		/*	SDR list of QuotaRule	*/
} QuotaClDb;

/*	quotaclo writes its state file every this many seconds.	*/
#define	QUOTACL_SNAPSHOT_S	10

/*	<ION working directory>/quota-<duct>.state; the duct name is
 *	used as is, except that '/' becomes '_'.			*/
static inline void	quotaclStatePath(const char *duct, char *buf,
				size_t size)
{
	char	*cursor;
	size_t	len;

	isprintf(buf, (int) size, "%s%cquota-", getIonWorkingDirectory(),
			ION_PATH_DELIMITER);
	len = strlen(buf);
	isprintf(buf + len, (int) (size - len), "%s.state", duct);
	for (cursor = buf + len; *cursor; cursor++)
	{
		if (*cursor == '/' || *cursor == '\\')
		{
			*cursor = '_';
		}
	}
}

static inline uint64_t	quotaclNowMs(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}

#ifdef __cplusplus
}
#endif

#endif /* QUOTACL_H */
