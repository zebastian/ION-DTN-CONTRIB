/*
	fuzz_zclinfo.c:	libFuzzer target for zclBundleInfo, which reads
			the bundles zclo is handed - built by other
			nodes - to pick a carrier's lifetime and
			priority.
									*/

#include "zclcodec.h"

#include <stdlib.h>

int	LLVMFuzzerTestOneInput(const uint8_t *data, size_t len)
{
	ZclBundleInfo	info;

	if (zclBundleInfo(data, len, &info) == 0
	&& (info.priority < -1 || info.priority > 2))
	{
		abort();		/*	Not a priority.		*/
	}

	return 0;
}
