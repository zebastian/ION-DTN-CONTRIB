/*	dmxrecv.c:	test receiver for bpdemux's integration test.  Opens
			an endpoint and prints one line per bundle:

			  src=<source EID> len=<payload bytes> text=<payload>

			until <count> bundles have come or <seconds> pass
			without one.  Exit 0 if all came, 1 if not.	*/

#include "bp.h"

#include <stdio.h>
#include <stdlib.h>

#define	MAX_TEXT	64

int	main(int argc, char **argv)
{
	BpSAP		sap;
	BpDelivery	dlv;
	ZcoReader	reader;
	Sdr		sdr;
	char		text[MAX_TEXT + 1];
	vast		len;
	int		got;
	int		want;
	int		seconds;
	int		n = 0;
	int		i;

	if (argc != 4)
	{
		fprintf(stderr, "usage: dmxrecv <own EID> <count> <seconds>\n");
		return 2;
	}

	want = atoi(argv[2]);
	seconds = atoi(argv[3]);
	if (bp_attach() < 0 || bp_open(argv[1], &sap) < 0)
	{
		fprintf(stderr, "dmxrecv: can't open %s\n", argv[1]);
		return 2;
	}

	sdr = bp_get_sdr();
	while (n < want)
	{
		if (bp_receive(sap, &dlv, seconds) < 0)
		{
			break;
		}

		if (dlv.result != BpPayloadPresent)
		{
			bp_release_delivery(&dlv, 1);
			break;
		}

		CHKZERO(sdr_begin_xn(sdr));
		len = zco_source_data_length(sdr, dlv.adu);
		zco_start_receiving(dlv.adu, &reader);
		got = zco_receive_source(sdr, &reader,
				len > MAX_TEXT ? MAX_TEXT : len, text);
		sdr_end_xn(sdr);
		if (got < 0)
		{
			got = 0;
		}

		text[got] = '\0';
		for (i = 0; i < got; i++)
		{
			if (text[i] < ' ' || text[i] > '~')
			{
				text[i] = '.';
			}
		}

		printf("src=%s len=%ld text=%s\n", dlv.bundleSourceEid,
				(long) len, text);
		fflush(stdout);
		bp_release_delivery(&dlv, 1);
		n++;
	}

	bp_close(sap);
	bp_detach();
	return n == want ? 0 : 1;
}
