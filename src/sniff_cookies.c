#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <pcap.h>
#include <signal.h>

#include "libmypcap.h"
#include "libsniffcookies.h"

/* ---------- Global variables ---------- */

pcap_t *handle = NULL;
void (*display_data)(int, Host_cookies *) = display_raw_data;

const char *argp_program_version = "v1.1.0";
const char *argp_program_bug_address = "<skyper@skyplabs.net>";
static char doc[] = "Allows to display the HTTP cookies passing through the network";
static struct argp_option options[] = {
	{"interface", 'i', "INTERFACE", 0, "Specify the network interface to use"},
	{"csv", 'C', 0, 0, "Display cookies as CSV data"},
	{0}
};

static struct argp argp = {options, parse_opt, 0, doc};

/* ---------- Functions ---------- */

int main (int argc, char ** argv)
{
	Arguments arguments;
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "port 80";
	bpf_u_int32 net, mask;

	/* Default values */
	arguments.interface = NULL;

	argp_parse(&argp, argc, argv, 0, 0, &arguments);

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	if (arguments.interface == NULL)
	{
		dev = pcap_lookupdev(errbuf);

		if (dev == NULL)
		{
			fprintf(stderr, "[x] Error during looking up device : %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	}
	else
		dev = arguments.interface;

	printf("[*] Device : %s\n", dev);

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "[!] Can't get netmask for device %s : %s\n", dev, errbuf);
		net = mask = 0;
	}

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL)
	{
		fprintf(stderr, "[x] Couldn't open device %s : %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	if ((pcap_compile(handle, &fp, filter_exp, 0, net)) == -1)
	{
		fprintf(stderr, "[x] Couldn't parse filter %s : %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	if ((pcap_setfilter(handle, &fp)) == -1)
	{
		fprintf(stderr, "[x] Couldn't install filter %s : %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	printf("[*] Start sniffing ...\n");

	if ((pcap_loop(handle, -1, got_packet, NULL) == -1))
	{
		fprintf(stderr, "[x] Error during reading packets\n");
		exit(EXIT_FAILURE);
	}

	pcap_close(handle);

	return EXIT_SUCCESS;
}
