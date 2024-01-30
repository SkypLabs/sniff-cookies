#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <argp.h>
#include <pcap.h>
#include <signal.h>

#include "libmypcap.h"
#include "libsniffcookies.h"

/* ---------- Global variables ---------- */

pcap_t *handle = NULL;
void (*display_data)(Host_cookies *) = display_raw_data;

const char *argp_program_version = "v2.0.1";
const char *argp_program_bug_address = "<skyper@skyplabs.net>";
static char doc[] = "A lightweight HTTP cookies sniffer";
static struct argp_option options[] = {
    {"interface", 'i', "INTERFACE", 0, "Network interface to use"},
    {"port", 'p', "PORT", 0, "Network port to listen (default: 80)"},
    {"csv", 'C', 0, 0, "Display the cookies as CSV data"},
    {0}
};

static struct argp argp = {options, parse_opt, 0, doc};

/* ---------- Functions ---------- */

int main (int argc, char ** argv)
{
    Arguments arguments;
    char *int_name, errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;
    struct bpf_program fp;
    bpf_u_int32 net, mask;

    /* Default values */
    arguments.interface = NULL;
    strcpy(arguments.filter_exp, "tcp port 80");

    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (arguments.interface == NULL)
    {
        if (pcap_findalldevs(&interfaces, errbuf) == PCAP_ERROR)
        {
            fprintf(stderr,
                "[x] Couldn't get the list of network interfaces: %s\n",
                errbuf);
            exit(EXIT_FAILURE);
        }

        if (interfaces == NULL)
        {
            fprintf(stderr, "[x] No network interface found\n");
            exit(EXIT_FAILURE);
        }

        // The first network interface of the list is used by default.
        int_name = interfaces->name;
    }
    else
        int_name = arguments.interface;

    printf("[*] Interface: %s\n", int_name);

    if (pcap_lookupnet(int_name, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "[!] Couldn't get the netmask for interface %s: %s\n",
            int_name, errbuf);
        net = mask = 0;
    }

    handle = pcap_open_live(int_name, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "[x] Couldn't open interface %s: %s\n", int_name,
            errbuf);
        pcap_freealldevs(interfaces);
        exit(EXIT_FAILURE);
    }

    // At this point, the network interface list is no more needed.
    pcap_freealldevs(interfaces);

    if ((pcap_compile(handle, &fp, arguments.filter_exp, 0, net)) == -1)
    {
        fprintf(stderr, "[x] Couldn't parse filter %s: %s\n", arguments.filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    if ((pcap_setfilter(handle, &fp)) == -1)
    {
        fprintf(stderr, "[x] Couldn't install filter %s: %s\n", arguments.filter_exp, pcap_geterr(handle));
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    printf("[*] Filter: %s\n", arguments.filter_exp);
    printf("[*] Start sniffing ...\n");

    if ((pcap_loop(handle, -1, got_packet, NULL) == -1))
    {
        fprintf(stderr, "[x] Error while reading the packets\n");
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }

    printf("\n[*] Good Bye\n");
    pcap_close(handle);

    return EXIT_SUCCESS;
}
