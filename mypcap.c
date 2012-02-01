#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdlib.h>

#include "mypcap.h"

/* ---------- Functions ---------- */

/*
	Display the PCAP error and exit.
*/
void pcap_fatal(const char *failed_in, const char *errbuf) {
	printf("Fatal Error in %s: %s\n", failed_in, errbuf);
	exit(EXIT_FAILURE);
}

/*
	Return 1 if the packet uses IP protocol,
	else 0.
*/
int is_ip (const struct pcap_pkthdr *header, const u_char *packet) {
	Ether_hdr *eptr;
	u_short ether_type;

	eptr = (Ether_hdr *) packet;
	ether_type = ntohs(eptr->ether_type);

	if (ether_type == ETHERTYPE_IP) return 1;
	return 0;
}

/*
	Return 1 if the packet uses TCP protocol,
	else 0.
*/
int is_tcp (const struct pcap_pkthdr *header, const u_char *packet) {
	const Ip_hdr *ip;

	ip = (Ip_hdr*)(packet + sizeof(Ether_hdr));

	if (ip->ip_type == IPPROTO_TCP) return 1;
	return 0;
}
