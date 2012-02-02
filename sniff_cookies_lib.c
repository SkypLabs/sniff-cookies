#include <pcap.h>

#include "mypcap.h"

/* ---------- Functions ---------- */

/*
	Callback function used by pcap_loop().
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	if (!is_ip(header, packet))
		return;

	if (!is_tcp(header, packet))
		return;

	printf("[->] Got TCP/IP packet !\n");
}
