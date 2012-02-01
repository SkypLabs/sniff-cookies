#include <pcap.h>

/* ---------- Functions ---------- */

/*
	Callback function used by pcap_loop().
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	
}
