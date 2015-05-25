#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "mypcap.h"

/* ---------- Functions ---------- */

/*
	Display the PCAP error and exit.
*/
void pcap_fatal(const char *failed_in, const char *errbuf)
{
	printf("Fatal Error in %s : %s\n", failed_in, errbuf);
	exit(EXIT_FAILURE);
}

/*
	Return 1 if the packet uses IP protocol,
	else 0.
*/
char is_ip(const struct pcap_pkthdr *header, const u_char *packet)
{
	const Ether_hdr *eptr;
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
char is_tcp(const struct pcap_pkthdr *header, const u_char *packet)
{
	const Ip_hdr *ip;

	ip = (Ip_hdr *)(packet + sizeof(Ether_hdr));

	if (ip->ip_type == IPPROTO_TCP) return 1;
	return 0;
}

/*
	Return 1 if the packet uses HTTP protocol,
	else 0.
*/
char is_http(const struct pcap_pkthdr *header, const u_char *packet)
{
	void *http_payload_addr = NULL;
	u_int http_payload_size = 0;
	static char http_payload[DEFAULT_TCP_PAYLOAD_SIZE];

	http_payload_addr = get_tcp_payload_addr(header, packet);
	http_payload_size = get_tcp_payload_size(header, packet);

	memcpy(http_payload, http_payload_addr, http_payload_size);

	if ((strstr(http_payload, " HTTP/")) == NULL)
		return 0;
	else
		return 1;
}

/*
	Return the TCP payload address.
*/
void *get_tcp_payload_addr(const struct pcap_pkthdr *header, const u_char *packet)
{
	const Tcp_hdr *tcp;
	u_int tcp_header_size;

	tcp = (Tcp_hdr *)(packet + ETHER_HDR_LENGTH + IP_HDR_LENGTH);
	tcp_header_size = 4 * tcp->tcp_offset;

	return (void *)(packet + ETHER_HDR_LENGTH + IP_HDR_LENGTH + tcp_header_size);
}

/*
	Return the payload size.
*/
u_int get_tcp_payload_size(const struct pcap_pkthdr *header, const u_char *packet)
{
	const Tcp_hdr *tcp;
	u_int tcp_header_size;

	tcp = (Tcp_hdr *)(packet + ETHER_HDR_LENGTH + IP_HDR_LENGTH);
	tcp_header_size = 4 * tcp->tcp_offset;

	return header->len - (ETHER_HDR_LENGTH + IP_HDR_LENGTH + tcp_header_size);
}
