#include <pcap.h>
#include <stdlib.h>

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
	if (!is_ip(header, packet))
		return;

	if (!is_tcp(header, packet))
		return;

	printf("[->] Got TCP/IP packet !\n");
}
