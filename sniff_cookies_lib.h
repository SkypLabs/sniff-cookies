/* ---------- Defines ---------- */

#define SIGTERM			15
#define SIGKILL			9
#define SIGINT			2

/* ---------- Prototypes ---------- */

void signal_handler(int signal);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
