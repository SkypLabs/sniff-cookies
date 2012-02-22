/* ---------- Defines ---------- */

#define SIGTERM			15
#define SIGKILL			9
#define SIGINT			2

#define LENGTH_ID_COOKIE	4000
#define LENGTH_VAL_COOKIE	4000
#define LENGTH_ADDR_DST		4096
#define NB_COOKIE_HOST		20

/* ---------- Structures ---------- */

typedef struct
{
	char id[LENGTH_ID_COOKIE];
	char val[LENGTH_VAL_COOKIE];
} HTTP_cookie;

typedef struct
{
	unsigned int host_src;
	char host_dst[LENGTH_ADDR_DST];
	HTTP_cookie cookies[NB_COOKIE_HOST];
} Host_cookies;

/* ---------- Prototypes ---------- */

void signal_handler(int signal);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
