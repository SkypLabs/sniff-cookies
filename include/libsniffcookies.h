/* ---------- Defines ---------- */

#define SIGTERM			15
#define SIGKILL			9
#define SIGINT			2

#define NB_COOKIE_HOST		20

/* ---------- Structures ---------- */

typedef struct
{
	char *interface;
} Arguments;

typedef struct
{
	char *id;
	char *val;
} HTTP_cookie;

typedef struct
{
	char *ip_src;
	char *host_dst;
	HTTP_cookie cookies[NB_COOKIE_HOST];
} Host_cookies;

/* ---------- Prototypes ---------- */

error_t parse_opt(int key, char *arg, struct argp_state *state);
void signal_handler(int signal);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
