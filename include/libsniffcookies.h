/* ---------- Defines ---------- */

#define SIGTERM			15
#define SIGKILL			9
#define SIGINT			2

/* ---------- Structures ---------- */

typedef struct
{
	char *interface;
	char filter_exp[15];
} Arguments;

struct HTTP_cookie
{
	char *id;
	char *val;
	struct HTTP_cookie *next;
};

typedef struct HTTP_cookie HTTP_cookie;

typedef struct
{
	char *ip_src;
	char *host_dst;
	char *resource;
	char *request_type;
	HTTP_cookie *cookies;
} Host_cookies;

/* ---------- Prototypes ---------- */

error_t parse_opt(int key, char *arg, struct argp_state *state);
void signal_handler(int signal);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void display_raw_data(Host_cookies *host_cookies);
void display_csv_data(Host_cookies *host_cookies);
