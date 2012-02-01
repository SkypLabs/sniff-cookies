/* ---------- Defines ---------- */

#define ETHER_ADDR_LENGHT 6
#define ETHER_HDR_LENGHT 14

/* ---------- Prototypes ---------- */

typedef struct {
	unsigned char ether_dest_addr[ETHER_ADDR_LENGHT];
	unsigned char ether_src_addr[ETHER_ADDR_LENGHT];
	unsigned short ether_type;

} Ether_hdr;

typedef struct {
	unsigned char ip_version_and_header_lenght;
	unsigned char ip_tos;
	unsigned short ip_len;
	unsigned short ip_id;
	unsigned short ip_frag_offset;
	unsigned char ip_ttl;
	unsigned char ip_type;
	unsigned short ip_checksum;
	unsigned int ip_src_addr;
	unsigned int ip_dest_addr;
} Ip_hdr;


typedef struct {
	unsigned short tcp_src_port;
	unsigned short tcp_dest_port;
	unsigned int tcp_seq;
	unsigned int tcp_ack;
	unsigned char reserved:4;
	unsigned char tcp_offset:4;
	unsigned char tcp_flags;
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
	unsigned short tcp_windows;
	unsigned short tcp_checksum;
	unsigned short tcp_urgent;
} Tcp_hdr;

/* ---------- Prototypes ---------- */

void pcap_fatal(const char *failed_in, const char *errbuf);
int is_ip(const struct pcap_pkthdr *header, const u_char *packet);
int is_tcp(const struct pcap_pkthdr *header, const u_char *packet);
