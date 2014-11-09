#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/if_ether.h>     /* IEEE 802.3 Ethernet constants */

/* Ethernet protocol ID's */
#define	ETHERTYPE_IP   0x0800   /* IP */
#define	ETHERTYPE_ARP  0x0806   /* Address resolution */

#define	ETHER_ADDR_LEN ETH_ALEN /* size of ethernet addr */
#define	ETHER_HDR_LEN  ETH_HLEN /* total octets in header */

/* IP protocol ID's' */
#define IP_PROTO_ICMP  0x01     /* ICMP */
#define IP_PROTO_TCP   0x06     /* TCP */
#define IP_PROTO_UDP   0x11     /* UDP */

/**
 * Estructura para el encabezado ETHERNET II
 * net/ethernet.h
 **/
struct ethernet_v2              /* 10Mb/s ethernet header */
{
  u_int8_t  ether_dhost[ETH_ALEN]; /* destination eth addr */
  u_int8_t  ether_shost[ETH_ALEN]; /* source ether addr */
  u_int16_t ether_type;            /* packet type ID field */
} __attribute__ ((__packed__));

/**
 * Estructura para el encabezado IP
 * netinet/ip.h
 **/
struct ip
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
  unsigned int ip_hl:4;          /* header length */
  unsigned int ip_v:4;           /* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
  unsigned int ip_v:4;	         /* version */
  unsigned int ip_hl:4;	         /* header length */
#endif
  u_int8_t ip_tos;               /* type of service */
  u_short ip_len;                /* total length */
  u_short ip_id;                 /* identification */
  u_short ip_off;                /* fragment offset field */
#define	IP_RF 0x8000             /* reserved fragment flag */
#define	IP_DF 0x4000             /* dont fragment flag */
#define	IP_MF 0x2000             /* more fragments flag */
#define	IP_OFFMASK 0x1fff        /* mask for fragmenting bits */
  u_int8_t ip_ttl;               /* time to live */
  u_int8_t ip_p;                 /* protocol */
  u_short ip_sum;                /* checksum */
  struct in_addr ip_src, ip_dst; /* source and dest address */
};

/**
 * Estructura del encabezado TCP
 * netinet/tcp.h
 */
typedef	u_int32_t tcp_seq;

struct tcphdr
{
  u_int16_t th_sport;           /* source port */
  u_int16_t th_dport;           /* destination port */
  tcp_seq th_seq;               /* sequence number */
  tcp_seq th_ack;               /* acknowledgement number */
# if __BYTE_ORDER == __LITTLE_ENDIAN
  u_int8_t th_x2:4;             /* (unused) */
  u_int8_t th_off:4;            /* data offset */
# endif
# if __BYTE_ORDER == __BIG_ENDIAN
  u_int8_t th_off:4;            /* data offset */
  u_int8_t th_x2:4;             /* (unused) */
# endif
  u_int8_t th_flags;
# define TH_FIN    0x01
# define TH_SYN    0x02
# define TH_RST    0x04
# define TH_PUSH   0x08
# define TH_ACK    0x10
# define TH_URG    0x20
  u_int16_t th_win;             /* window */
  u_int16_t th_sum;             /* checksum */
  u_int16_t th_urp;             /* urgent pointer */
};

/* Imprime los paquetes recibidos */
void print_packet (u_char*, const struct pcap_pkthdr*, const u_char*);

/* Muestra el menú de captura */
void print_menu (void);
