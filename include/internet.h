#include <arpa/inet.h>

/* IP protocol ID's' */
#define IP_PROTO_ICMP  0x01     /* ICMP */
#define IP_PROTO_TCP   0x06     /* TCP */
#define IP_PROTO_UDP   0x11     /* UDP */

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
 * Estructura del encabezado ARP
 * net/if_arp.h
 **/
struct arp
{
  unsigned short int ar_hrd;          /* Format of hardware address.  */
  unsigned short int ar_pro;          /* Format of protocol address.  */
  unsigned char ar_hln;               /* Length of hardware address.  */
  unsigned char ar_pln;               /* Length of protocol address.  */
  unsigned short int ar_op;           /* ARP opcode (command).  */
#if 0
  /* Ethernet looks like this : This bit is variable sized
     however...  */
  unsigned char __ar_sha[ETH_ALEN];   /* Sender hardware address.  */
  unsigned char __ar_sip[4];          /* Sender IP address.  */
  unsigned char __ar_tha[ETH_ALEN];   /* Target hardware address.  */
  unsigned char __ar_tip[4];          /* Target IP address.  */
#endif
};
