/**
 * Estructura del encabezado ICMP
 * netinet/ip_icmp.h
 **/
struct icmphdr
{
  u_int8_t type;                /* message type */
  u_int8_t code;                /* type sub-code */
  u_int16_t checksum;
  union
  {
    struct
    {
      u_int16_t id;
      u_int16_t sequence;
    } echo;                     /* echo datagram */
    u_int32_t   gateway;        /* gateway address */
    struct
    {
      u_int16_t __glibc_reserved;
      u_int16_t mtu;
    } frag;                     /* path mtu discovery */
  } un;
};

/**
 * Estructura del encabezado TCP
 * netinet/tcp.h
 **/
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

/**
 * Estructura del encabezado UDP
 * netinet/udp.h
 **/
struct udphdr
{
  u_int16_t source;
  u_int16_t dest;
  u_int16_t len;
  u_int16_t check;
};
