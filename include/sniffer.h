#include <pcap/pcap.h>
#include <unistd.h>
#include "datalink.h"           /* Estructura Ethernet */
#include "network.h"           /* Estructuras IP, ARP */
#include "transport.h"          /* Estructuras ICMP, TCP, UDP */

/**
 * Estructura del modelo TCP/IP
 **/
struct tcp_ip
{
  /* Network Access Layer */
  struct ethernet* datalink;
  /* Internet Layer */
  union
  {
    struct ip* ip_hdr;
    struct arp* arp_hdr;
  } network;
  /* Transport Layer */
  union
  {
    struct icmphdr* icmp_hdr;
    struct tcphdr* tcp_hdr;
    struct udphdr* udp_hdr;
  } transport;
};

/* Procesa los paquetes recibidos */
void packet_parser (u_char*, const struct pcap_pkthdr*, const u_char*);

/* Muestra los datos de los paquetes capturados */
void print_data (struct tcp_ip*);
