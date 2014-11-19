#include <pcap/pcap.h>
#include <unistd.h>
#include "network_access.h"     /* Estructura ethernet */
#include "internet.h"           /* Estructuras IP, ARP */
#include "transport.h"          /* Estructuras ICMP, TCP, UDP */

/**
 * Estructura del modelo TCP/IP
 **/
struct pkt_data
{
  /* Network Access Layer */
  struct ethernet* network_access;
  /* Internet Layer */
  union
  {
    struct ip* ip_hdr;
    struct arp* arp_hdr;
  } internet;
  /* Transport Layer */
  union
  {
    struct icmphdr* icmp_hdr;
    struct tcphdr* tcp_hdr;
    struct udphdr* udp_hdr;
  } transport;
  /* Appplication Layer (Not implemented yet) */
};

/* Procesa los paquetes recibidos */
void packet_parser (u_char*, const struct pcap_pkthdr*, const u_char*);

/* Muestra los datos de los paquetes capturados */
void print_data (struct pkt_data*);
