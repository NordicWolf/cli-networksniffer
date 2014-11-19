/* Aldo Rodríguez Coreño */
/* Analizador de Protocolo Ethernet II */

#include "../include/sniffer.h"

/* Procesa los paquetes recibidos */
void packet_parser (u_char* arg,
                   const struct pcap_pkthdr* pkthdr,
                   const u_char* packet)
{
  const u_char* ptr;            /* Apuntador a los campos de las cabeceras */
  unsigned short ether_type;    /* Ethertype */
  struct pkt_data data;

  /* -- ETHERNET II -- */
  data.network_access = (struct ethernet*) packet;
  ether_type = ntohs (data.network_access->ether_type);

  /* Payload (46 - 1500 bytes) */
  ptr = packet + ETHER_HDR_LEN;

  switch (ether_type)
    {
    case ETHERTYPE_IP:          /* 0x800 IPv4 */
      /* Obtiene los campos de la cabecera IP */
      data.internet.ip_hdr = (struct ip*) ptr;

      /* Obtiene los campos de la capa de transporte */
      ptr = packet + data.internet.ip_hdr->ip_hl;
      switch (data.internet.ip_hdr->ip_p)
        {
        case IP_PROTO_ICMP:     /* 1 ICMP */
          data.transport.icmp_hdr = (struct icmphdr*) ptr;
          break;
        case IP_PROTO_TCP:      /* 6 TCP */
          data.transport.tcp_hdr = (struct tcphdr*) ptr;
          break;
        case IP_PROTO_UDP:      /* 17 UDP */
          data.transport.udp_hdr = (struct udphdr*) ptr;
          break;
        default:                /* No implementado o desconocido */
          fprintf (stderr, "Protocolo no soportado: %u\n",
                   data.internet.ip_hdr->ip_p);
        }
      break;

    case ETHERTYPE_ARP:         /* 0x806 ARP */
      data.internet.arp_hdr = (struct arp*) ptr;
      break;
    default:
      fprintf (stderr, "Ethertype no soportado: %d\n",
               ether_type);
      break;
    }

  print_data (&data);
}

void print_data (struct pkt_data* data)
{
  /* Cabecera Ethernet II */
  int i;
  printf ("\nMAC origen:\t");   /* MAC origen (6 bytes) */
  for (i = 0; i < 6;
       printf ("%02x%c",
               data->network_access->ether_shost[i],
               i < 5 ? ':' : '\n'),
         i++);

  printf ("MAC destino:\t");    /* MAC destino (6 bytes) */
  for (i = 0; i < 6;
       printf ("%02x%c",
               data->network_access->ether_dhost[i],
               i < 5 ? ':' : '\n'),
         i++);

  printf ("Tipo: %04x\n",       /* Ethertype (2 bytes) */
          ntohs (data->network_access->ether_type));

  /* Cabecera IP */
  /* printf ("\tVersión: %u\tIHL: %u bytes\tTipo de servicio: %X\tLongitud: %u bytes\n", */
  /*         ip_header->ip_v,                            /\* Versión *\/ */
  /*         ip_header->ip_hl * 4,                       /\* Header Length (IHL) *\/ */
  /*         ip_header->ip_tos,                          /\* Type of service *\/ */
  /*         ntohs (ip_header->ip_len));                 /\* Total length *\/ */
  /* printf ("\tId.: %u\tBanderas: %c%c%c\tOffset: %u\n", */
  /*         ntohs (ip_header->ip_id),                   /\* Identification *\/ */
  /*         ip_header->ip_off && IP_RF ? '-':'X',       /\* Reserved fragment flag *\/ */
  /*         ip_header->ip_off && IP_DF ? 'D':'-',       /\* Dont't fragment flag *\/ */
  /*         ip_header->ip_off && IP_MF ? 'M':'-',       /\* More fragments flag *\/ */
  /*         ntohs (ip_header->ip_off) & IP_OFFMASK);    /\* Fragment offset *\/ */
  /* printf ("\tTTL: %u\tProtocolo: %s\tChecksum %X\n", */
  /*         ip_header->ip_ttl,                          /\* Tiempo de vida *\/ */
  /*         ip_header->ip_p == IP_PROTO_ICMP ? "ICMP" : /\* Protocolo *\/ */
  /*         ip_header->ip_p == 6 ? "TCP" : */
  /*         ip_header->ip_p == 17 ? "UDP" : "Desconocido", */
  /*         ip_header->ip_sum);                         /\* Header Checksum *\/ */
  /* printf ("\tIP origen:\t%s\n",                       /\* IP origen *\/ */
  /*         inet_ntoa (ip_header->ip_src)); */
  /* printf ("\tIP destino:\t%s\n\n",                    /\* IP destino *\/ */
  /*         inet_ntoa (ip_header->ip_dst)); */
}
