/**********************************************
* Autor: Aldo Rodríguez Coreño
* Analizador de Protocolos sobre Ethernet II
*
* Extracción de datos de los paquetes de red
***********************************************/

#include "../include/sniffer.h"

/* Procesa los paquetes recibidos */
void packet_parser (u_char* arg,
                   const struct pcap_pkthdr* pkthdr,
                   const u_char* packet)
{
  const u_char* ptr;            /* Apuntador a datos dentro del paquete */
  unsigned short ether_type;    /* Ethertype */
  struct tcp_ip data;

  /* -- ETHERNET II -- */
  data.datalink = (struct ethernet*) packet;
  ether_type = ntohs (data.datalink->ether_type);

  /* Payload (46 - 1500 bytes) */
  ptr = packet + ETHER_HDR_LEN;

  switch (ether_type)
    {
    case ETHERTYPE_IP:          /* 0x800 IPv4 */
      /* Obtiene los campos de la cabecera IP */
      data.network.ip_hdr = (struct ip*) ptr;

      /* Obtiene los campos de la capa de transporte */
      ptr += data.network.ip_hdr->ip_hl * 4;
      switch (data.network.ip_hdr->ip_p)
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
                   data.network.ip_hdr->ip_p);
        }
      break;

    case ETHERTYPE_ARP:         /* 0x806 ARP */
      data.network.arp_hdr = (struct arp*) ptr;
      break;
    default:
      fprintf (stderr, "Ethertype no soportado: %d\n",
               ether_type);
      break;
    }

  print_data (&data);
}

void print_data (struct tcp_ip* data)
{
  /* Cabecera Ethernet II */
  int i;
  printf("\n\t[");                /* MAC origen (6 bytes) */
  for (i = 0; i < 6;
       printf ("%02x%c",
               data->datalink->ether_shost[i],
               i < 5 ? ':' : ' '), i++);
  for (i = 0; i < 6;            /* MAC destino (6 bytes) */
       printf ("%02x%c",
               data->datalink->ether_dhost[i],
               i < 5 ? ':' : ']'), i++);

  int ether_type = ntohs (data->datalink->ether_type);
  printf ("\t%s (0x%x)\n",      /* Ethertype (2 bytes) */
          ether_type == 0x800 ? "IP" : "ARP",
          ether_type);

  puts("\t----------------------------------------------------");
  switch (ether_type)
    {
    case ETHERTYPE_IP:          /* Cabecera IP */
      printf ("\tVer: %u\tIHL: %u bytes\tToS:%X\tLongitud: %u bytes\n",
              data->network.ip_hdr->ip_v,
              data->network.ip_hdr->ip_hl * 4,
              data->network.ip_hdr->ip_tos,
              ntohs (data->network.ip_hdr->ip_len));
      printf ("\tId.: %u\tBanderas: %c%c%c\tOffset: %u\n",
              ntohs (data->network.ip_hdr->ip_id),
              data->network.ip_hdr->ip_off && IP_RF ? '-':'X',
              data->network.ip_hdr->ip_off && IP_DF ? 'D':'-',
              data->network.ip_hdr->ip_off && IP_MF ? 'M':'-',
              ntohs (data->network.ip_hdr->ip_off) & IP_OFFMASK);
      printf ("\tTTL: %u\tProto: %s\tChecksum %X\n",
              data->network.ip_hdr->ip_ttl,
              data->network.ip_hdr->ip_p == IP_PROTO_ICMP ? "ICMP" :
              data->network.ip_hdr->ip_p == IP_PROTO_TCP ? "TCP" :
              data->network.ip_hdr->ip_p == IP_PROTO_UDP ? "UDP" : "Desconocido",
              data->network.ip_hdr->ip_sum);
      printf ("\tIP origen:\t%s\n",
              inet_ntoa (data->network.ip_hdr->ip_src));
      printf ("\tIP destino:\t%s\n",
              inet_ntoa (data->network.ip_hdr->ip_dst));
      puts("\t----------------------------------------------------");
      /* Cabecera ICMP */
      switch (data->network.ip_hdr->ip_p)
        {
        case IP_PROTO_ICMP:
          printf("\tTipo: %u\tCódigo: %u\tChecksum: %X\n",
                 data->transport.icmp_hdr->type,
                 data->transport.icmp_hdr->code,
                 data->transport.icmp_hdr->checksum);
          if (data->transport.icmp_hdr->type == 0 ||
              data->transport.icmp_hdr->type == 8)
            {
              printf ("\tId: %u\tNum. secuencia: %u\n",
                      ntohs (data->transport.icmp_hdr->un.echo.id),
                      ntohs (data->transport.icmp_hdr->un.echo.sequence));
            }
          break;
        case IP_PROTO_TCP:
          printf ("\tPuerto origen: %u\tPuerto destino: %u\n",
                  ntohs (data->transport.tcp_hdr->th_sport),
                  ntohs (data->transport.tcp_hdr->th_dport));
          printf ("\tNum. secuencia: %u\tNum. Ack: %u\n",
                  ntohl (data->transport.tcp_hdr->th_seq),
                  ntohl (data->transport.tcp_hdr->th_ack));
          printf ("\tOffset: %u\tBanderas: %c%c%c%c%c%c\tWin: %u\n",
                  data->transport.tcp_hdr->th_off,
                  data->transport.tcp_hdr->th_flags & TH_URG ? 'U' : '-',
                  data->transport.tcp_hdr->th_flags & TH_ACK ? 'A' : '-',
                  data->transport.tcp_hdr->th_flags & TH_PUSH ? 'P' : '-',
                  data->transport.tcp_hdr->th_flags & TH_RST ? 'R' : '-',
                  data->transport.tcp_hdr->th_flags & TH_SYN ? 'S' : '-',
                  data->transport.tcp_hdr->th_flags & TH_FIN ? 'F' : '-',
                  ntohs (data->transport.tcp_hdr->th_win));
          printf ("\tChecksum: %X\tUrg. pointer: %u\n",
                  ntohs (data->transport.tcp_hdr->th_sum),
                  ntohs (data->transport.tcp_hdr->th_urp));
          break;
        case IP_PROTO_UDP:
          printf ("\tPuerto origen: %u\tPuerto destino: %u\n",
                  ntohs (data->transport.udp_hdr->source),
                  ntohs (data->transport.udp_hdr->dest));
          printf ("\tLongitud: %u\tChecksum: %X\n",
                  ntohs (data->transport.udp_hdr->len),
                  ntohs (data->transport.udp_hdr->check));
          break;
        default:
          printf ("Protocolo no implementado: %u\n",
                  data->network.ip_hdr->ip_p);
        }
      break;
      /* Cabecera ARP */
    case ETHERTYPE_ARP:
      printf ("\tHAT: %u (%s)\tPAT: %u (%s)\n",
              ntohs(data->network.arp_hdr->ar_hrd),
              ntohs(data->network.arp_hdr->ar_hrd) == 1 ? "Ethernet" :
              ntohs(data->network.arp_hdr->ar_hrd) == 6 ? "IEEE 802 LAN" : "Desconocido",
              ntohs(data->network.arp_hdr->ar_pro),
              ntohs(data->network.arp_hdr->ar_pro) == 2048 ? "IPv4" : "Desconocido");
      printf ("\tHAL: %u (%s)\tPAL: %u (%s)\tOp: %u (%s)\n",
              data->network.arp_hdr->ar_hln,
              data->network.arp_hdr->ar_hln == 6 ? "Ethernet/IEEE 802" : "Desconocido",
              data->network.arp_hdr->ar_pln,
              data->network.arp_hdr->ar_pln == 4 ? "IPv4" : "Desconocido",
              ntohs(data->network.arp_hdr->ar_op),
              ntohs(data->network.arp_hdr->ar_op) == 1 ? "Request" :
              ntohs(data->network.arp_hdr->ar_op) == 2 ? "Reply" : "Desconocido");
      putchar('\t');
      for (i = 0; i < 6;        /* Source Hardware Address */
           printf ("%02x%c",
                   data->network.arp_hdr->__ar_sha[i],
                   i < 5 ? ':' : ' '), i++);
      putchar('\t');
      for (i = 0; i < 4;        /* Source Protocol Address */
           printf ("%u%c",
                   data->network.arp_hdr->__ar_sip[i],
                   i < 3 ? '.' : ' '), i++);
      putchar('\n');
      putchar('\t');
      for (i = 0; i < 6;        /* Target Hardware Address */
           printf ("%02x%c",
                   data->network.arp_hdr->__ar_tha[i],
                   i < 5 ? ':' : ' '), i++);
      putchar('\t');
      for (i = 0; i < 4;        /* Target Protocol Address */
           printf ("%u%c",
                   data->network.arp_hdr->__ar_tip[i],
                   i < 3 ? '.' : ' '), i++);
      putchar('\n');
      break;
    }
}
