/* Aldo Rodríguez Coreño */
/* Analizador de Protocolo Ethernet II */

#include "../include/sniffer.h"

/* Procesa los paquetes recibidos */
void print_packet (u_char* arg,
                   const struct pcap_pkthdr* pkthdr,
                   const u_char* packet)
{
  const u_char* ptr;            /* Apuntador a los campos de las cabeceras */
  unsigned short ether_type;    /* Ethertype */

  /* -- ETHERNET II -- */

  struct ethernet_v2* ether_header;
  ether_header = (struct ethernet_v2*) packet;

  /* MAC origen (6 bytes) */
  int i;
  printf ("\nMAC origen:\t");
  for (i = 0; i < 6;
       printf ("%02x%c", 
               ether_header->ether_shost[i],
               i < 5 ? ':' : '\n'),
       i++);

  printf ("MAC destino:\t");
  for (i = 0; i < 6;
       printf ("%02x%c", 
               ether_header->ether_dhost[i],
               i < 5 ? ':' : '\n'),
       i++);

  /* Ethertype (2 bytes) */
  ether_type = ntohs (ether_header->ether_type);
  printf ("Tipo: %04x\n", ether_type);

  /* Payload (46 - 1500 bytes) */
  ptr = packet + ETHER_HDR_LEN;
  struct ip* ip_header;

  switch (ether_type)
    {
    case ETHERTYPE_IP:          /* 0x800 IPv4 */
      /* Obtiene los campos de la cabecera IP */
      ip_header = (struct ip*) ptr;

      printf ("  + Versión: %u\tIHL: %u bytes\tTipo de servicio: %X\tLongitud: %u bytes\n",
              ip_header->ip_v,                            /* Versión */
              ip_header->ip_hl * 4,                       /* Header Length (IHL) */
              ip_header->ip_tos,                          /* Type of service */
              ntohs (ip_header->ip_len));                 /* Total length */
      printf ("  + Id.: %u\tBanderas: %c%c%c\tOffset: %u\n",
              ntohs (ip_header->ip_id),                   /* Identification */
              ip_header->ip_off && IP_RF ? '-':'X',       /* Reserved fragment flag */
              ip_header->ip_off && IP_DF ? 'D':'-',       /* Dont't fragment flag */
              ip_header->ip_off && IP_MF ? 'M':'-',       /* More fragments flag */
              ntohs (ip_header->ip_off) & IP_OFFMASK);    /* Fragment offset */
      printf ("  + TTL: %u\tProtocolo: %s\tChecksum %X\n",
              ip_header->ip_ttl,                          /* Tiempo de vida */
              ip_header->ip_p == IP_PROTO_ICMP ? "ICMP" : /* Protocolo */
              ip_header->ip_p == 6 ? "TCP" :
              ip_header->ip_p == 17 ? "UDP" : "Desconocido",
              ip_header->ip_sum);                         /* Header Checksum */
      printf ("  + IP origen:\t%s\n",                     /* IP origen */
              inet_ntoa (ip_header->ip_src));
      printf ("  + IP destino:\t%s\n",                    /* IP destino */
              inet_ntoa (ip_header->ip_dst));

      /* Imprime los campos de la capa de transporte */
      switch (ip_header->ip_p)
        {
        case IP_PROTO_ICMP:     /* 1 ICMP */
          /* Obtiene los campos de la cabecera ICMP */
          break;
        case IP_PROTO_TCP:      /* 6 TCP */
          /* Obtiene los campos de la cabecera TCP */
          break;
        case IP_PROTO_UDP:      /* 17 UDP */
          /* Obtiene los campos de la cabecera UDP */
          break;
        default:                /* No implementado o desconocido */
          fprintf (stderr, "Protocolo no soportado: %u\n",
                   ip_header->ip_p);
        }
      break;

    case ETHERTYPE_ARP:         /* 0x806 ARP */
      break;
    default:
      fprintf (stderr, "Protocolo no soportado %d\n", ether_type);
      break;
    }

  /* CRC (4 bytes) */
  
}
