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

  /* {{{ -- ETHERNET II -- */

  /* Payload:       46 - 1500 bytes */
  /* CRC:           4 bytes         */
  printf ("---\n");
  /* }}} */

  struct ethernet_v2* ether_header;
  ether_header = (struct ethernet_v2*) packet;

  /* MAC origen (6 bytes) */
  printf ("MAC origen: %02x:%02x:%02x:%02x:%02x:%02x\n",
          ether_header->ether_shost[0],
          ether_header->ether_shost[1],
          ether_header->ether_shost[2],
          ether_header->ether_shost[3],
          ether_header->ether_shost[4],
          ether_header->ether_shost[5]);
  /* MAC destino (6 bytes) */
  printf ("MAC destino: %02x:%02x:%02x:%02x:%02x:%02x\n",
          ether_header->ether_dhost[0],
          ether_header->ether_dhost[1],
          ether_header->ether_dhost[2],
          ether_header->ether_dhost[3],
          ether_header->ether_dhost[4],
          ether_header->ether_dhost[5]);

  /* Ethertype (2 bytes) */
  ether_type = ntohs (ether_header->ether_type);
  printf ("Tipo: %04x\n", ether_type);

  /* Payload */
  /* {{{ Salta al campo de datos (Payload) */
  ptr = packet + ETHER_HDR_LEN;
  struct ip* ip_header;

  switch (ether_type)
    {
    case ETHERTYPE_IP:          /* 0x800 IPv4 */
      /* {{{ -- IPv4 -- */
      /* Versión                 4 bits  */
      /* IHL                     4 bits  */
      /* Type of service         1 byte  */
      /* Total length            2 bytes */
      /* Identification          2 bytes */
      /* Flags                   3 bits  */
      /* Fragment offset         13 bits */
      /* Time to live            1 byte  */
      /* Protocol                1 byte  */
      /* Header checksum         2 bytes */
      /* Source IP address       4 bytes */
      /* Destination IP address  4 bytes */
      /* Options and padding     4 bytes */
      /* }}} */

      /* Obtiene las direcciones IP */
      /* {{{ */
      ip_header = (struct ip*) ptr;
      printf ("  | Versión: %u IHL: %u bytes - ToS: %X Longitud: %u bytes\n",
              ip_header->ip_v,                      /* Versión */
              ip_header->ip_hl * 4,                 /* Header Length (IHL) */
              ip_header->ip_tos,                    /* Type of service */
              ip_header->ip_len * 4);               /* Total length */
      printf ("  | ID: %u - Banderas: [%c%c%c] Offset: %u \n",
              ip_header->ip_id,                     /* Identification */
              ip_header->ip_off && IP_RF ? '*':'X', /* Reserved fragment flag */
              ip_header->ip_off && IP_DF ? 'D':'*', /* Dont't fragment flag */
              ip_header->ip_off && IP_MF ? 'M':'*', /* More fragments flag */
              ip_header->ip_off & IP_OFFMASK);      /* Fragment offset */
      printf ("  | Tiempo de vida: %u Protocolo: %u - Checksum %X\n",
              ip_header->ip_ttl,                    /* Tiempo de vida */
              ip_header->ip_p,                      /* Protocolo */
              ip_header->ip_sum);                   /* Header Checksum */
      printf ("  | %s -> %s\n",
              inet_ntoa (ip_header->ip_src),        /* IP origen */
              inet_ntoa (ip_header->ip_dst));       /* IP destino */
      break;
      /* }}} */

    case ETHERTYPE_ARP:         /* 0x806 ARP */
      break;
    default:
      fprintf (stderr, "Protocolo no soportado %d\n", ether_type);
      break;
    }
  /* }}} */

}
