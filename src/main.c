/* Aldo Rodríguez Coreño */
/* Analizador de Protocolo Ethernet II */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../include/sniffer.h"

int main(int argc, char *argv[])
{
  int counter;                  /* Establece el límite de paquetes a capturar */
  char* device;
  char errbuf [PCAP_ERRBUF_SIZE];
  pcap_t* session;
  bpf_u_int32 net_mask;         /* Máscara de red */
  bpf_u_int32 net_ip;           /* Dirección IP */
  struct bpf_program filter;    /* Berkeley Packet Filter struct */

  /* Obtiene Las opciones de la línea de comandos */
  /* {{{ */
  int opciones;
  while ((opciones = getopt (argc, argv, "i:c:")) != -1)
    {
      switch (opciones)
        {
        case 'i':               /* Establece el nombre del dispositivo */
          device = optarg;
          break;
        case 'c':               /* Establece el límite de paquetes en la captura */
          counter = atoi (optarg);
          break;
        default:
          break;
        }
    }
  /* }}} */
  /* Obtiene los parámetros de la red (net_mask, net_ip)*/
  /* {{{ */
  pcap_lookupnet (device, &net_ip, &net_mask, errbuf);
  printf ("Se inicia la captura desde el dispositivo %s con filtro %s\n", device, argv[5]);
  /* }}} */
  /* Inicia una sesión para la captura de paquetes */
  /* {{{ */
  session = pcap_open_live (device, BUFSIZ, 0, 1000, errbuf);
  if(session == NULL)
    {
      fprintf (stderr, "Error al iniciar la captura [%s]\n", errbuf);
      exit (EXIT_FAILURE);
    }
  /* }}} */
  /* Prepara el filtro BPF pasado como argumento */
  /* {{{ */
  /* Se compila el BPF */
  if(pcap_compile(session, &filter, argv[5], 0, net_ip) == -1)
    {
      fprintf (stderr, "Error al compilar el BPF\n");
      exit (EXIT_FAILURE);
    }
  /* Se aplica el BPF */
  if(pcap_setfilter(session, &filter) == -1)
    {
      fprintf (stderr, "Error al aplicar el BPF\n");
      exit(EXIT_FAILURE);
    }
  /* }}} */
  /* Inicia la captura de paquetes */
  /* {{{ */
  pcap_loop (session, counter, packet_parser, NULL);
  /* }}} */

  return EXIT_SUCCESS;
}
