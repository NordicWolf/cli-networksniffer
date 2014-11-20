/**********************************************
* Autor: Aldo Rodríguez Coreño
* Analizador de Protocolos sobre Ethernet II
*
* Esquema básico para la captura de paquetes
***********************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "../include/sniffer.h"

int main(int argc, char *argv[])
{
  int counter;                    /* Establece el límite de paquetes a capturar */
  char errbuf [PCAP_ERRBUF_SIZE]; /* Búfer de mensaje de error */
  char* device;                   /* Nombre del dispositivo de red */
  char* filter;                   /* Apuntador a una cadena de filtro */
  pcap_t* session;                /* Apuntador a una sesión de captura */
  bpf_u_int32 net_mask;           /* Máscara de red */
  bpf_u_int32 net_ip;             /* Dirección de red */
  struct bpf_program bpf;         /* Berkeley Packet Filter */

  /* Obtiene Las opciones de la línea de comandos */
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
  /* Obtiene los atributos de la red (máscara de red, direccion de red)*/
  if (pcap_lookupnet (device, &net_ip, &net_mask, errbuf) < 0)
    {
      fprintf (stderr, "%s\n", errbuf);
      exit (EXIT_FAILURE);
    }

  /* Inicia una sesión para la captura de paquetes */
  session = pcap_open_live (device, BUFSIZ, 1, 100, errbuf);
  if(session == NULL)
    {
      fprintf (stderr, "%s\n", errbuf);
      exit (EXIT_FAILURE);
    }

  /* Se compila el BPF */
  filter = argv[5];
  if(pcap_compile(session, &bpf, filter, 0, net_ip) < 0)
    {
      fprintf (stderr, "Error al compilar el filtro\n");
      exit (EXIT_FAILURE);
    }
  /* Se aplica el BPF */
  if(pcap_setfilter(session, &bpf) < 0)
    {
      fprintf (stderr, "Error al aplicar el filtro\n");
      exit(EXIT_FAILURE);
    }

  /* Inicia la captura de paquetes */
  pcap_loop (session, counter, packet_parser, NULL);

  return EXIT_SUCCESS;
}
