#include <linux/if_ether.h>     /* IEEE 802.3 Ethernet constants */

/* Ethernet protocol ID's */
#define	ETHERTYPE_IP   0x0800   /* IP */
#define	ETHERTYPE_ARP  0x0806   /* Address resolution */
#define	ETHER_ADDR_LEN ETH_ALEN /* size of ethernet addr */
#define	ETHER_HDR_LEN  ETH_HLEN /* total octets in header */

/**
 * Estructura para el encabezado ETHERNET II
 * net/ethernet.h
 **/
struct ethernet                    /* 10Mb/s ethernet header */
{
  u_int8_t  ether_dhost[ETH_ALEN]; /* destination eth addr */
  u_int8_t  ether_shost[ETH_ALEN]; /* source ether addr */
  u_int16_t ether_type;            /* packet type ID field */
} __attribute__ ((__packed__));
