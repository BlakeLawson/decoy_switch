/*
 * Author: Blake Lawson (blawson@princeton.edu)
 * Adviser: Jennifer Rexford
 *
 * Definitions used throughout tag_detection
 */

/* BOOLEAN */
#define FALSE               0
#define TRUE                1

/* ETHERTYPE */
#define ETHERTYPE_IPV4      0x0800
#define ETHERTYPE_ARP       0x0806
#define ETHERTYPE_ETHERNET  0x6558
#define ETHERTYPE_VLAN      0x8100
#define ETHERTYPE_IPV6      0x8600

/* ARP OPS */
#define ARP_REQUEST         1
#define ARP_REPLY           2
#define RARP_REQUEST        3
#define RARP_REPLY          4
#define DRARP_REQUEST       5
#define DRARP_REPLY         6
#define DRARP_ERROR         7
#define INARP_REQUEST       8
#define INARP_REPLY         9

/* IP PROTOCOLS */
#define IP_PROTOCOLS_ICMP   1
#define IP_PROTOCOLS_IGMP   2
#define IP_PROTOCOLS_IPV4   4
#define IP_PROTOCOLS_TCP    6
#define IP_PROTOCOLS_UDP    17
#define IP_PROTOCOLS_IPV6   41

/* TCP Flags */
#define TCP_FLAG_FIN        1
#define TCP_FLAG_SYN        2
#define TCP_FLAG_RST        4
#define TCP_FLAG_PSH        8
#define TCP_FLAG_ACK        16
#define TCP_FLAG_URG        32
