/*
 * Author: Blake Lawson (blawson@princeton.edu)
 * Adviser: Jennifer Rexford
 *
 * Initial code from https://github.com/p4lang/tutorials/blob/master
 * /SIGCOMM_2016/heavy_hitter/p4src/includes/parser.p4
 */

parser start {
  return parse_ethernet;
}

header ethernet_t ethernet;

parser parse_ethernet {
  extract(ethernet);
  return select(latest.etherType) {
    ETHERTYPE_IPV4 : parse_ipv4;
    ETHERTYPE_ARP : parse_arp;
    default: ingress;
  }
}

header arp_t arp;

parser parse_arp {
  extract(arp);
  return ingress;
}

header ipv4_t ipv4;

parser parse_ipv4 {
  extract(ipv4);
  return select(latest.protocol) {
    IP_PROTOCOLS_TCP : parse_tcp;
    default: ingress;
  }
}

header tcp_t tcp;

parser parse_tcp {
  extract(tcp);
  return ingress;
}
