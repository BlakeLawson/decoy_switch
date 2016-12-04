/*
 * Author: Blake Lawson (blawson@princeton.edu)
 * Adviser: Jennifer Rexford
 *
 * Initial code from https://github.com/p4lang/tutorials/blob/master/
 * SIGCOMM_2016/heavy_hitter/p4src/includes/parser.p4
 */

parser start {
  set_metadata(cpu_metadata.from_cpu, FALSE);
  set_metadata(routing_metadata.do_route, TRUE);
  return select(current(0, 64)) {
    0: parse_cpu_header;
    default: parse_ethernet;
  }
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

header cpu_header_t cpu_header;

parser parse_cpu_header {
  extract(cpu_header);
  set_metadata(cpu_metadata.from_cpu, TRUE);
  return parse_ethernet;
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
  set_metadata(tcp_metadata.tcpLength, ipv4.totalLen - 20);
  return ingress;
}
