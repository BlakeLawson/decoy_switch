/*
 * Author: Blake Lawson
 * Adviser: Jennifer Rexford
 */

/* IPv4 Routing */
header_type routing_metadata_t {
  fields {
    nhop_ipv4: 32;
    do_route: 1;
  }
}
metadata routing_metadata_t routing_metadata;

/* ARP Reply fields */
header_type arp_tmp_metadata_t {
  fields {
    reqMac: 48;
    reqIp: 32;
    queryMac: 48;
    queryIp: 32;
  }
}
metadata arp_tmp_metadata_t arp_tmp_metadata;

/* Decoy switching metadata */
header_type decoy_metadata_t {
  fields {
    tag : 32;
    proxyIp : 32;
  }
}
metadata decoy_metadata_t decoy_metadata;

/* Metadata for CPU offloading */
header_type cpu_metadata_t {
  fields {
    from_cpu : 1;
  }
}
metadata cpu_metadata_t cpu_metadata;

/* TCP metadata */
header_type tcp_metadata_t {
  fields {
    tcpLength : 16;
  }
}
metadata tcp_metadata_t tcp_metadata;
