/*
 * Author: Blake Lawson (blawson@princeton.edu)
 * Adviser: Jennifer Rexford
 */

/* Intrinsic data defined as recommended for switch emulator */
header_type intrinsic_metadata_t {
  fields {
    ingress_global_timestamp : 48;
    lf_field_list : 8;
    mcast_grp : 16;
    egress_rid : 16;
    resubmit_flag : 8;
    recirculate_flag : 8;
  }
}
metadata intrinsic_metadata_t intrinsic_metadata;


/* Temporary variables */
header_type scratch_t {
  fields {
    s1: 1;
    s4: 4;
    s8: 8;
    s16: 16;
    s32: 32;
    s48: 48;
  }
}
metadata scratch_t scratch;


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


/* Metadata for CPU offloading */
header_type cpu_metadata_t {
  fields {
    from_cpu : 1;
    reason: 8;
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
