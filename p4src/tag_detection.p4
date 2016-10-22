/*
 * Author: Blake Lawson (blawson@princeton.edu)
 * Adviser: Jennifer Rexford
 * 
 * Rewrite dest IP if hidden tags in TLS ClientHello detected.
 *
 * Base forwarding code from p4 SIGCOMM_2016 tutorial.
 */
#include "includes/defines.p4"
#include "includes/hashes.p4"
#include "includes/headers.p4"
#include "includes/metadata.p4"
#include "includes/parser.p4"

action _no_op() {
  no_op();
}

action _drop() {
  drop();
}

/* INGRESS */

/* IPV4 */

action set_nhop(nhop_ipv4, port) {
  modify_field(routing_metadata.nhop_ipv4, nhop_ipv4);
  modify_field(standard_metadata.egress_spec, port);
  add_to_field(ipv4.ttl, -1);
}

action set_dmac(dmac) {
  modify_field(ethernet.dstAddr, dmac);
}

table ipv4_lpm {
  reads {
    ipv4.dstAddr: lpm;
  }
  actions {
    set_nhop;
    _drop;
  }
  size: 1024;
}

table forward {
  reads {
    routing_metadata.nhop_ipv4: exact;
  }
  actions {
    set_dmac;
    _drop;
  }
  size: 512;
}

control ipv4_ingress {
  apply(ipv4_lpm);
  apply(forward);
}

/* ARP */

// Convert ARP query into response
action set_arp_resp(dmac) {
  // Store relevant information from current packet.
  modify_field(arp_tmp_metadata.reqMac, arp.senderHdwAddr);
  modify_field(arp_tmp_metadata.reqIp, arp.senderProtoAddr);
  modify_field(arp_tmp_metadata.queryMac, dmac);
  modify_field(arp_tmp_metadata.queryIp, arp.tgtProtoAddr);

  // Perform conversion 
  modify_field(arp.opCode, ARP_REPLY);
  modify_field(arp.senderHdwAddr, arp_tmp_metadata.queryMac);
  modify_field(arp.senderProtoAddr, arp_tmp_metadata.queryIp);
  modify_field(arp.tgtHdwAddr, arp_tmp_metadata.reqMac);
  modify_field(arp.tgtProtoAddr, arp_tmp_metadata.reqIp);

  modify_field(ethernet.dstAddr, arp_tmp_metadata.reqMac);
  modify_field(standard_metadata.egress_spec, standard_metadata.ingress_port);
}

table arp_resp_lookup {
  reads {
    arp_tmp_metadata.queryIp: exact;
  }
  actions {
    set_arp_resp;
    _drop;
  }
  size: 128;
}

control arp_ingress {
  if (arp.opCode == ARP_REQUEST) {
    apply(arp_resp_lookup);
  }
}


/* TCP Tagging, etc. */

action check_tag() {
  // set_field_to_hash_index(decoy_metadata.tag, tag_hash, 0, 0);
  modify_field_with_hash_based_offset(decoy_metadata.tag, 0, tag_hash, 0);
}

// Determine whether packet contains tag
table check_tag_table {
  actions {
    check_tag;
  }
  size: 1;
}

action get_proxy_ip(ipAddr, port) {
  // Save the proxy ip address
  modify_field(decoy_metadata.proxyIp, ipAddr);

  // Prepare packet for forwarding to proxy
  modify_field(ipv4.dstAddr, ipAddr);
  modify_field(tcp.dstPort, port);
}

// Gets the ip addr of the decoy proxy
table proxy_ip_table {
  reads {
    decoy_metadata.tag: valid;
  }
  actions {
    get_proxy_ip;
    _no_op;
  }
  size: 1;
}

control tcp_ingress {
  if (tcp.ctrl == TCP_FLAG_SYN) {
    apply(check_tag_table);
    if (decoy_metadata.tag == tcp.seqNo) {
      apply(proxy_ip_table);
    }
  }
}


/* MAIN INGRESS */

control ingress {
  if (valid(tcp)) {
    tcp_ingress();
  }
  if (valid(ipv4)) {
    ipv4_ingress();
  }
  if (valid(arp)) {
    arp_ingress();
  }
}

/* EGRESS */

action rewrite_mac(smac) {
  modify_field(ethernet.srcAddr, smac);
}

table send_frame {
  reads {
    standard_metadata.egress_port: exact;
  }
  actions {
    rewrite_mac;
    _drop;
  }
  size: 256;
}

control egress {
  apply(send_frame);
}
