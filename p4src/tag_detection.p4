/*
 * Author: Blake Lawson (blawson@princeton.edu)
 * Adviser: Jennifer Rexford
 * 
 * Rewrite dest IP if hidden tags in TLS ClientHello detected.
 *
 * Base forwarding code from p4 SIGCOMM_2016 tutorial.
 */
#include "includes/defines.p4"
#include "includes/headers.p4"
#include "includes/metadata.p4"
#include "includes/parser.p4"

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


/* Store relevant information from current packet. */
action set_arp_metadata() {
  modify_field(arp_tmp_metadata.reqMac, arp.senderHdwAddr);
  modify_field(arp_tmp_metadata.reqIp, arp.senderProtoAddr);
  modify_field(arp_tmp_metadata.queryIp, arp.tgtProtoAddr);
}

/* This table used to filter out all but ARP Requests */
table arp_op_filter {
  reads {
    arp.opCode: exact;
  }
  actions {
    set_arp_metadata;
    _drop;
  }
  size: 128;
}

/* Convert ARP query into response */
action set_arp_resp(dmac) {
  modify_field(arp_tmp_metadata.queryMac, dmac);

  /* Perform conversion */
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
  apply(arp_op_filter);
  apply(arp_resp_lookup);
}

control ingress {
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
