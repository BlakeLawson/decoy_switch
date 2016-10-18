/*
 * Author: Blake Lawson (blawson@princeton.edu)
 * Adviser: Jennifer Rexford
 * 
 * Rewrite dest IP if hidden tags in TLS ClientHello detected.
 *
 * Base forwarding code from p4 SIGCOMM_2016 tutorial.
 */
#include "includes/headers.p4"
#include "includes/parser.p4"

field_list ipv4_checksum_list {
  ipv4.version;
  ipv4.ihl;
  ipv4.diffserv;
  ipv4.totalLen;
  ipv4.identification;
  ipv4.flags;
  ipv4.fragOffset;
  ipv4.ttl;
  ipv4.protocol;
  ipv4.srcAddr;
  ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
  input {
    ipv4_checksum_list;
  }
  algorithm: csum16;
  output_width: 16;
}

calculated_field ipv4.hdrChecksum {
  verify ipv4_checksum;
  update ipv4_checksum;
}

action _drop() {
  drop();
}

header_type custom_metadata_t {
  fields {
    nhop_ipv4: 32;
  }
}

metadata custom_metadata_t custom_metadata;

action set_nhop(nhop_ipv4, port) {
  modify_field(custom_metadata.nhop_ipv4, nhop_ipv4);
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
    custom_metadata.nhop_ipv4: exact;
  }
  actions {
    set_dmac;
    _drop;
  }
  size: 512;
}

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

control ingress {
  apply(ipv4_lpm);
  apply(forward);
}

control egress {
  apply(send_frame);
}
