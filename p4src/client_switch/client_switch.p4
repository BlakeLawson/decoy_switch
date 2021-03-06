/*
 * Author: Blake Lawson (blawson@princeton.edu)
 * Adviser: Jennifer Rexford
 *
 * Rewrite requests from client so SYN packets are tagged for detection.
 */
#include "includes/defines.p4"
#include "includes/hashes.p4"
#include "includes/headers.p4"
#include "includes/metadata.p4"
#include "includes/parser.p4"

#define CLIENT_PORT 1
#define WORLD_PORT  2

#define CPU_MIRROR_SESSION_ID 251

action _drop() {
  drop();
}

action _no_op() {
  no_op();
}

/* INGRESS */

field_list copy_to_cpu_fields {
  standard_metadata;
  decoy_metadata;
}

action do_set_tag() {
  // 0x100000000 == 2^32
  modify_field_with_hash_based_offset(decoy_metadata.tag, 0, tag_hash, 0x100000000);
  clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID, copy_to_cpu_fields);
  drop();
}

table set_tag_table {
  actions {
    do_set_tag;
  }
  size: 0;
}

action pos_outbound(seq_diff) {
  modify_field(tcp.seqNo, tcp.seqNo + seq_diff);
}

action pos_inbound(seq_diff) {
  modify_field(tcp.ackNo, tcp.ackNo - seq_diff);
}

action neg_outbound(seq_diff) {
  modify_field(tcp.seqNo, tcp.seqNo - seq_diff);
}

action neg_inbound(seq_diff) {
  modify_field(tcp.ackNo, tcp.ackNo + seq_diff);
}

table tag_offset {
  reads {
    ipv4.srcAddr: exact;
    tcp.srcPort: exact;
    ipv4.dstAddr: exact;
    tcp.dstPort: exact;
  }
  actions {
    pos_outbound;
    pos_inbound;
    neg_outbound;
    neg_inbound;
    _no_op;
  }
  size: 256;
}

action cpu_to_client() {
  remove_header(cpu_header);
  modify_field(standard_metadata.egress_spec, CLIENT_PORT);
}

action cpu_to_world() {
  remove_header(cpu_header);
  modify_field(standard_metadata.egress_spec, WORLD_PORT);
}

table handle_cpu_table {
  reads {
    ipv4.dstAddr: lpm;
  }
  actions {
    cpu_to_client;
    cpu_to_world;
  }
  size: 1;
}

control tcp_ingress {
  if (tcp.flags == TCP_FLAG_SYN) {
    if (cpu_metadata.from_cpu == TRUE) {
      // Remove the cpu headers and update egress port
      apply(handle_cpu_table);
    } else {
      // Mark and send to controller to update tables
      apply(set_tag_table);
    }
  }

  // Lookup in table and do some stuff
  apply(tag_offset);
}

action do_send_to_world() {
  modify_field(standard_metadata.egress_spec, WORLD_PORT);
}

action do_send_to_client() {
  modify_field(standard_metadata.egress_spec, CLIENT_PORT);
}

table send_to_world {
  actions {
    do_send_to_world;
  }
  size: 0;
}

table send_to_client {
  actions {
    do_send_to_client;
  }
  size: 0;
}

control set_egress {
  if (standard_metadata.ingress_port == CLIENT_PORT) {
    apply(send_to_world);
  } else {
    apply(send_to_client);
  }
}

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
    arp.tgtProtoAddr: exact;
  }
  actions {
    set_arp_resp;
    _drop;
  }
}

control arp_ingress {
  if (arp.opCode == ARP_REQUEST) {
    apply(arp_resp_lookup);
  }
}

control ingress {
  set_egress();
  if (valid(tcp)) {
    tcp_ingress();
  }
  if (valid(arp)) {
    arp_ingress();
  }
}

/* EGRESS */

action do_cpu_encap() {
  add_header(client_cpu_header);
  add_header(cpu_header);
  modify_field(cpu_header.preamble, 0);
  modify_field(cpu_header.reason, 0xab);
  modify_field(client_cpu_header.preamble, 0);
  modify_field(client_cpu_header.tag_value, decoy_metadata.tag);
}

table send_to_cpu {
  actions {
    do_cpu_encap;
  }
  size: 0;
}

control egress {
  if (standard_metadata.instance_type != 0) {
    // Packet to controller
    apply(send_to_cpu);
  }
}
