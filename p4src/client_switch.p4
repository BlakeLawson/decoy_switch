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

action _drop() {
  drop();
}

/* INGRESS */

action set_tag() {
  // 0x100000000 == 2^32
  modify_field_with_hash_based_offset(tcp.seqNo, 0, tag_hash, 0x100000000);
}

table set_tag_table {
  actions {
    set_tag;
  }
  size: 0;
}

control tcp_ingress {
  if (tcp.flags == TCP_FLAG_SYN) {
    apply(set_tag_table);
  }
}

action send_to_world() {
  modify_field(standard_metadata.egress_spec, WORLD_PORT);
}

action send_to_client() {
  modify_field(standard_metadata.egress_spec, CLIENT_PORT);
}

table send_to_world {
  actions {
    send_to_world;
  }
  size: 0;
}

table send_to_client {
  actions {
    send_to_client;
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
  if (valid(tcp)) {
    tcp_ingress();
  }
  set_egress();
  if (valid(arp)) {
    arp_ingress();
  }
}

/* EGRESS */

control egress {
}
