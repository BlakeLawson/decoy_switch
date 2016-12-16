/*
 * Author: Blake Lawson (blawson@princeton.edu)
 * Adviser: Jennifer Rexford
 * 
 * Rewrite dest IP if hidden tags in SYN sequence number detected.
 */
#include "includes/defines.p4"
#include "includes/hashes.p4"
#include "includes/headers.p4"
#include "includes/metadata.p4"
#include "includes/parser.p4"
#include "includes/arp.p4"
#include "includes/standard_actions.p4"
#include "includes/tag_manager.p4"
#include "includes/decoy_routing.p4"

/* INGRESS */

/* IPV4 */

action set_nhop(nhop_ipv4, port) {
  modify_field(routing_metadata.nhop_ipv4, nhop_ipv4);
  modify_field(standard_metadata.egress_spec, port);
  add_to_field(ipv4.ttl, -1);
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

// update_smac used to overwrite src MAC address if the packet is being sent
// by this switch.
//
// NOTE: this is pretty hack-y because in reality, we do not always know the
// MAC address of neighbors, so this only works for this test environment.
// Probably not a big deal for now.
action do_update_smac(smac) {
  modify_field(ethernet.srcAddr, smac);
}
table update_smac {
  reads {
    ipv4.srcAddr: lpm;
  }
  actions {
    do_update_smac;
    _no_op;
  }
  size: 1024;
}

action set_dmac(dmac) {
  modify_field(ethernet.dstAddr, dmac);
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
  apply(update_smac);
  apply(forward);
}

action do_remove_cpu_header() {
  remove_header(cpu_header);
}

table remove_cpu_header {
  actions {
    do_remove_cpu_header;
  }
  size: 0;
}

control tcp_ingress {
  if (cpu_metadata.from_cpu == TRUE) {
    apply(remove_cpu_header);
  }

  // Take care of tag detection/handling
  tagging();
  if (tagging_metadata.ready_for_routing == TRUE) {
    decoy_routing();
  }
}

/* MAIN INGRESS */

control ingress {
  if (valid(tcp)) {
    tcp_ingress();
  }
  if (valid(arp)) {
    arp_ingress();
  }
  if (valid(ipv4) and routing_metadata.do_route == TRUE) {
    ipv4_ingress();
  }

  apply(dbg1);
  decoy_routing_ingress_tail();
  apply(dbg2);
}

table dbg1 {
  reads {
    standard_metadata.egress_spec: exact;
  }
  actions {
    _no_op;
  }
  size:0;
}

table dbg2 {
  reads {
    standard_metadata.egress_spec: exact;
  }
  actions {
    _no_op;
  }
  size:0;
}

/* EGRESS */

action rewrite_mac(smac) {
  modify_field(ethernet.dstAddr, smac);
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

action do_cpu_encap() {
  add_header(cpu_header);
  modify_field(cpu_header.preamble, 0);
  modify_field(cpu_header.reason, cpu_metadata.reason);
}

table send_to_cpu {
  actions {
    do_cpu_encap;
  }
  size: 0;
}

control egress {
  decoy_egress();
  if (decoy_routing_metadata.egress_used == FALSE) {
    if (standard_metadata.instance_type == INSTANCE_TYPE_NORMAL) {
      // Regular packet ready to send
      apply(send_frame);
    } else {
      // CPU packet
      apply(send_to_cpu);
    }
  }
}
