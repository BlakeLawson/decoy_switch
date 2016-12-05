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
  apply(forward);
}


/* TCP Tagging, etc. */

action send_to_proxy(ipAddr, port) {
  // Prepare packet for forwarding to proxy
  modify_field(ipv4.dstAddr, ipAddr);
  modify_field(tcp.dstPort, port);
}

#define CPU_MIRROR_SESSION_ID 250

field_list copy_to_cpu_fields {
  standard_metadata;
}

action do_record_flow() {
  clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID, copy_to_cpu_fields);

  // Drop the packet. It will be sent once the controller is done
  modify_field(routing_metadata.do_route, FALSE);
  drop();
}

// Update the packet's dest ip and port so it's from the covert dst
action hide_dst(covert_addr, covert_port) {
  modify_field(ipv4.srcAddr, covert_addr);
  modify_field(tcp.srcPort, covert_port);
}

table check_tag {
  reads {
    ipv4.srcAddr: exact;
    tcp.srcPort: exact;
    ipv4.dstAddr: exact;
    tcp.dstPort: exact;
  }
  actions {
    send_to_proxy;
    hide_dst;
    do_record_flow;
  }
  size: 256;
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
    apply(check_tag);
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
}

/* EGRESS */

action rewrite_mac(smac) {
  // TODO: Figure out why the default code changes the srdAddr
  // modify_field(ethernet.srcAddr, smac);
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
  modify_field(cpu_header.reason, 0xab); // Meaningless right now
}

table send_to_cpu {
  actions {
    do_cpu_encap;
  }
  size: 0;
}

control egress {
  if (standard_metadata.instance_type == 0) {
    // Regular packet ready to send
    apply(send_frame);
  } else {
    // CPU packet
    apply(send_to_cpu);
  }
}
