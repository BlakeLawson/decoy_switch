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


action do_calculate_tag() {
  // 0x100000000 == 2^32
  modify_field_with_hash_based_offset(decoy_metadata.tag, 0, tag_hash, 0x100000000);
}

// Determine whether packet contains tag
table calculate_tag {
  actions {
    do_calculate_tag;
  }
  size: 0;
}

action send_to_proxy(ipAddr, port) {
  // Save the proxy ip address
  modify_field(decoy_metadata.proxyIp, ipAddr);

  // Prepare packet for forwarding to proxy
  modify_field(ipv4.dstAddr, ipAddr);
  modify_field(tcp.dstPort, port);

  // Get rid of cpu header
  remove_header(cpu_header);
}

// Gets the ip addr of the decoy proxy
table proxy_ip_table {
  reads {
    decoy_metadata.tag: valid;
  }
  actions {
    send_to_proxy;
    _no_op;
  }
  size: 1;
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

// Tag the flow
table record_flow {
  actions {
    do_record_flow;
  }
  size: 0;
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
    _no_op;
  }
  size: 256;
}

control tcp_ingress {
  if (tcp.flags == TCP_FLAG_SYN) {
    apply(calculate_tag);
    if (decoy_metadata.tag == tcp.seqNo) {
      if (cpu_metadata.from_cpu == FALSE) {
        // Send to CPU to mark flow
        apply(record_flow);
      } else {
        apply(proxy_ip_table);
      }
    }
  } else {
    // General logic here... If the packet is on its way back from decoy
    // dst, need to restore the covert destination. If the packet is on its
    // way out and the packet is in the tagged table, change the covert
    // destination to the decoy proxy.

    // Check whether the packet is in a tagged flow
    apply(check_tag);
  }
}

table debug {
  reads {
    ipv4.srcAddr: exact;
    tcp.srcPort: exact;
    ipv4.dstAddr: exact;
    tcp.dstPort: exact;
    standard_metadata.instance_type: exact;
  }
  actions {
    _no_op;
  }
  size: 0;
}

/* MAIN INGRESS */

control ingress {
  if (valid(tcp)) {
    apply(debug);
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
