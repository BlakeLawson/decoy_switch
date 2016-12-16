/*
 * Author: Blake Lawson (blawson@princeton.edu)
 * Adviser: Jennifer Rexford
 *
 * This module handles all of the connection setup that is required to
 * configure Decoy Switching once the client sends the address of the
 * covert destination.
 *
 * To invoke this module, call the decoy_routing() control. When this module
 * is done configuring the connection to the covert destination,
 * decoy_routing_metadata.done will be set to 1. Otherwise, it will be set
 * to 0.
 *
 * When using this module, it is also necessary to invoke the decoy_egress()
 * control in the egress pipeline. The decoy_egress control sets metadata
 * field decoy_routing_metadata.egress_used to 1 if this module did something
 * to the packet that should not be changed. Check that field after invoking,
 * and if it is 1, do not do anything else to the packet.
 *
 * Also necessary to call decoy_routing_ingress_tail() at the end of the
 * ingress pipeline.
 */

header_type decoy_routing_metadata_t {
  fields {
    done: 1;
    egress_used: 1;
    isCopy: 1;
    doClone: 1;
    synAck: 1;
    inToClient: 1;
    outFromClient: 1;
    newIpSrc: 32;
    newTcpSport: 16;
    newIpDst: 32;
    newTcpDport: 16;
  }
}
metadata decoy_routing_metadata_t decoy_routing_metadata;


field_list recirculate_fields {
  standard_metadata;
  decoy_routing_metadata;
}


// ----------------------------------------------------------------------------


action do_set_synack_metadata() {
  modify_field(decoy_routing_metadata.synAck, TRUE);
}
table set_synack_metadata {
  actions {
    do_set_synack_metadata;
  }
  size: 0;
}


action out_from_client(newSrc, newSport, newDst, newDport) {
  modify_field(decoy_routing_metadata.outFromClient, TRUE);
  modify_field(decoy_routing_metadata.newIpSrc, newSrc);
  modify_field(decoy_routing_metadata.newTcpSport, newSport);
  modify_field(decoy_routing_metadata.newIpDst, newDst);
  modify_field(decoy_routing_metadata.newTcpDport, newDport);
}
action in_to_client(newSrc, newSport, newDst, newDport) {
  modify_field(decoy_routing_metadata.inToClient, TRUE);
  modify_field(decoy_routing_metadata.newIpSrc, newSrc);
  modify_field(decoy_routing_metadata.newTcpSport, newSport);
  modify_field(decoy_routing_metadata.newIpDst, newDst);
  modify_field(decoy_routing_metadata.newTcpDport, newDport);
}
table check_mappings {
  reads {
    ipv4.srcAddr: exact;
    tcp.srcPort: exact;
    ipv4.dstAddr: exact;
    tcp.dstPort: exact;
  }
  actions {
    out_from_client;
    in_to_client;
    _no_op;
  }
  size: 256;
}


control init_metadata {
  if (tcp.flags == TCP_FLAG_SYN | TCP_FLAG_ACK) {
    apply(set_synack_metadata);
  }
  apply(check_mappings);
}


// ----------------------------------------------------------------------------


// Close the connection to the decoy destination.
action do_close_connection() {
  modify_field(tcp.flags, TCP_FLAG_RST);
  modify_field(tcp.ackNo, 0);
  modify_field(tcp.dataOffset, 5);
  modify_field(ipv4.totalLen, IPV4_HEADER_LEN + TCP_HEADER_LEN);
  truncate(ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN);  // Discard the payload

  // Recirculate the packet in order to send SYN to covert
  modify_field(decoy_routing_metadata.doClone, TRUE);
}
table close_connection {
  actions {
    do_close_connection;
  }
  size: 0;
}


// Convert the packet into a SYN packet to the covert destination.
//
// TODO: Debug this. Think about how to calculate the seq and ack differences
action do_open_covert_connection() {
  modify_field(ipv4.srcAddr, decoy_routing_metadata.newIpSrc);
  modify_field(ipv4.dstAddr, decoy_routing_metadata.newIpDst);
  modify_field(tcp.srcPort, decoy_routing_metadata.newTcpSport);
  modify_field(tcp.dstPort, decoy_routing_metadata.newTcpDport);

  modify_field(tcp.flags, TCP_FLAG_SYN);
  modify_field(tcp.ackNo, 0);
  modify_field(ipv4.totalLen, IPV4_HEADER_LEN + TCP_HEADER_LEN);
  truncate(ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN);  // Discard the payload

  // Mark so it doesn't get caught in egress
  modify_field(standard_metadata.instance_type, INSTANCE_TYPE_NORMAL);
  modify_field(decoy_routing_metadata.isCopy, FALSE);
  modify_field(decoy_routing_metadata.doClone, FALSE);
}
table open_covert_connection {
  actions {
    do_open_covert_connection;
  }
  size: 0;
}


table debug1 {
  reads {
    tcp.flags: exact;
    ipv4.srcAddr: exact;
    tcp.srcPort: exact;
    ipv4.dstAddr: exact;
    tcp.dstPort: exact;
    standard_metadata.instance_type: exact;
    cpu_metadata.from_cpu: exact;
    decoy_routing_metadata.isCopy: exact;
  }
  actions {
    _no_op;
  }
  size: 0;
}


table debug2 {
  reads {
    tcp.flags: exact;
    ipv4.srcAddr: exact;
    tcp.srcPort: exact;
    ipv4.dstAddr: exact;
    tcp.dstPort: exact;
    standard_metadata.instance_type: exact;
    cpu_metadata.from_cpu: exact;
    decoy_routing_metadata.isCopy: exact;
  }
  actions {
    _no_op;
  }
  size: 0;
}

// Take care of packet on its way out. In the normal case, simply update the
// IP addresses and TCP ports, but extra work to do in connection set up.
control handle_out_from_client {
  if (cpu_metadata.from_cpu == TRUE) {
    // It must be the case that the CPU just recorded the flow for the first
    // time. In that case, it is time to start a new connection with the covert
    // destination.
    apply(close_connection);
    apply(debug1);
  }
  if (decoy_routing_metadata.isCopy == TRUE) {
    // This packet should be sent to start a new connection to the covert
    // destination.
    apply(open_covert_connection);
    apply(debug2);
  }
}


// ----------------------------------------------------------------------------


// Take care of packet on its way back to client. In normal case, update IP
// addresses and TCP ports. Extra work required in connection set up.
control handle_in_to_client {
  
}


// ----------------------------------------------------------------------------


// Send the packet to CPU to read the covert destination and add the flow to
// the tag mapping table.
action do_parse_covert() {
  modify_field(cpu_metadata.reason, CPU_REASON_PARSE_COVERT);
  clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID, copy_to_cpu_fields);

  // Drop the packet. It will be sent once the controller is done
  modify_field(routing_metadata.do_route, FALSE);
  drop();
}
table parse_covert {
  actions {
    do_parse_covert;
  }
  size: 0;
}

// Send the flow to the CPU to parse the covert destination and record the flow
// for later use.
control register_flow {
  if (tagging_metadata.ready_for_routing == TRUE) {
    apply(parse_covert);
  }
}


// ----------------------------------------------------------------------------


// Main for this module
control decoy_routing {
  init_metadata();
  
  // Determine state
  if (decoy_routing_metadata.outFromClient == TRUE) {
    handle_out_from_client();
  } else {
    if (decoy_routing_metadata.inToClient == TRUE) {
      handle_in_to_client();
    } else {
      // Flow hasn't been registered yet
      register_flow();
    }
  }
}


// ----------------------------------------------------------------------------

action do_decoy_clone() {
  modify_field(decoy_routing_metadata.isCopy, TRUE);
  clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID, recirculate_fields);
}
table decoy_clone {
  actions {
    do_decoy_clone;
  }
  size: 0;
}

// ----------------------------------------------------------------------------

// Control that should be called at the end of the ingress pipeline
control decoy_routing_ingress_tail {
  if (decoy_routing_metadata.doClone == TRUE) {
    apply(decoy_clone);
  }
}

// ----------------------------------------------------------------------------

action do_recirculate() {
  modify_field(decoy_routing_metadata.egress_used, TRUE);
  recirculate(recirculate_fields);
}
table decoy_routing_recirculate {
  actions {
    do_recirculate;
  }
  size: 0;
}

// ----------------------------------------------------------------------------

table debug_clone {
  reads {
    standard_metadata.instance_type: exact;
  }
  actions {
    _no_op;
  }
  size: 0;
}

// Logic for egress section.
control decoy_egress {
  apply(debug_clone);
  if (standard_metadata.instance_type != 0 and decoy_routing_metadata.isCopy == TRUE) {
    apply(decoy_routing_recirculate);
  }
}
