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
 */

header_type decoy_routing_metadata_t {
  fields {
    done: 1;
    resumbit: 1;
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


#define CPU_MIRROR_SESSION_ID 250
#define CPU_PARSE_COVERT_REASON 0xab

field_list copy_to_cpu_fields {
  standard_metadata;
  cpu_metadata;
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
  modify_field(ipv4.totalLen, TCP_PACKET_LEN_SANS_PAYLOAD);
  truncate(TCP_PACKET_LEN_SANS_PAYLOAD);  // Discard the payload

  // TODO: Recirculate the packet in order to send SYN to covert
}
table close_connection {
  actions {
    do_close_connection;
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
  modify_field(cpu_metadata.reason, CPU_PARSE_COVERT_REASON);
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
