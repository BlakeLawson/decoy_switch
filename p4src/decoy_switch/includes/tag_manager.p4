/*
 * Author: Blake Lawson (blawson@princeton.edu)
 * Adviser: Jennifer Rexford
 *
 * This module is intended to track the state of TCP handshake between a tagged
 * client and the decoy destination. When this module recognizes that the TCP
 * handshake is complete and it is time to hijack the connection and start
 * doing decoy switching, this module sets the metadata field
 * "tagging_metadata.ready_for_routing" to 1.
 *
 * A program that uses this module should invoke it by calling control
 * "tagging" and then checking tagging_metadata.ready_for_routing to
 * determine the return value.
 */

/* Module-specific metadata */
header_type tagging_metadata_t {
  fields {
    ready_for_routing: 1;
    syn_seen: 1;
    ack_seen: 1;
    tag: 32;
    hash1: 16;
    hash2: 16;
    res1: 1;
    res2: 1;
    toCPU: 1;
  }
}
metadata tagging_metadata_t tagging_metadata;


/* Framework for bloom filters */

field_list tagging_bloom_fields {
  ipv4.srcAddr;
  ipv4.dstAddr;
  ipv4.protocol;
  tcp.srcPort;
  tcp.dstPort;
}

field_list_calculation tagging_bloom_hash1 {
  input {
    tagging_bloom_fields;
  }
  algorithm: csum16;
  output_width: 16;
}

field_list_calculation tagging_bloom_hash2 {
  input {
    tagging_bloom_fields;
  }
  algorithm: crc16;
  output_width: 16;
}


/* Define the registers used for the bloom filters. Use multiple registers for
   each bloom filter to minimize collisions. */

#define BLOOM_LENGTH 1024

register tagging_syn_counter1 {
  width: 1;
  instance_count: BLOOM_LENGTH;
}

register tagging_syn_counter2 {
  width: 1;
  instance_count: BLOOM_LENGTH;
}

register tagging_ack_counter1 {
  width: 1;
  instance_count: BLOOM_LENGTH;
}

register tagging_ack_counter2 {
  width: 1;
  instance_count: BLOOM_LENGTH;
}


/* Match-action tables for the module */
// ----------------------------------------------------------------------------


action do_tagging_init() {
  // Most of these are unnecessary because metadata is set to 0 by default...
  modify_field(tagging_metadata.ready_for_routing, FALSE);
  modify_field(tagging_metadata.syn_seen, FALSE);
  modify_field(tagging_metadata.ack_seen, FALSE);
  modify_field(tagging_metadata.res1, 0);
  modify_field(tagging_metadata.res2, 0);
  modify_field_with_hash_based_offset(tagging_metadata.hash1, 0, tagging_bloom_hash1, BLOOM_LENGTH);
  modify_field_with_hash_based_offset(tagging_metadata.hash2, 0, tagging_bloom_hash2, BLOOM_LENGTH);
}
table tagging_init {
  actions {
    do_tagging_init;
  }
  size: 0;
}


action do_calculate_tag() {
  // 0x100000000 == 2^32
  modify_field_with_hash_based_offset(tagging_metadata.tag, 0, tag_hash, 0x100000000);
}
table calculate_tag {
  actions {
    do_calculate_tag;
  }
  size: 0;
}

action do_insert_syn() {
  // Add SYN packet to bloom filter
  register_write(tagging_syn_counter1, tagging_metadata.hash1, 1);
  register_write(tagging_syn_counter2, tagging_metadata.hash2, 1);

  // Also send packet to CPU to get TCP options
  clone_ingress_pkt_to_egress(CPU_MIRROR_SESSION_ID, copy_to_cpu_fields);
  modify_field(cpu_metadata.reason, CPU_REASON_GET_OPTIONS);
}
table insert_syn {
  actions {
    do_insert_syn;
  }
  size: 0;
}


action do_insert_ack() {
  register_write(tagging_ack_counter1, tagging_metadata.hash1, 1);
  register_write(tagging_ack_counter2, tagging_metadata.hash2, 1);
}
table insert_ack {
  actions {
    do_insert_ack;
  }
  size: 0;
}


action do_read_syn() {
  // Read the values in the bloom filter
  register_read(tagging_metadata.res1, tagging_syn_counter1, tagging_metadata.hash1);
  register_read(tagging_metadata.res2, tagging_syn_counter2, tagging_metadata.hash2);

  // Store result
  modify_field(tagging_metadata.syn_seen, tagging_metadata.res1 & tagging_metadata.res2);

  // Clear temp variables
  modify_field(tagging_metadata.res1, 0);
  modify_field(tagging_metadata.res2, 0);
}
table read_syn {
  actions {
    do_read_syn;
  }
  size: 0;
}


action do_read_ack() {
  // Read the values in the bloom filter
  register_read(tagging_metadata.res1, tagging_ack_counter1, tagging_metadata.hash1);
  register_read(tagging_metadata.res2, tagging_ack_counter2, tagging_metadata.hash2);

  // Store result
  modify_field(tagging_metadata.ack_seen, tagging_metadata.res1 & tagging_metadata.res2);

  // Clear temp variables
  modify_field(tagging_metadata.res1, 0);
  modify_field(tagging_metadata.res2, 0);
}
table read_ack {
  actions {
    do_read_ack;
  }
  size: 0;
}


action do_set_ready_for_routing() {
  modify_field(tagging_metadata.ready_for_routing, TRUE);
}
table set_ready_for_routing {
  actions {
    do_set_ready_for_routing;
  }
  size: 0;
}


// Main for this module 
control tagging {
  apply(tagging_init);
  if (tcp.flags == TCP_FLAG_SYN) {
    tagging_handle_syn();
  } else {
    tagging_handle_nonsyn();
  }
}

// Handle initial syn packet
control tagging_handle_syn {
  // Determine whether this flow is tagged, and if so, mark that we've seen
  // seen the syn packet.
  apply(calculate_tag);
  if (tagging_metadata.tag == tcp.seqNo) {
    apply(insert_syn);
  }
}

// Handle packets that are not SYNs
control tagging_handle_nonsyn {
  // Not a syn packet, so check whether there has been a tagged syn for this
  // flow. If not, there's nothing more to do. If it is, see if it's in the
  // ack table. If it's in both, we can do decoy switching on the packet.
  apply(read_syn);
  if (tagging_metadata.syn_seen == TRUE) {
    apply(read_ack);
    if (tagging_metadata.ack_seen == TRUE) {
      apply(set_ready_for_routing);
    } else {
      if (tcp.flags == TCP_FLAG_ACK) {
        // Probably the ACK to a SYN-ACK concluding the TCP handshake.
        apply(insert_ack);
      }
    }
  }
}
