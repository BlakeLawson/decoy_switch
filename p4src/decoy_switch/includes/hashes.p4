/*
 * Author: Blake Lawson (blawson@princeton.edu)
 * Adviser: Jennifer Rexford
 *
 * Hash functions
 */

/* Fields for clone to CPU */
field_list copy_to_cpu_fields {
  standard_metadata;
  cpu_metadata;
}

/* ipv4 checksum */

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
  verify ipv4_checksum if (valid(ipv4));
  update ipv4_checksum if (valid(ipv4));
}

/* TCP Checksum */

field_list tcp_checksum_list {
  ipv4.srcAddr;
  ipv4.dstAddr;
  8'0;
  ipv4.protocol;
  tcp_metadata.tcpLength;
  tcp.srcPort;
  tcp.dstPort;
  tcp.seqNo;
  tcp.ackNo;
  tcp.dataOffset;
  tcp.res;
  tcp.flags;
  tcp.window;
  tcp.urgentPtr;
  payload;
}

field_list_calculation tcp_checksum {
  input {
    tcp_checksum_list;
  }
  algorithm: csum16;
  output_width: 16;
}

calculated_field tcp.checksum {
  verify tcp_checksum if(valid(tcp));
  update tcp_checksum if(valid(tcp));
}

/* Tag hash */

// TODO: Make this more legit. Ideally include some key on disk in the hash.
field_list tag_fields {
  ipv4.srcAddr;
  ipv4.dstAddr;
  ipv4.protocol;
  tcp.srcPort;
  tcp.dstPort;
  tcp.window;
}

field_list_calculation tag_hash {
  input {
    tag_fields;
  }
  algorithm : crc32;
  output_width : 32;
}
