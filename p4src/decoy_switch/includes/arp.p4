/*
 * Author: Blake Lawson (blawson@princeton.edu)
 * Adviser: Jennifer Rexford
 *
 * Assumes included along with proper headers, defines, and parsing.
 */

// Convert ARP query into response
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
  size: 128;
}

control arp_ingress {
  if (arp.opCode == ARP_REQUEST) {
    apply(arp_resp_lookup);
  }
}
