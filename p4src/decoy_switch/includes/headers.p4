/*
 * Author: Blake Lawson (blawson@princeton.edu)
 * Adviser: Jennifer Rexford
 *
 * Initial code from https://github.com/p4lang/tutorials/blob/master/
 * SIGCOMM_2016/heavy_hitter/p4src/includes/headers.p4
 */

header_type ethernet_t {
  fields {
    dstAddr : 48;
    srcAddr : 48;
    etherType : 16;
  }
}

header_type arp_t {
  fields {
    senderhdw : 16;
    protoSpace : 16;
    hdwAddrLen : 8;
    ProtoAddrLen : 8;
    opCode : 16;

    /* Hardcode length for MAC and ipv4 */
    senderHdwAddr : 48;
    senderProtoAddr : 32;
    tgtHdwAddr : 48;
    tgtProtoAddr : 32;
  }
}

header_type ipv4_t {
  fields {
    version : 4;
    ihl : 4;
    diffserv : 8;
    totalLen : 16;
    identification : 16;
    flags : 3;
    fragOffset : 13;
    ttl : 8;
    protocol : 8;
    hdrChecksum : 16;
    srcAddr : 32;
    dstAddr: 32;
  }
}

header_type tcp_t {
  fields {
    srcPort : 16;
    dstPort : 16;
    seqNo : 32;
    ackNo : 32;
    dataOffset : 4;
    res : 4;
    flags : 8;
    window : 16;
    checksum : 16;
    urgentPtr : 16;
  }
}

header_type cpu_header_t {
  fields {
    preamble: 64;
    reason: 8;
  }
}
