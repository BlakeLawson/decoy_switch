// Author: Blake Lawson (blawson@princeton.edu)
// Adviser: Jennifer Rexford

package client

import (
  "log"
  "math/rand"
  "net"

  "third-party/tcpHeaders"
)

const proxyIP string = "10.0.0.2"
const proxyPort uint16 = 8888

// getPort Generates random port number.
func getPort() uint16 {
  // TODO: Do this better
  for {
    p := uint16(rand.Uint32())
    if p > 1024 {
      return p
    }
  }
}

// getSeq() makes the sequence number hash that indicates decoy routing
// desired.
func getSeq(srcIP string, srcPort uint16, dstIp string, dstPort uint16) uint32 {
  return rand.Uint32()
}

// makeSynPacket generates the initial TCP SYN packet using specially chosen
// sequence number to request decoy routing.
func makeSynPacket(srcIP string, srcPort uint16, dstIP string, dstPort uint16) []byte {
  packet := tcpHeaders.TCPHeader{
    Source: srcPort,
    Destination: dstPort,
    SeqNum: getSeq(srcIP, srcPort, dstIP, dstPort),
    AckNum: 0,
    DataOffset: 5, // No extra data
    Reserved: 0,
    ECN: 0,
    Ctrl: 2, // 000010: SYN set
    Window: 0xAAAA, // TODO: Investigate good value for this. 
    Checksum: 0, // Set by kernel
    Urgent: 0,
    Options: []tcpHeaders.TCPOption{},
  }

  data := packet.Marshal()
  packet.Checksum = tcpHeaders.Csum(data, tcpHeaders.To4byte(srcIP), tcpHeaders.To4byte(dstIP))

  return packet.Marshal()
}

// makeSynAckPacket generate the SYN-ACK to complete the TCP handshake.
// func makeSynAckPacket() []byte {
// 
// }

// doHandshake Performs the TCP three-way handshake over the given connection.
func doHandshake(conn net.Conn) error {
  // Send the initial SYN.

  log.Println("about to make syn packet")
  syn := makeSynPacket(conn.LocalAddr().String(), getPort(),
                       conn.RemoteAddr().String(), proxyPort)
  _, err := conn.Write(syn)
  if err != nil {
    return err
  }
  log.Println("syn packet sent")

  // Wait for ACK.


  // Send the SYN-ACK.
//   synAck := makeSynAckPacket()
//   _, err = conn.Write(synAck)
//   return err

  return nil
}

func Start() {
  conn, err := net.Dial("ip4:tcp", proxyIP)
  if err != nil {
    log.Fatalf("Dial: %s\n", err)
  }
  defer conn.Close()

  err = doHandshake(conn)
  if err != nil {
    log.Fatalf("Handshake: %s\n", err)
  }
}
