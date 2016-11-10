// Author: Blake Lawson (blawson@princeton.edu)
// Adviser: Jennifer Rexford

package client

import (
  "bytes"
  "encoding/binary"
  "hash/crc32"
  "log"
  "math/rand"
  "net"

  "third-party/tcpHeaders"
)

const proxyIP string = "10.0.0.2"
const proxyPort uint16 = 8888

const decoyDst string = "10.0.0.3"
const decoyPort uint16 = 80

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
func getSeq(srcIp string,
            srcPort uint16,
            dstIp string,
            dstPort uint16,
            window uint16) uint32 {
  // Convert to byte array
  var byteBuffer bytes.Buffer

  srcIpByte := tcpHeaders.To4byte(srcIp)
  dstIpByte := tcpHeaders.To4byte(dstIp)
  byteBuffer.Write(srcIpByte[:])
  byteBuffer.Write(dstIpByte[:])

  vals := []uint16{
    srcPort,
    dstPort,
    window,
  }

  for i := 0; i < len(vals); i++ {
    b := make([]byte, 8)
    n := binary.PutUvarint(b, uint64(vals[i]))
    byteBuffer.Write(b[:n])
  }

  return crc32.Checksum(byteBuffer.Bytes(), crc32.MakeTable(crc32.IEEE))
}

// makeSynPacket generates the initial TCP SYN packet using specially chosen
// sequence number to request decoy routing.
func makeSynPacket(srcIP string, srcPort uint16, dstIP string, dstPort uint16) []byte {
  var windowSize uint16 = 0xAAAA
  packet := tcpHeaders.TCPHeader{
    Source: srcPort,
    Destination: dstPort,
    SeqNum: getSeq(srcIP, srcPort, dstIP, dstPort, windowSize),
    AckNum: 0,
    DataOffset: 5, // No extra data
    Reserved: 0,
    ECN: 0,
    Ctrl: tcpHeaders.SYN,
    Window: windowSize, // TODO: Investigate good value for this. 
    Checksum: 0, // Set below
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
                       conn.RemoteAddr().String(), decoyPort)
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
  conn, err := net.Dial("ip4:tcp", decoyDst)
  if err != nil {
    log.Fatalf("Dial: %s\n", err)
  }
  defer conn.Close()

  err = doHandshake(conn)
  if err != nil {
    log.Fatalf("Handshake: %s\n", err)
  }

  // conn, err := net.Dial("tcp", "10.0.0.3:80")
  // if err != nil {
  //   log.Fatalf("Dial: %s\n", err)
  // }
  // conn.Close()
}
