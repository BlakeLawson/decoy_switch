// Author: Blake Lawson (blawson@princeton.edu)
// Adviser: Jennifer Rexford

package main

import (
  "log"
  "net"
)

// port is the TCP port that the server listens on.
const port string = ":80"

// handleRequest serves client requests.
func handleRequest(conn net.Conn) {
  defer conn.Close()

  log.Printf("request from %s\n", conn.RemoteAddr().String())
}

// main starts the proxy.
func main() {
  l, err := net.Listen("tcp", port)
  if err != nil {
    log.Fatalln(err)
  }
  defer l.Close()
  log.Printf("Listening on %s\n", l.Addr().String())

  // Accept connections on l.
  for {
    conn, err := l.Accept()
    if err != nil {
      log.Println(err)
      continue
    }
    go handleRequest(conn)
  }
}
