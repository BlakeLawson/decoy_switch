// Author: Blake Lawson (blawson@princeton.edu)
// Adviser: Jennifer Rexford

package client

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
)

// Start runs the client.
func Start(decoyDst, covertDst string) {
	conn, err := net.Dial("tcp", decoyDst)
	if err != nil {
		log.Fatalf("Connection to proxy failed: %s\n", err)
	}
	defer conn.Close()

	conn.Write([]byte(fmt.Sprintf("GET http://%s/ HTTP/1.1\r\n\r\n", covertDst)))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		log.Fatalf("Failed to get response: %s\n", err)
	}
	defer resp.Body.Close()

	log.Printf("Request to covert destination returned %s\n", resp.Status)

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %s\n", err)
	}

	fmt.Println(string(body[:]))
}
