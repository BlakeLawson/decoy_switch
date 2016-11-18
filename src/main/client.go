// Blake Lawson (blawson@princeton.edu)
// Adviser: Jennifer Rexford

package main

import (
	"client"
	"flag"
	"fmt"
)

func main() {
	covertDst := flag.String("covert", "", "IP address and port of the covert destination.")
	decoyDst := flag.String("decoy", "", "IP address and port of the decoy destination.")
	flag.Parse()
	if *covertDst == "" {
		fmt.Println("Must provide address for covert destination with -covert option.")
		return
	}
	if *decoyDst == "" {
		fmt.Println("Must provide address for decoy destination with -decoy option.")
		return
	}

	client.Start(*decoyDst, *covertDst)
}
