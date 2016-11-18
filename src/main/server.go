// Blake Lawson (blawson@princeton.edu)
// Adviser: Jennifer Rexford

package main

import (
	"flag"
	"fmt"
	"server"
)

func main() {
	fname := flag.String("f", "", "Path to the file the server should serve.")
	flag.Parse()
	if *fname == "" {
		fmt.Println("Must provide file to serve with -f option.")
		return
	}

	server.Start(*fname)
}
