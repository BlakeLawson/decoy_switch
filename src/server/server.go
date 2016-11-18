// Author: Blake Lawson (blawson@princeton.edu)
// Adviser: Jennifer Rexford

package server

import (
	"log"
	"net/http"
	"time"
)

// port is the TCP port that the server listens on.
const (
	port           string        = ":8080"
	defaultTimeout time.Duration = 5 // seconds
)

// Configure the server and server handlers. Takes filePath, which specifiies
// the file to serve.
func initServer(filePath string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		// The "/" pattern matches everything
		http.ServeFile(w, req, filePath)
	})

	server := http.Server{
		Addr:         port,
		Handler:      mux,
		ReadTimeout:  defaultTimeout * time.Second,
		WriteTimeout: defaultTimeout * time.Second,
	}

	return &server
}

// Start the server.
func Start(filePath string) {
	server := initServer(filePath)
	log.Fatal(server.ListenAndServe())
}
