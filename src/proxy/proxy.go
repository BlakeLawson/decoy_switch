// Author: Blake Lawson (blawson@princeton.edu)
// Adviser: Jennifer Rexford
//
// This proxy is based on a proxy written by Blake Lawson and Graham Turk

package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/net/html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Global constants
const (
	servErrorCode       = 500
	badReqCode          = 400
	defaultMaxObjSize   = 500 * 1024
	defaultMaxCacheSize = 10 * 1024 * 1024
	exitFailure         = 1
	chunkSize           = 512
	defaultHTTPPort     = ":80"
	tcpProtocol         = "tcp"
)

const notImpMsg = "<html><head>\r\b" +
	"<title>501 Not Implemented</title>\r\n" +
	"</head><body>\r\n<h1>Not Found</h1>\r\n" +
	"</body></html>\r\n"

const intrnErrMsg = "<html><head>\r\b" +
	"<title>500 Internal Error</title>\r\n" +
	"</head>/<body>\r\n<h1>Not Found</h1>\r\n" +
	"</body></html>\r\n"

// Command line parameters
var (
	listeningPort   uint
	dnsPrefetching  bool
	caching         bool
	cacheTimeout    uint
	maxCacheSize    uint
	maxObjSize      uint
	linkPrefetching bool
	maxConcurrency  uint
	outputFile      string
)

// Channel to synchronize number of prefetch threads
var semConc chan bool

// Cache for caching optimization
var cache *HTTPCache

// Stat variables
var (
	clientRequests  int // HTTP requests
	cacheHits       int // Cache Hits
	cacheMisses     int // Cache misses
	cacheEvictions  int // Cache evictions
	trafficSent     int // Bytes sent to clients
	volumeFromCache int // Bytes sent from the cache
	downloadVolume  int // Bytes downloaded from servers
)

// RW lock for the stat variables.
// You need to lock the stat variables when updating them.
var statLock sync.RWMutex

func saveStatistics() {
	f, err := os.Create(outputFile)
	if err != nil {
		log.Fatal("Error creating output file", outputFile)
	}
	start := time.Now()
	str := "#Time(s)\tclientRequests\tcacheHits\tcacheMisses\tcacheEvictions" +
		"\ttrafficSent\tvolumeFromCache\tdownloadVolume\ttrafficWastage\tcacheEfficiency"
	f.WriteString(str)
	for {
		var cacheEfficiency float64
		var trafficWastage int

		currentTime := time.Now().Sub(start)
		statLock.RLock()
		if trafficSent > 0 {
			cacheEfficiency = float64(volumeFromCache) / float64(trafficSent)
		} else {
			cacheEfficiency = 0.0
		}
		if downloadVolume > trafficSent {
			trafficWastage = downloadVolume - trafficSent
		} else {
			trafficWastage = 0
		}

		str := fmt.Sprintf("\n%d\t\t%d\t\t%d\t\t%d\t\t%d\t\t%d\t\t%d\t\t%d\t\t%d\t\t%f",
			int(currentTime.Seconds()), clientRequests,
			cacheHits, cacheMisses, cacheEvictions,
			trafficSent, volumeFromCache, downloadVolume,
			trafficWastage, cacheEfficiency)
		statLock.RUnlock()
		f.WriteString(str)
		f.Sync()
		time.Sleep(time.Second * 10)
	}
}

// Send the given byte array over a connection
func sendBytes(conn net.Conn, buf []byte) error {
	for b := 0; b < len(buf); {
		temp, err := conn.Write(buf[b:])
		if err != nil {
			return err
		}
		b += temp
	}
	return nil
}

// Given a connection, return the specified error response. Type may be set to
// "500" or "501".
func sendErrorResponse(conn net.Conn, statusCode string) {
	var body, statusLine string
	if statusCode == "500" {
		// Set variables
		statusLine = "HTTP/1.0 500 Internal Error\r\n"
		body = intrnErrMsg
	} else {
		// Set variables
		statusLine = "HTTP/1.0 501 Not Implemented\r\n"
		body = notImpMsg
	}

	// Send the response
	sendBytes(conn, []byte(statusLine))
	sendBytes(conn, []byte(body))
	sendBytes(conn, []byte("\r\n"))
}

// Given an io.Reader, read its contents into a buffer and return a pointer to
// the buffer.
func readAll(reader *bufio.Reader) (*[]byte, error) {
	b := make([]byte, chunkSize)
	i := 0
	for n, err := reader.Read(b); n > 0 || err != io.EOF; n, err = reader.Read(b[i:]) {
		if err != nil && err != io.EOF {
			return nil, err
		}

		// Resize b if necessary
		i += n
		if i >= len(b) {
			temp := b
			b = make([]byte, 2*len(temp))
			copy(b, temp)
		}
	}
	ret := b[:i]
	return &ret, nil
}

// Given a net.Request containing the desired http response, a byte array
// containing the body of the response, and a connection to a client, send the
// response to the client.
func forwardResponse(clientConn net.Conn, resp *http.Response,
	body *[]byte) error {
	// Send status line
	err := sendBytes(clientConn,
		[]byte(fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status)))
	if err != nil {
		return err
	}

	// Send the headers
	for k, v := range resp.Header {
		for i := 0; i < len(v); i++ {
			err = sendBytes(clientConn,
				[]byte(fmt.Sprintf("%s:%s\r\n", k, v[i])))
			if err != nil {
				return err
			}
		}
	}

	// Send empty line between headers and body
	err = sendBytes(clientConn, []byte("\r\n"))
	if err != nil {
		return err
	}

	// Send the body
	err = sendBytes(clientConn, *body)
	if err != nil {
		return err
	}

	return nil
}

// Given a http.Request, preform the request and return the resulting
// http.Response
func makeRequest(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, errors.New("makeRequest: cannot send nil request")
	}
	if req.Method != "GET" {
		return nil, errors.New("makeRequest: can only send GET requests")
	}

	// Connect to the server
	conn, err := net.Dial(tcpProtocol, req.URL.Host)
	if err != nil {
		return nil, err
	}

	// Ensure that there is some Path set
	if req.URL.Path == "" {
		req.URL.Path = "/"
	}

	// Send request line
	var uri string
	if req.URL.RawQuery == "" {
		uri = req.URL.Path
	} else {
		uri = fmt.Sprintf("%s?%s", req.URL.Path, req.URL.RawQuery)
	}
	err = sendBytes(conn, []byte(
		fmt.Sprintf("GET %s %s\r\n", uri, req.Proto)))
	if err != nil {
		return nil, err
	}

	// Send headers
	for k, v := range req.Header {
		for i := 0; i < len(v); i++ {
			err = sendBytes(conn, []byte(fmt.Sprintf("%s:%s\r\n", k, v[i])))
			if err != nil {
				return nil, err
			}
		}
	}

	// End header
	err = sendBytes(conn, []byte("\r\n"))
	if err != nil {
		return nil, err
	}

	// Do not need to send a body because GET requests do not have bodies

	// Read response
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Increment the semaphore-channel
func incrementChannel() {
	semConc <- true
}

// Given a link to fetch, fetch the link and if it returns content, add it to
// the cache.
func prefetch(addr *url.URL) {
	<-semConc                // Only execute if there are tokens in the channel
	defer incrementChannel() // Return a token to the channel on exit

	if idx := strings.Index(addr.Host, ":"); idx == -1 {
		addr.Host += defaultHTTPPort
	}

	h, b, err := cache.Get(addr.String())
	if err != nil {
		return
	}
	if h != nil && b != nil {
		// Cache hit
		statLock.Lock()
		cacheHits++
		statLock.Unlock()
		return
	}
	statLock.Lock()
	cacheMisses++
	statLock.Unlock()

	// Initialize the request
	req := &http.Request{
		Method:     "GET",
		URL:        addr,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header: map[string][]string{
			"Accept-Encoding": {"gzip"},
			"Connection":      {"close"},
			"Host":            {addr.Host},
		},
		Close: true,
		Host:  addr.Host,
	}

	// Make the request
	resp, err := makeRequest(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Only save if 200 response
	if resp.StatusCode != 200 {
		return
	}

	// Save response
	body, err := readAll(bufio.NewReader(resp.Body))
	if err != nil {
		return
	}

	// Update amount of data downloaded
	statLock.Lock()
	downloadVolume += len(*body)
	statLock.Unlock()

	// Add to cache
	cache.Insert(addr.String(), time.Now(), resp.Header, *body)
}

// Given an html Node, perform a DFS traversal of the tree, fetch every link,
// and add the response to the cache. The structure of the function comes from
// the code on slide 8 of the active measurement precept slides.
func doLinkPrefetching(base *url.URL, n *html.Node) {
	if n.Type == html.ElementNode && n.Data == "a" {
		for _, a := range n.Attr {
			if a.Key == "href" {
				// Parse url
				u, err := url.Parse(a.Val)
				if err != nil {
					break
				}
				if u.Host == "" {
					// In this case, the given href is relative to the base. If
					// it begins with a / then it is an absolute path from the
					// URL host. Otherwise, it is relative to the current path.
					newURL, err := url.Parse(base.String())
					if err != nil {
						break
					}
					if strings.HasPrefix(u.Path, "/") {
						newURL.Path = u.Path
					} else {
						newURL.Path += u.Path
					}

					u = newURL
				}
				// Don't fetch https links
				if !strings.Contains(a.Val, "https:") {
					go prefetch(u)
				}
				break
			}
		}
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		doLinkPrefetching(base, c)
	}
}

// Given an html Node, perform a DFS traversal of the tree and look up every
// a tag. The structure of this function comes from the code on slide 8 of the
// active measurement precept slides.
func doDNSPrefetching(n *html.Node) {
	if n.Type == html.ElementNode && n.Data == "a" {
		for _, a := range n.Attr {
			if a.Key == "href" {
				// Parse url
				u, err := url.Parse(a.Val)
				if err != nil {
					break
				}
				if u.Host != "" && !strings.Contains(a.Val, "https:") {
					net.LookupIP(u.Host)
				}
				break
			}
		}
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		doDNSPrefetching(c)
	}
}

// Read data send on the connection, and forward the request to the desired
// destination.
func handleRequest(conn net.Conn) {
	defer conn.Close()

	// Update number of client requests received
	statLock.Lock()
	clientRequests++
	statLock.Unlock()

	// Read and validate data from client
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		sendErrorResponse(conn, "500")
		return
	}
	defer req.Body.Close()

	// Only handle GET requests
	if req.Method != "GET" {
		sendErrorResponse(conn, "501")
		return
	}

	// Update request to ensure proper connection settings
	req.Header.Set("Connection", "close")
	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Close = true

	// Ensure host field
	if idx := strings.Index(req.URL.Host, ":"); idx == -1 {
		req.URL.Host += defaultHTTPPort
	}

	var body *[]byte
	var resp *http.Response
	var inCache = false
	if caching {
		headers, tempBody, _ := cache.Get(req.URL.String())

		if tempBody != nil {
			inCache = true
			body = &tempBody
			resp = &http.Response{
				Status:     "200 OK",
				StatusCode: 200,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header:     headers,
			}
		}
		if inCache {
			// Update number of cache hits
			statLock.Lock()
			cacheHits++
			statLock.Unlock()
		} else {
			// Update number of cache misses
			statLock.Lock()
			cacheMisses++
			statLock.Unlock()
		}
	}

	if !inCache {
		// Forward the request.
		resp, err = makeRequest(req)
		if err != nil {
			sendErrorResponse(conn, "500")
			return
		}
		defer resp.Body.Close()

		// Read response
		body, err = readAll(bufio.NewReader(resp.Body))
		if err != nil {
			sendErrorResponse(conn, "500")
			return
		}
	}

	// Send back to client
	err = forwardResponse(conn, resp, body)
	if err != nil {
		// Since sending failed, no point in sending additional error message
		// to the client.
		return
	}

	// Update Bytes sent/downloaded
	statLock.Lock()
	trafficSent += len(*body)
	if inCache {
		volumeFromCache += len(*body)
	}
	statLock.Unlock()

	// Perform any requested optimizations
	if resp.StatusCode == 200 {
		if caching && !inCache {
			cache.Insert(req.URL.String(), time.Now(), resp.Header, *body)
		}

		r := bufio.NewReader(bytes.NewReader(*body))
		if resp.Header.Get("Content-Encoding") == "gzip" {
			d, err := gzip.NewReader(r)
			if err != nil {
				return
			}
			r = bufio.NewReader(d)
		}
		if linkPrefetching || dnsPrefetching {
			root, err := html.Parse(r)
			if err != nil {
				return
			}

			if linkPrefetching {
				go doLinkPrefetching(req.URL, root)
			} else if dnsPrefetching {
				go doDNSPrefetching(root)
			}
		}
	}
}

func initFlags() {
	flag.UintVar(&listeningPort, "port", 8080, "Proxy listening port")
	flag.BoolVar(&dnsPrefetching, "dns", false, "Enable DNS prefetching")
	flag.BoolVar(&caching, "cache", false, "Enable object caching")
	flag.UintVar(&cacheTimeout, "timeout", 120, "Cache timeout in seconds")
	flag.UintVar(&maxCacheSize, "max_cache", defaultMaxCacheSize, "Maximum cache size")
	flag.UintVar(&maxObjSize, "max_obj", defaultMaxObjSize, "Maximum object size")
	flag.BoolVar(&linkPrefetching, "link", false, "Enable link prefetching")
	flag.UintVar(&maxConcurrency, "max_conc", 10, "Number of threads for link prefetching")
	flag.StringVar(&outputFile, "file", "proxy.log", "Output file name")
	flag.Parse()
}

// Start used to run the proxy.
func Start() {
	initFlags()
	if linkPrefetching {
		// Link prefetching uses the cache
		caching = true
	}

	go saveStatistics()

	// Initialize the cache
	var err error
	cache, err = CacheInit(cacheTimeout, maxCacheSize, maxObjSize)
	if caching && err != nil {
		return
	}

	// Initialize the thread-limiting channel. Used as a semaphore.
	semConc = make(chan bool, maxConcurrency)
	for i := uint(0); i < maxConcurrency; i++ {
		incrementChannel()
	}

	// Create basic server
	ln, err := net.Listen(tcpProtocol, fmt.Sprintf(":%d", listeningPort))
	if err != nil {
		return
	}

	// Respond to requests
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleRequest(conn)
	}
}
