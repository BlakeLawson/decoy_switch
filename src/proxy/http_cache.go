// Blake Lawson (blawson) Graham Turk (gturk)
// This file is a thread-safe HTTP cache that performs all necessary
// functions for COS 461 assignment 4.

package proxy

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HTTPCache used to interact with this module.
type HTTPCache struct {
	currSize   uint                    // The current size of the cache in bytes
	maxSize    uint                    // The maximum allowable size of the cache
	maxObjSize uint                    // The maximum size of any object in the cache
	cache      map[string]*CacheObject // Actual mapping to cached objects
	timeout    time.Duration           // Number of seconds to store objects in cache
	lock       *sync.Mutex             // Lock to ensure atomic operations

	// linked list. Used for LRU replacement.
	lruList *CacheObject // Pointer to the first element in doubly-
}

// CacheObject is a wrapper for HTTP objects in the cache
type CacheObject struct {
	lastUpdated time.Time    // Time at which object was last updated
	srcAddr     string       // The URL from which the object arrived
	headers     http.Header  // The objects original headers
	obj         *[]byte      // The actual object
	next        *CacheObject // Pointers for implementing linked list
	prev        *CacheObject
}

// Add the given CacheObject to the back of the queue in the given HTTPCache
func (c *HTTPCache) enqueue(o *CacheObject) error {
	if o == nil {
		return errors.New("cache: attempt to insert nil object")
	}

	// Update root node
	if c.lruList == nil {
		o.next = o
		o.prev = o
		c.lruList = o
		return nil
	}

	o.next = c.lruList
	o.prev = c.lruList.prev
	c.lruList.prev.next = o
	c.lruList.prev = o
	return nil
}

// Dequeue from the back of the queue in the given HTTPCache
func (c *HTTPCache) dequeue() (*CacheObject, error) {
	if c.lruList == nil {
		return nil, errors.New("cache: attempt to dequeue from empty queue")
	}

	temp := c.lruList
	c.lruList.prev.next = c.lruList.next
	c.lruList = c.lruList.next
	c.lruList.prev = temp.prev
	temp.prev = nil
	temp.next = nil

	// Handle case where deqeuing last element.
	if c.lruList == temp {
		c.lruList = nil
	}
	return temp, nil
}

// Remove the given CacheObject from the queue in the HTTPCache
func (c *HTTPCache) remove(o *CacheObject) error {
	if c.lruList == nil {
		return errors.New("cache: attempt to remove from empty queue")
	}
	if o == nil {
		return errors.New("cache: attempt to remove nil object")
	}

	// Maintain proper root node
	if c.lruList == o {
		c.lruList = o.next
	}

	o.next.prev = o.prev
	o.prev.next = o.next
	o.next = nil
	o.prev = nil

	// If c.lruList still equals o then o must have been the only thing in the
	// queue.
	if c.lruList == o {
		c.lruList = nil
	}
	return nil
}

// Update the cache object if possible. Return true if it is okay to keep the
// object in the cache. Return false otherwise.
func (elem *CacheObject) update() error {
	req, err := http.NewRequest("GET", elem.srcAddr, nil)
	if err != nil {
		return err
	}

	req.Header.Add("If-Modified-Since",
		elem.lastUpdated.Format("Mon, 02 Jan 2006 15:04:05 GMT"))

	// Send the request
	resp, err := makeRequest(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 304 {
		// cache object does not have to be updated
		elem.lastUpdated = time.Now().UTC()
		return nil
	} else if resp.StatusCode == 200 {
		// update the cache object
		elem.lastUpdated = time.Now().UTC()

		// Save the new object
		bufSize := 1000
		newObj := make([]byte, bufSize)
		i := 0
		for {
			n, err := resp.Body.Read(newObj[i:])
			if err == io.EOF && n == 0 {
				// End of body
				newObj = newObj[:i]
				break
			}
			if err != nil {
				return err
			}

			i += n

			// double the buffer size if necessary
			if i >= len(newObj) {
				temp := newObj
				bufSize <<= 1
				newObj = make([]byte, bufSize)
				copy(newObj, temp)
			}
		}

		// Update the CacheObject
		elem.obj = &newObj
		elem.headers = resp.Header
		return nil
	}

	// If the code gets to this point, behavior undefined
	return fmt.Errorf("cache: Unexpected response status for %s (status: %d)",
		elem.srcAddr, resp.StatusCode)
}

// CacheInit used to create an HTTPCache.
func CacheInit(timeout, maxSize, maxObjSize uint) (*HTTPCache, error) {
	// Make duration in a roundabout way because I couldn't figure it out
	d, err := time.ParseDuration(fmt.Sprintf("%ds", timeout))
	if err != nil {
		return nil, err
	}
	return &HTTPCache{
		timeout:    d,
		currSize:   0,
		maxSize:    maxSize,
		maxObjSize: maxObjSize,
		cache:      make(map[string]*CacheObject),
		lock:       new(sync.Mutex),
		lruList:    nil,
	}, nil
}

// Get returns a pointer to the []byte object of it is in the cache. Returns
// nil otherwise
func (c *HTTPCache) Get(ref string) (http.Header, []byte, error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	// Get the CacheObject if it exists
	elem, ok := c.cache[ref]
	if !ok {
		return nil, nil, nil
	}

	// Check timeout
	if elem.lastUpdated.Add(c.timeout).Before(time.Now().UTC()) {
		c.currSize -= uint(len(*elem.obj))
		err := elem.update()
		if err != nil {
			return nil, nil, err
		}

		// Ensure new object is valid
		cachable := !strings.Contains(elem.headers.Get("Cache-Control"),
			"no-cache")
		if uint(len(*elem.obj)) >= c.maxObjSize || !cachable {
			// Here, it is not 100% clear whether the return value should be an
			// error. We have chosen to return no error and return the object
			// that was just fetched but not add the object to the cache. This
			// should not effect client performance until the client attempts
			// to fetch in the future, but from the client's perspective this
			// does not matter because it is as if the object was evicted from
			// the cache for some other reason.
			err = c.remove(elem)
			if err != nil {
				return nil, nil, err
			}
			delete(c.cache, elem.srcAddr)
			return elem.headers, *elem.obj, nil
		}
		c.currSize += uint(len(*elem.obj))
	}

	// Update position in LRU queue
	err := c.remove(elem)
	if err != nil {
		return nil, nil, err
	}
	err = c.enqueue(elem)
	if err != nil {
		return nil, nil, err
	}

	// Return the object
	return elem.headers, *elem.obj, nil
}

// Remove an element from the cache. NOTE: the calling function is responsible
// for taking care of locking/mutual exclusion.
func (c *HTTPCache) replacementPolicy() error {
	// Current replacement policy is LRU
	if c.lruList == nil {
		return errors.New("cache: Attempt to remove from empty cache")
	}
	elem, err := c.dequeue()
	if err != nil {
		return err
	}
	delete(c.cache, elem.srcAddr)
	c.currSize -= uint(len(*elem.obj))

	// Update number of cache evictions
	statLock.Lock()
	cacheEvictions++
	statLock.Unlock()
	return nil
}

// Insert adds the given []byte object to the cache. NOTE: ref should be the
// source URL for the given object.
func (c *HTTPCache) Insert(ref string, timeRetreived time.Time,
	headers http.Header, o []byte) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	// Check whether the object is already in the cache
	elem, ok := c.cache[ref]
	if ok {
		return fmt.Errorf(
			"cache: Given object name (%s) already present in cache",
			ref)
	}

	// If object is too big, return success anyway. The clients behavior should
	// not be effected.
	if uint(len(o)) >= c.maxObjSize || uint(len(o)) >= c.maxSize {
		return nil
	}

	// If object not supposed to be cached, do not cache and return success
	if strings.Contains(headers.Get("Cache-Control"), "no-cache") {
		return nil
	}

	// Check whether object needs to be removed from the cache
	for uint(len(o))+c.currSize >= c.maxSize {
		err := c.replacementPolicy()
		if err != nil {
			return err
		}
	}

	// Add object to the cache
	elem = &CacheObject{
		lastUpdated: timeRetreived,
		srcAddr:     ref,
		headers:     headers,
		obj:         &o,
		next:        nil,
		prev:        nil,
	}
	c.cache[ref] = elem
	err := c.enqueue(elem)
	if err != nil {
		delete(c.cache, elem.srcAddr)
		return err
	}
	c.currSize += uint(len(o))
	return nil
}
