package interceptor

import (
	"bufio"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"io"
	"log"
	"net/http"
)

// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct {
	requestParser bool
}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	requestParser  bool
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:           net,
		transport:     transport,
		r:             tcpreader.NewReaderStream(),
		requestParser: h.requestParser,
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) processResponse(buf *bufio.Reader) (*http.Response, error) {
	resp, err := http.ReadResponse(buf, nil)

	return resp, err
}

func (h *httpStream) processRequest(buf *bufio.Reader) (*http.Request, error) {
	req, err := http.ReadRequest(buf)

	return req, err
}

func (h *httpStream) run() {
	var err error
	var req *http.Request
	var resp *http.Response

	buf := bufio.NewReader(&h.r)
	for {
		if h.requestParser {
			req, err = h.processRequest(buf)
		} else {
			resp, err = h.processResponse(buf)
		}
		/*
			if err == io.EOF {
				return
			}
			if req != nil {
				req.Body.Close()
				log.Println(req.Method, req.Host, req.URL, "\n")
			} else if resp != nil {
				resp.Body.Close()
				log.Println(resp.Status, "\n")
			}*/

		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			//log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {
			if h.requestParser {
				bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
				req.Body.Close()
				log.Println(h.net, ":", h.transport)
				log.Println(req.Method, req.Host, req.URL)
				log.Println("Body size:", bodyBytes, "bytes\n")
			} else {
				bodyBytes := tcpreader.DiscardBytesToEOF(resp.Body)
				resp.Body.Close()
				log.Println(h.net, ":", h.transport)
				log.Println(resp.Status)
				log.Println("Body size:", bodyBytes, "bytes\n")
			}

		}
	}
}
