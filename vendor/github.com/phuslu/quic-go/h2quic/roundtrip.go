package h2quic

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	quic "github.com/phuslu/quic-go"

	"golang.org/x/net/lex/httplex"
)

type roundTripCloser interface {
	http.RoundTripper
	io.Closer
}

// RoundTripper implements the http.RoundTripper interface
type RoundTripper struct {
	mutex sync.Mutex

	// DisableCompression, if true, prevents the Transport from
	// requesting compression with an "Accept-Encoding: gzip"
	// request header when the Request contains no existing
	// Accept-Encoding value. If the Transport requests gzip on
	// its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body. However, if the user
	// explicitly requested gzip it is not automatically
	// uncompressed.
	DisableCompression bool

	// ResponseHeaderTimeout, if non-zero, specifies the amount of
	// time to wait for a server's response headers after fully
	// writing the request (including its body, if any). This
	// time does not include the time to read the response body.
	ResponseHeaderTimeout time.Duration

	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client. If nil, the default configuration is used.
	TLSClientConfig *tls.Config

	// GetClientKey specifies a function to return a clients key string for hostname
	GetClientKey func(hostname string) string

	// DialAddr specifies an optional function for quic.DailAddr.
	// If this value is nil, it will default to net.DialAddr for the client.
	DialAddr func(hostname string, tlsConfig *tls.Config, config *quic.Config) (quic.Session, error)

	// QuicConfig is the quic.Config used for dialing new connections.
	// If nil, reasonable default values will be used.
	QuicConfig *quic.Config

	// KeepAliveTimeout is specifies an optional duration for quic.Session life time.
	// If this value is zero, it will never close
	KeepAliveTimeout time.Duration

	// IdleConnTimeout is specifies an optional duration for quic.Session idle time.
	IdleConnTimeout time.Duration

	clients map[string]roundTripCloser
}

// RoundTripOpt are options for the Transport.RoundTripOpt method.
type RoundTripOpt struct {
	// OnlyCachedConn controls whether the RoundTripper may
	// create a new QUIC connection. If set true and
	// no cached connection is available, RoundTrip
	// will return ErrNoCachedConn.
	OnlyCachedConn bool
}

var _ roundTripCloser = &RoundTripper{}

// ErrNoCachedConn is returned when RoundTripper.OnlyCachedConn is set
var ErrNoCachedConn = errors.New("h2quic: no cached connection was available")

// RoundTripOpt is like RoundTrip, but takes options.
func (r *RoundTripper) RoundTripOpt(req *http.Request, opt RoundTripOpt) (*http.Response, error) {
	if req.URL == nil {
		closeRequestBody(req)
		return nil, errors.New("quic: nil Request.URL")
	}
	if req.URL.Host == "" {
		closeRequestBody(req)
		return nil, errors.New("quic: no Host in request URL")
	}
	if req.Header == nil {
		closeRequestBody(req)
		return nil, errors.New("quic: nil Request.Header")
	}

	if req.URL.Scheme == "https" {
		for k, vv := range req.Header {
			if !httplex.ValidHeaderFieldName(k) {
				return nil, fmt.Errorf("quic: invalid http header field name %q", k)
			}
			for _, v := range vv {
				if !httplex.ValidHeaderFieldValue(v) {
					return nil, fmt.Errorf("quic: invalid http header field value %q for key %v", v, k)
				}
			}
		}
	} else {
		closeRequestBody(req)
		return nil, fmt.Errorf("quic: unsupported protocol scheme: %s", req.URL.Scheme)
	}

	if req.Method != "" && !validMethod(req.Method) {
		closeRequestBody(req)
		return nil, fmt.Errorf("quic: invalid method %q", req.Method)
	}

	hostname := authorityAddr("https", hostnameFromRequest(req))
	cl, err := r.getClient(hostname, opt.OnlyCachedConn)
	if err != nil {
		return nil, err
	}

	resp, err := cl.RoundTrip(req)

	if err == nil {
		return resp, err
	}

	if _, ok := err.(*net.OpError); ok {
		return resp, err
	}

	nerr := &net.OpError{
		Op:  "read",
		Net: "udp",
		Err: err,
	}

	session := cl.(*client).session
	if session != nil {
		nerr.Addr = session.RemoteAddr()
		nerr.Source = session.LocalAddr()
	}

	return resp, nerr
}

// RoundTrip does a round trip.
func (r *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return r.RoundTripOpt(req, RoundTripOpt{})
}

func (r *RoundTripper) getClient(hostname string, onlyCached bool) (http.RoundTripper, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if r.clients == nil {
		r.clients = make(map[string]roundTripCloser)
	}

	var hostnameKey string
	if r.GetClientKey != nil {
		hostnameKey = r.GetClientKey(hostname)
	} else {
		hostnameKey = hostname
	}

	c, ok := r.clients[hostnameKey]
	if ok && r.KeepAliveTimeout != 0 && time.Since(c.(*client).createdAt) > r.KeepAliveTimeout {
		ok = false
	}
	if ok && r.IdleConnTimeout != 0 && time.Since(c.(*client).accessAt) > r.IdleConnTimeout {
		ok = false
	}
	if !ok {
		if onlyCached {
			return nil, ErrNoCachedConn
		}
		c = newClient(hostname, r.TLSClientConfig, &roundTripperOpts{DisableCompression: r.DisableCompression, ResponseHeaderTimeout: r.ResponseHeaderTimeout, DialAddr: r.DialAddr}, r.QuicConfig)
		runtime.SetFinalizer(c, func(r *client) { r.Close() })
		r.clients[hostnameKey] = c
	}
	return c, nil
}

// Close closes the QUIC connections that this RoundTripper has used
func (r *RoundTripper) Close() error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	for _, client := range r.clients {
		if err := client.Close(); err != nil {
			return err
		}
	}
	r.clients = nil
	return nil
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}

func validMethod(method string) bool {
	/*
				     Method         = "OPTIONS"                ; Section 9.2
		   		                    | "GET"                    ; Section 9.3
		   		                    | "HEAD"                   ; Section 9.4
		   		                    | "POST"                   ; Section 9.5
		   		                    | "PUT"                    ; Section 9.6
		   		                    | "DELETE"                 ; Section 9.7
		   		                    | "TRACE"                  ; Section 9.8
		   		                    | "CONNECT"                ; Section 9.9
		   		                    | extension-method
		   		   extension-method = token
		   		     token          = 1*<any CHAR except CTLs or separators>
	*/
	return len(method) > 0 && strings.IndexFunc(method, isNotToken) == -1
}

// copied from net/http/http.go
func isNotToken(r rune) bool {
	return !httplex.IsTokenRune(r)
}

// CloseConnections remove clients according the net.Addr
func (r *RoundTripper) CloseConnection(f func(raddr net.Addr) bool) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if f == nil {
		r.Close()
		return
	}

	keys := make([]string, 0)
	for k, c := range r.clients {
		session := c.(*client).session
		if session != nil && f(session.RemoteAddr()) {
			go session.Close(errors.New("h2quic: CloseConnections called"))
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		delete(r.clients, k)
	}
}
