package impersonate

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// roundTripper dials every connection with a uTLS ClientHello matching the
// profile, then dispatches to an HTTP/2 or HTTP/1.1 transport based on the
// ALPN the server negotiated. Per-host transports are cached so connection
// pooling and keep-alive work normally.
type roundTripper struct {
	profile Profile
	dialer  *net.Dialer

	mu         sync.Mutex
	transports map[string]http.RoundTripper
}

func newRoundTripper(p Profile) *roundTripper {
	return &roundTripper{
		profile:    p,
		dialer:     &net.Dialer{},
		transports: map[string]http.RoundTripper{},
	}
}

func (rt *roundTripper) dialTLS(ctx context.Context, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host, addr = addr, net.JoinHostPort(addr, "443")
	}
	raw, err := rt.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(raw, &utls.Config{ServerName: host}, rt.profile.ClientHello)
	if err := uconn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return uconn, nil
}

func (rt *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	addr := canonicalAddr(req.URL.Hostname(), req.URL.Port(), req.URL.Scheme)

	rt.mu.Lock()
	t, ok := rt.transports[addr]
	rt.mu.Unlock()
	if !ok {
		var err error
		if t, err = rt.buildTransport(req.Context(), addr); err != nil {
			return nil, err
		}
		rt.mu.Lock()
		rt.transports[addr] = t
		rt.mu.Unlock()
	}
	return t.RoundTrip(req)
}

func (rt *roundTripper) buildTransport(ctx context.Context, addr string) (http.RoundTripper, error) {
	conn, err := rt.dialTLS(ctx, addr)
	if err != nil {
		return nil, err
	}
	alpn := ""
	if u, ok := conn.(*utls.UConn); ok {
		alpn = u.ConnectionState().NegotiatedProtocol
	}
	conn.Close()

	dial := func(ctx context.Context, network, a string) (net.Conn, error) {
		return rt.dialTLS(ctx, a)
	}

	if alpn == http2.NextProtoTLS {
		return &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, a string, _ *tls.Config) (net.Conn, error) {
				return dial(ctx, network, a)
			},
		}, nil
	}
	return &http.Transport{DialTLSContext: dial, ForceAttemptHTTP2: false}, nil
}

func canonicalAddr(host, port, scheme string) string {
	if port == "" {
		if scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	return net.JoinHostPort(host, port)
}
