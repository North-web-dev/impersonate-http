package impersonate

import (
	"context"
	"net"
)

// DialTLSContext dials addr and performs the profile's browser-exact TLS
// handshake (JA3/JA4 identical to the browser), returning the established
// connection. Plug it into a WebSocket client to get browser-fingerprinted
// wss:// connections:
//
//	// coder/websocket:
//	websocket.Dial(ctx, "wss://host/path", &websocket.DialOptions{
//	    HTTPClient: &http.Client{Transport: impersonate.NewTransport(impersonate.Chrome)},
//	})
//
//	// gorilla/websocket:
//	d := websocket.Dialer{NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
//	    return impersonate.Chrome.DialTLSContext(ctx, network, addr)
//	}}
func (p Profile) DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return newRoundTripper(p, nil).dialTLS(ctx, addr)
}

// Dial is DialTLSContext with a background context.
func (p Profile) Dial(network, addr string) (net.Conn, error) {
	return p.DialTLSContext(context.Background(), network, addr)
}
