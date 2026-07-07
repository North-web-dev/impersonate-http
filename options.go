package impersonate

import (
	"context"
	"net"
	"time"
)

// DialFunc establishes the raw TCP connection the browser TLS handshake runs
// over. Override it (e.g. with WithProxy) to route through a proxy.
type DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

type config struct {
	dial    DialFunc
	timeout time.Duration
}

func defaults() config {
	return config{dial: (&net.Dialer{}).DialContext, timeout: 30 * time.Second}
}

func (c config) apply(opts []Option) config {
	for _, o := range opts {
		o(&c)
	}
	return c
}

// Option customizes a Client or Transport.
type Option func(*config)

// WithDialer routes the underlying TCP connection through dial.
func WithDialer(dial DialFunc) Option {
	return func(c *config) {
		if dial != nil {
			c.dial = dial
		}
	}
}

// WithTimeout sets the client timeout. It affects New; NewTransport ignores it.
func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

// WithProxy routes connections through a socks5:// or http(s):// proxy. An
// unparseable URL surfaces as an error on the first request rather than a
// panic; use ProxyDialer directly if you want the error up front.
func WithProxy(rawurl string) Option {
	dial, err := ProxyDialer(rawurl)
	return func(c *config) {
		if err != nil {
			c.dial = func(context.Context, string, string) (net.Conn, error) { return nil, err }
			return
		}
		c.dial = dial
	}
}
