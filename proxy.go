package impersonate

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"

	xproxy "golang.org/x/net/proxy"
)

// ProxyDialer returns a DialFunc that tunnels TCP connections through the proxy
// at rawurl. Supported schemes: socks5, socks5h, http, https.
func ProxyDialer(rawurl string) (DialFunc, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil, fmt.Errorf("parse proxy url: %w", err)
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		var auth *xproxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &xproxy.Auth{User: u.User.Username(), Password: pw}
		}
		d, err := xproxy.SOCKS5("tcp", u.Host, auth, xproxy.Direct)
		if err != nil {
			return nil, err
		}
		cd, ok := d.(xproxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("socks5 dialer does not support contexts")
		}
		return cd.DialContext, nil
	case "http", "https":
		return httpConnectDialer(u), nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
}

func httpConnectDialer(pu *url.URL) DialFunc {
	proxyAddr := pu.Host
	if pu.Port() == "" {
		port := "80"
		if pu.Scheme == "https" {
			port = "443"
		}
		proxyAddr = net.JoinHostPort(pu.Hostname(), port)
	}

	var authHeader string
	if pu.User != nil {
		pw, _ := pu.User.Password()
		authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(pu.User.Username()+":"+pw))
	}

	var base net.Dialer
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		conn, err := base.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, err
		}
		if pu.Scheme == "https" {
			tconn := tls.Client(conn, &tls.Config{ServerName: pu.Hostname()})
			if err := tconn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, fmt.Errorf("proxy tls handshake: %w", err)
			}
			conn = tconn
		}

		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: make(http.Header),
		}
		if authHeader != "" {
			req.Header.Set("Proxy-Authorization", authHeader)
		}
		if err := req.Write(conn); err != nil {
			conn.Close()
			return nil, err
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			conn.Close()
			return nil, err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			conn.Close()
			return nil, fmt.Errorf("proxy CONNECT %s: %s", addr, resp.Status)
		}
		return conn, nil
	}
}
