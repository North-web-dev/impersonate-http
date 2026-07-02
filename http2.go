package impersonate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const h2preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// h2Transport speaks HTTP/2 over uTLS connections while emitting the browser's
// exact SETTINGS / WINDOW_UPDATE / pseudo-header fingerprint. One connection per
// host, requests serialized.
type h2Transport struct {
	p    Profile
	dial func(ctx context.Context) (net.Conn, error)

	mu   sync.Mutex
	conn *h2Conn
}

func (t *h2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		c, err := t.getConn(req.Context())
		if err != nil {
			return nil, err
		}
		resp, err := c.roundTrip(req)
		if err != nil {
			t.mu.Lock()
			if t.conn == c {
				t.conn = nil
			}
			t.mu.Unlock()
			c.close()
			if attempt == 0 {
				continue
			}
			return nil, err
		}
		return resp, nil
	}
	return nil, errors.New("impersonate: http2 round trip failed")
}

func (t *h2Transport) getConn(ctx context.Context) (*h2Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil && !t.conn.dead() {
		return t.conn, nil
	}
	nc, err := t.dial(ctx)
	if err != nil {
		return nil, err
	}
	c, err := newH2Conn(t.p, nc)
	if err != nil {
		nc.Close()
		return nil, err
	}
	t.conn = c
	return c, nil
}

type h2Conn struct {
	p    Profile
	conn net.Conn
	fr   *http2.Framer
	henc *hpack.Encoder
	hbuf *bytes.Buffer

	mu       sync.Mutex
	nextID   uint32
	sendWin  int64
	maxFrame uint32
	broken   bool
}

func newH2Conn(p Profile, conn net.Conn) (*h2Conn, error) {
	c := &h2Conn{p: p, conn: conn, nextID: 1, sendWin: 65535, maxFrame: 16384}
	c.hbuf = new(bytes.Buffer)
	c.henc = hpack.NewEncoder(c.hbuf)
	c.fr = http2.NewFramer(conn, conn)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
	c.fr.MaxHeaderListSize = 262144

	if _, err := io.WriteString(conn, h2preface); err != nil {
		return nil, err
	}
	if err := c.fr.WriteSettings(p.H2Settings...); err != nil {
		return nil, err
	}
	if p.H2ConnWindow > 0 {
		if err := c.fr.WriteWindowUpdate(0, p.H2ConnWindow); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *h2Conn) dead() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.broken }
func (c *h2Conn) close()     { c.mu.Lock(); c.broken = true; c.mu.Unlock(); c.conn.Close() }

func (c *h2Conn) roundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	id := c.nextID
	c.nextID += 2

	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		body = b
	}

	if err := c.writeHeaders(id, req, len(body) == 0); err != nil {
		c.broken = true
		return nil, err
	}
	if len(body) > 0 {
		if err := c.writeBody(id, body); err != nil {
			c.broken = true
			return nil, err
		}
	}
	return c.readResponse(id, req)
}

func pseudoValue(letter string, req *http.Request) (string, string) {
	switch letter {
	case "m":
		return ":method", req.Method
	case "a":
		return ":authority", req.Host
	case "s":
		return ":scheme", "https"
	case "p":
		path := req.URL.RequestURI()
		if path == "" {
			path = "/"
		}
		return ":path", path
	}
	return "", ""
}

func (c *h2Conn) writeHeaders(id uint32, req *http.Request, endStream bool) error {
	if req.Host == "" {
		req.Host = req.URL.Host
	}
	c.hbuf.Reset()
	order := c.p.H2PseudoOrder
	if len(order) == 0 {
		order = []string{"m", "a", "s", "p"}
	}
	for _, l := range order {
		n, v := pseudoValue(l, req)
		c.henc.WriteField(hpack.HeaderField{Name: n, Value: v})
	}

	written := map[string]bool{}
	emit := func(k string) {
		lk := strings.ToLower(k)
		if written[lk] || isSkippedH2Header(lk) {
			return
		}
		vals := req.Header.Values(k)
		if len(vals) == 0 {
			return
		}
		written[lk] = true
		for _, v := range vals {
			c.henc.WriteField(hpack.HeaderField{Name: lk, Value: v})
		}
	}
	for _, k := range c.p.HeaderOrder {
		emit(k)
	}
	for k := range req.Header {
		emit(k)
	}

	return c.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      id,
		BlockFragment: c.hbuf.Bytes(),
		EndStream:     endStream,
		EndHeaders:    true,
	})
}

func (c *h2Conn) writeBody(id uint32, body []byte) error {
	for len(body) > 0 {
		n := len(body)
		if int64(n) > c.sendWin {
			n = int(c.sendWin)
		}
		if n > int(c.maxFrame) {
			n = int(c.maxFrame)
		}
		if n <= 0 {
			if err := c.pump(); err != nil {
				return err
			}
			continue
		}
		end := n == len(body)
		if err := c.fr.WriteData(id, end, body[:n]); err != nil {
			return err
		}
		c.sendWin -= int64(n)
		body = body[n:]
	}
	return nil
}

func (c *h2Conn) pump() error {
	f, err := c.fr.ReadFrame()
	if err != nil {
		return err
	}
	switch fr := f.(type) {
	case *http2.SettingsFrame:
		if !fr.IsAck() {
			c.applySettings(fr)
			c.fr.WriteSettingsAck()
		}
	case *http2.WindowUpdateFrame:
		c.sendWin += int64(fr.Increment)
	case *http2.PingFrame:
		if !fr.IsAck() {
			c.fr.WritePing(true, fr.Data)
		}
	}
	return nil
}

func (c *h2Conn) applySettings(fr *http2.SettingsFrame) {
	fr.ForeachSetting(func(s http2.Setting) error {
		switch s.ID {
		case http2.SettingInitialWindowSize:
			c.sendWin = int64(s.Val)
		case http2.SettingMaxFrameSize:
			c.maxFrame = s.Val
		}
		return nil
	})
}

func (c *h2Conn) readResponse(id uint32, req *http.Request) (*http.Response, error) {
	var (
		hdr     http.Header
		status  int
		bodyBuf bytes.Buffer
	)
	for {
		f, err := c.fr.ReadFrame()
		if err != nil {
			c.broken = true
			return nil, err
		}
		switch fr := f.(type) {
		case *http2.MetaHeadersFrame:
			if fr.StreamID != id {
				continue
			}
			hdr = http.Header{}
			for _, hf := range fr.Fields {
				if hf.Name == ":status" {
					status, _ = strconv.Atoi(hf.Value)
				} else if !strings.HasPrefix(hf.Name, ":") {
					hdr.Add(hf.Name, hf.Value)
				}
			}
			if fr.StreamEnded() {
				return c.buildResp(status, hdr, &bodyBuf, req), nil
			}
		case *http2.DataFrame:
			if fr.StreamID != id {
				continue
			}
			bodyBuf.Write(fr.Data())
			if n := len(fr.Data()); n > 0 {
				c.fr.WriteWindowUpdate(0, uint32(n))
				c.fr.WriteWindowUpdate(id, uint32(n))
			}
			if fr.StreamEnded() {
				return c.buildResp(status, hdr, &bodyBuf, req), nil
			}
		case *http2.RSTStreamFrame:
			if fr.StreamID == id {
				c.broken = true
				return nil, fmt.Errorf("impersonate: stream reset (%v)", fr.ErrCode)
			}
		case *http2.GoAwayFrame:
			c.broken = true // stop reusing; our stream may still be answered
			if id > fr.LastStreamID {
				return nil, fmt.Errorf("impersonate: GOAWAY, stream not processed (%v)", fr.ErrCode)
			}
		case *http2.SettingsFrame:
			if !fr.IsAck() {
				c.applySettings(fr)
				c.fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !fr.IsAck() {
				c.fr.WritePing(true, fr.Data)
			}
		case *http2.WindowUpdateFrame:
			c.sendWin += int64(fr.Increment)
		}
	}
}

func (c *h2Conn) buildResp(status int, hdr http.Header, body *bytes.Buffer, req *http.Request) *http.Response {
	if hdr == nil {
		hdr = http.Header{}
	}
	return &http.Response{
		StatusCode:    status,
		Status:        strconv.Itoa(status) + " " + http.StatusText(status),
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        hdr,
		Body:          io.NopCloser(bytes.NewReader(body.Bytes())),
		ContentLength: int64(body.Len()),
		Request:       req,
	}
}

func isSkippedH2Header(lower string) bool {
	switch lower {
	case "host", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade":
		return true
	}
	return false
}
