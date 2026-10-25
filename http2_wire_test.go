package impersonate

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// frame builds a raw HTTP/2 frame (9-byte header + payload) independently of
// golang.org/x/net/http2 so the tests check the bytes our code actually emits
// against a hand-rolled reference, not against the same library that wrote them.
func frame(typ, flags byte, streamID uint32, payload []byte) []byte {
	h := make([]byte, 9)
	h[0] = byte(len(payload) >> 16)
	h[1] = byte(len(payload) >> 8)
	h[2] = byte(len(payload))
	h[3] = typ
	h[4] = flags
	binary.BigEndian.PutUint32(h[5:], streamID)
	return append(h, payload...)
}

func settingsPayload(p Profile) []byte {
	var out []byte
	for _, s := range p.H2Settings {
		b := make([]byte, 6)
		binary.BigEndian.PutUint16(b, uint16(s.ID))
		binary.BigEndian.PutUint32(b[2:], s.Val)
		out = append(out, b...)
	}
	return out
}

// expectedConnPreamble is the exact byte stream newH2Conn must write before any
// request: client connection preface, then the browser's SETTINGS frame, then
// the connection-level WINDOW_UPDATE.
func expectedConnPreamble(p Profile) []byte {
	const settingsType, windowUpdateType = 0x4, 0x8
	out := []byte(h2preface)
	out = append(out, frame(settingsType, 0, 0, settingsPayload(p))...)
	if p.H2ConnWindow > 0 {
		inc := make([]byte, 4)
		binary.BigEndian.PutUint32(inc, p.H2ConnWindow)
		out = append(out, frame(windowUpdateType, 0, 0, inc)...)
	}
	return out
}

// TestH2ConnEmitsExactChromeBytes pins the Chrome connection preamble to a fully
// hand-written literal — the strongest "fixed expected bytes" check.
func TestH2ConnEmitsExactChromeBytes(t *testing.T) {
	want := []byte{
		// client connection preface
		'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', '.', '0',
		'\r', '\n', '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n',
		// SETTINGS frame: len=24, type=0x04, flags=0, stream=0
		0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x00, 0x01, 0x00, 0x00, // HEADER_TABLE_SIZE = 65536
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00, // ENABLE_PUSH = 0
		0x00, 0x04, 0x00, 0x60, 0x00, 0x00, // INITIAL_WINDOW_SIZE = 6291456
		0x00, 0x06, 0x00, 0x04, 0x00, 0x00, // MAX_HEADER_LIST_SIZE = 262144
		// WINDOW_UPDATE frame: len=4, type=0x08, flags=0, stream=0, inc=15663105
		0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0xef, 0x00, 0x01,
	}
	got := captureConnPreamble(t, Chrome)
	if !bytes.Equal(got, want) {
		t.Fatalf("chrome preamble bytes mismatch\n got: % x\nwant: % x", got, want)
	}
}

// TestH2ConnPreambleBytesPerProfile checks every profile's emitted preamble
// against an independently computed byte reference.
func TestH2ConnPreambleBytesPerProfile(t *testing.T) {
	for _, n := range []string{"chrome", "chrome_android", "firefox", "safari", "edge", "ios"} {
		p := Profiles[n]
		want := expectedConnPreamble(p)
		got := captureConnPreamble(t, p)
		if !bytes.Equal(got, want) {
			t.Fatalf("%s preamble bytes mismatch\n got: % x\nwant: % x", n, got, want)
		}
	}
}

// captureConnPreamble runs newH2Conn against an in-memory pipe and returns every
// byte it wrote (preface + SETTINGS + WINDOW_UPDATE).
func captureConnPreamble(t *testing.T, p Profile) []byte {
	t.Helper()
	cli, srv := net.Pipe()
	_ = cli.SetDeadline(time.Now().Add(5 * time.Second))
	_ = srv.SetDeadline(time.Now().Add(5 * time.Second))
	ch := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(srv)
		ch <- b
	}()
	c, err := newH2Conn(p, cli)
	if err != nil {
		t.Fatalf("newH2Conn(%s): %v", p.Name, err)
	}
	_ = c
	cli.Close() // unblock ReadAll with EOF once the preamble is written
	select {
	case b := <-ch:
		return b
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: timed out reading preamble", p.Name)
		return nil
	}
}

// TestH2WriteHeadersPseudoOrder verifies the HEADERS frame carries the four
// pseudo-headers in the profile's exact order, immediately followed by the
// regular headers in HeaderOrder — the "pseudo-header-order" field of the
// Akamai fingerprint and the header order Akamai also records.
func TestH2WriteHeadersPseudoOrder(t *testing.T) {
	letterToName := map[string]string{":method": "m", ":authority": "a", ":scheme": "s", ":path": "p"}

	for _, n := range []string{"chrome", "firefox", "safari", "edge", "ios"} {
		p := Profiles[n]
		cli, srv := net.Pipe()
		_ = cli.SetDeadline(time.Now().Add(5 * time.Second))
		_ = srv.SetDeadline(time.Now().Add(5 * time.Second))

		fieldsCh := make(chan []hpack.HeaderField, 1)
		go func() {
			pre := make([]byte, len(h2preface))
			if _, err := io.ReadFull(srv, pre); err != nil {
				fieldsCh <- nil
				return
			}
			fr := http2.NewFramer(io.Discard, srv)
			fr.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
			for {
				f, err := fr.ReadFrame()
				if err != nil {
					fieldsCh <- nil
					return
				}
				if mh, ok := f.(*http2.MetaHeadersFrame); ok {
					fieldsCh <- mh.Fields
					return
				}
			}
		}()

		c, err := newH2Conn(p, cli)
		if err != nil {
			t.Fatalf("%s: newH2Conn: %v", n, err)
		}
		req, _ := http.NewRequest("GET", "https://example.test/path?q=1", nil)
		// Apply the profile's default headers the way the real client does.
		for name, vals := range p.Headers {
			for _, v := range vals {
				req.Header.Add(name, v)
			}
		}
		if err := c.writeHeaders(1, req, true); err != nil {
			t.Fatalf("%s: writeHeaders: %v", n, err)
		}

		var fields []hpack.HeaderField
		select {
		case fields = <-fieldsCh:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: timed out reading HEADERS", n)
		}
		cli.Close()
		if fields == nil {
			t.Fatalf("%s: no HEADERS frame decoded", n)
		}

		// 1. The first four fields must be the pseudo-headers, in profile order.
		if len(fields) < 4 {
			t.Fatalf("%s: got %d header fields, want >= 4", n, len(fields))
		}
		var gotPseudo []string
		for i := 0; i < 4; i++ {
			gotPseudo = append(gotPseudo, letterToName[fields[i].Name])
			if fields[i].Name == "" || fields[i].Name[0] != ':' {
				t.Fatalf("%s: field %d is %q, expected a pseudo-header", n, i, fields[i].Name)
			}
		}
		for i, want := range p.H2PseudoOrder {
			if gotPseudo[i] != want {
				t.Fatalf("%s: pseudo-header order = %v, want %v", n, gotPseudo, p.H2PseudoOrder)
			}
		}

		// 2. No pseudo-header may appear after a regular header.
		seenRegular := false
		for _, f := range fields {
			isPseudo := len(f.Name) > 0 && f.Name[0] == ':'
			if isPseudo && seenRegular {
				t.Fatalf("%s: pseudo-header %q appeared after a regular header", n, f.Name)
			}
			if !isPseudo {
				seenRegular = true
			}
		}

		// 3. Regular headers must lead with the profile's HeaderOrder.
		var gotRegular []string
		for _, f := range fields {
			if len(f.Name) == 0 || f.Name[0] != ':' {
				gotRegular = append(gotRegular, f.Name)
			}
		}
		for i, want := range p.HeaderOrder {
			if i >= len(gotRegular) {
				t.Fatalf("%s: regular header %q (index %d) missing", n, want, i)
			}
			// writeHeaders lowercases names on the wire (HPACK convention).
			if gotRegular[i] != strings.ToLower(want) {
				t.Fatalf("%s: regular header[%d] = %q, want %q (order %v)", n, i, gotRegular[i], strings.ToLower(want), gotRegular)
			}
		}
	}
}
