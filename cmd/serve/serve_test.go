package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func TestDecompress(t *testing.T) {
	const want = "<html>hello</html>"
	cases := map[string]func() io.Reader{
		"identity": func() io.Reader { return strings.NewReader(want) },
		"gzip": func() io.Reader {
			var b bytes.Buffer
			w := gzip.NewWriter(&b)
			w.Write([]byte(want))
			w.Close()
			return &b
		},
		"br": func() io.Reader {
			var b bytes.Buffer
			w := brotli.NewWriter(&b)
			w.Write([]byte(want))
			w.Close()
			return &b
		},
		"zstd": func() io.Reader {
			var b bytes.Buffer
			w, _ := zstd.NewWriter(&b)
			w.Write([]byte(want))
			w.Close()
			return &b
		},
	}
	for enc, mk := range cases {
		r, err := decompress(mk(), enc)
		if err != nil {
			t.Fatalf("%s: decompress: %v", enc, err)
		}
		got, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("%s: read: %v", enc, err)
		}
		if string(got) != want {
			t.Errorf("%s: got %q, want %q", enc, got, want)
		}
	}
	if _, err := decompress(strings.NewReader(""), "lz4"); err == nil {
		t.Error("expected error for unsupported encoding")
	}
}

func TestReadBodyTruncates(t *testing.T) {
	resp := &http.Response{Body: io.NopCloser(strings.NewReader("0123456789")), Header: http.Header{}}
	body, truncated, err := readBody(resp, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated || body != "0123" {
		t.Errorf("got %q truncated=%v, want %q truncated=true", body, truncated, "0123")
	}
}

func TestAuthenticate(t *testing.T) {
	hit := false
	s := &server{keys: singleKeystore("secret")}
	h := s.authenticate(func(http.ResponseWriter, *http.Request) { hit = true })

	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/fetch", nil))
	if rec.Code != http.StatusUnauthorized || hit {
		t.Fatalf("no key: got %d hit=%v, want 401", rec.Code, hit)
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/fetch", nil)
	req.Header.Set("Authorization", "Bearer secret")
	h(rec, req)
	if !hit {
		t.Fatalf("valid key rejected: got %d", rec.Code)
	}
}

func TestFetchValidation(t *testing.T) {
	s := &server{}
	for _, body := range []string{`{}`, `{"url":"https://x","profile":"nope"}`} {
		rec := httptest.NewRecorder()
		s.handleFetch(rec, httptest.NewRequest(http.MethodPost, "/fetch", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s: got %d, want 400", body, rec.Code)
		}
		var out map[string]string
		json.Unmarshal(rec.Body.Bytes(), &out)
		if out["error"] == "" {
			t.Errorf("body %s: missing error field", body)
		}
	}
}
