// Command serve exposes impersonate-http as an HTTP fetch API: POST a URL and a
// browser profile, get back the response fetched with that browser's exact
// TLS/HTTP2 fingerprint. This is the hosted-service front-end of the library.
package main

import (
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/North-web-dev/impersonate-http"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	apiKey := flag.String("key", "", "single unlimited API key; empty disables auth (use -keys for plans)")
	keysFile := flag.String("keys", "", "path to a JSON keys file ([{key,name,rps,burst,daily}]); overrides -key")
	timeout := flag.Duration("timeout", 30*time.Second, "default per-request timeout")
	maxBody := flag.Int64("max-body", 5<<20, "max response body bytes returned")
	flag.Parse()

	s := &server{timeout: *timeout, maxBody: *maxBody}
	switch {
	case *keysFile != "":
		ks, err := loadKeystore(*keysFile)
		if err != nil {
			log.Fatalf("load keys: %v", err)
		}
		s.keys = ks
	case *apiKey != "":
		s.keys = singleKeystore(*apiKey)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })
	mux.HandleFunc("GET /profiles", s.handleProfiles)
	mux.HandleFunc("POST /fetch", s.authenticate(s.handleFetch))
	mux.HandleFunc("GET /usage", s.authenticate(s.handleUsage))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("impersonate serve on %s (auth=%v)", *addr, s.keys != nil)
	log.Fatal(srv.ListenAndServe())
}

type server struct {
	keys    *keystore
	timeout time.Duration
	maxBody int64
}

type ctxKey struct{}

// authenticate resolves the API key and stashes its state in the context.
// Metering is charged by the handler (only /fetch), so /usage stays free.
// With no keystore configured every endpoint is open.
func (s *server) authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.keys == nil {
			next(w, r)
			return
		}
		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		state, ok := s.keys.lookup(key)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "invalid or missing API key")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, state)))
	}
}

func (s *server) handleUsage(w http.ResponseWriter, r *http.Request) {
	state, ok := r.Context().Value(ctxKey{}).(*keyState)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"auth": false})
		return
	}
	writeJSON(w, http.StatusOK, state.usage())
}

func (s *server) handleProfiles(w http.ResponseWriter, _ *http.Request) {
	names := make([]string, 0, len(impersonate.Profiles))
	for name := range impersonate.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	writeJSON(w, http.StatusOK, map[string]any{"profiles": names})
}

type fetchRequest struct {
	URL             string            `json:"url"`
	Profile         string            `json:"profile"`
	Method          string            `json:"method"`
	Headers         map[string]string `json:"headers"`
	Body            string            `json:"body"`
	Proxy           string            `json:"proxy"`
	TimeoutMS       int               `json:"timeout_ms"`
	FollowRedirects *bool             `json:"follow_redirects"`
}

type fetchResponse struct {
	Status    int         `json:"status"`
	FinalURL  string      `json:"final_url"`
	Headers   http.Header `json:"headers"`
	Body      string      `json:"body"`
	Truncated bool        `json:"truncated,omitempty"`
	ElapsedMS int64       `json:"elapsed_ms"`
}

func (s *server) handleFetch(w http.ResponseWriter, r *http.Request) {
	if state, ok := r.Context().Value(ctxKey{}).(*keyState); ok {
		if admitted, reason := state.admit(); !admitted {
			writeErr(w, http.StatusTooManyRequests, reason)
			return
		}
	}

	var req fetchRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if req.URL == "" {
		writeErr(w, http.StatusBadRequest, "url is required")
		return
	}
	profile := req.Profile
	if profile == "" {
		profile = "chrome"
	}
	if _, ok := impersonate.Profiles[profile]; !ok {
		writeErr(w, http.StatusBadRequest, "unknown profile: "+profile)
		return
	}

	timeout := s.timeout
	if req.TimeoutMS > 0 {
		timeout = time.Duration(req.TimeoutMS) * time.Millisecond
	}
	opts := []impersonate.Option{impersonate.WithTimeout(timeout)}
	if req.Proxy != "" {
		opts = append(opts, impersonate.WithProxy(req.Proxy))
	}
	client, _ := impersonate.NewByName(profile, opts...)
	if req.FollowRedirects != nil && !*req.FollowRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}

	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}
	hreq, err := http.NewRequestWithContext(ctx, method, req.URL, body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad request: "+err.Error())
		return
	}
	for k, v := range req.Headers {
		hreq.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(hreq)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "fetch failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	text, truncated, err := readBody(resp, s.maxBody)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "read body failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, fetchResponse{
		Status:    resp.StatusCode,
		FinalURL:  resp.Request.URL.String(),
		Headers:   resp.Header,
		Body:      text,
		Truncated: truncated,
		ElapsedMS: time.Since(start).Milliseconds(),
	})
}

// readBody decompresses the response per Content-Encoding and returns at most
// max bytes, flagging truncation.
func readBody(resp *http.Response, max int64) (string, bool, error) {
	r, err := decompress(resp.Body, resp.Header.Get("Content-Encoding"))
	if err != nil {
		return "", false, err
	}
	if c, ok := r.(io.Closer); ok && c != resp.Body {
		defer c.Close()
	}
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return "", false, err
	}
	if int64(len(data)) > max {
		return string(data[:max]), true, nil
	}
	return string(data), false, nil
}

func decompress(r io.Reader, encoding string) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return r, nil
	case "gzip":
		return gzip.NewReader(r)
	case "deflate":
		return zlib.NewReader(r)
	case "br":
		return brotli.NewReader(r), nil
	case "zstd":
		zr, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		return zr.IOReadCloser(), nil
	default:
		return nil, fmt.Errorf("unsupported content-encoding %q", encoding)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil && !errors.Is(err, http.ErrHandlerTimeout) {
		log.Printf("encode response: %v", err)
	}
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
