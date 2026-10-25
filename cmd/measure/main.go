// Command measure points each browser profile at a passive-fingerprint
// reflector and prints the REAL fingerprint the reflector observed on the wire:
// JA3/JA4 (TLS) and the Akamai HTTP/2 string (SETTINGS|WINDOW_UPDATE|PRIORITY|
// pseudo-header-order). Use it to verify, and regenerate, the parity table in
// the README — these are live measurements, not canned values.
//
// Usage:
//
//	go run ./cmd/measure                      # defaults to tls.peet.ws
//	go run ./cmd/measure -url https://fp.shshbshsnang.shop/api/all
//	REFLECTOR_URL=https://fp.shshbshsnang.shop/api/all go run ./cmd/measure
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	imp "github.com/North-web-dev/impersonate-http"
)

func main() {
	def := os.Getenv("REFLECTOR_URL")
	if def == "" {
		def = "https://tls.peet.ws/api/all"
	}
	url := flag.String("url", def, "fingerprint reflector returning tls{} and http2{} JSON")
	flag.Parse()

	profiles := map[string]imp.Profile{
		"chrome": imp.Chrome, "chrome_android": imp.ChromeAndroid, "firefox": imp.Firefox,
		"safari": imp.Safari, "edge": imp.Edge, "ios": imp.IOS,
	}
	out := map[string]any{"_reflector": *url}
	for name, p := range profiles {
		c := &http.Client{Transport: imp.NewTransport(p), Timeout: 15 * time.Second}
		r, err := c.Get(*url)
		if err != nil {
			out[name] = map[string]string{"error": err.Error()}
			continue
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		var m map[string]any
		json.Unmarshal(b, &m)
		fp := map[string]any{}
		if tls, ok := m["tls"].(map[string]any); ok {
			fp["ja3"] = tls["ja3"]
			fp["ja3_hash"] = tls["ja3_hash"]
			fp["ja4"] = tls["ja4"]
			fp["peetprint_hash"] = tls["peetprint_hash"]
		}
		if h2, ok := m["http2"].(map[string]any); ok {
			// tls.peet.ws exposes akamai_fingerprint; other reflectors may
			// use a different key, so fall back to any "akamai"-ish field.
			if v, ok := h2["akamai_fingerprint"]; ok {
				fp["akamai_h2"] = v
			}
			if v, ok := h2["akamai_fingerprint_hash"]; ok {
				fp["akamai_h2_hash"] = v
			}
		}
		// Some reflectors (e.g. fp.shshbshsnang.shop) surface the Akamai string
		// at the top level as akamai_h2 rather than nested under http2{}.
		if _, ok := fp["akamai_h2"]; !ok {
			if v, ok := m["akamai_h2"]; ok {
				fp["akamai_h2"] = v
			}
		}
		fp["user_agent"] = p.Headers.Get("User-Agent")
		out[name] = fp
	}
	j, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(j))
}
