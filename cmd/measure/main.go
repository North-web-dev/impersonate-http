package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	imp "github.com/North-web-dev/impersonate-http"
)

func main() {
	profiles := map[string]imp.Profile{
		"chrome": imp.Chrome, "firefox": imp.Firefox, "safari": imp.Safari,
		"edge": imp.Edge, "ios": imp.IOS,
	}
	out := map[string]any{}
	for name, p := range profiles {
		c := &http.Client{Transport: imp.NewTransport(p), Timeout: 15 * time.Second}
		r, err := c.Get("https://tls.peet.ws/api/all")
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
			fp["akamai_h2"] = h2["akamai_fingerprint"]
			fp["akamai_h2_hash"] = h2["akamai_fingerprint_hash"]
		}
		fp["user_agent"] = p.Headers.Get("User-Agent")
		out[name] = fp
	}
	j, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(j))
}
