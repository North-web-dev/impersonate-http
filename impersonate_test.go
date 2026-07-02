package impersonate

import (
	"net/http"
	"testing"
)

type capture struct{ req *http.Request }

func (c *capture) RoundTrip(r *http.Request) (*http.Response, error) {
	c.req = r
	return &http.Response{StatusCode: 200, Body: http.NoBody, Header: http.Header{}}, nil
}

func TestProfilesPresent(t *testing.T) {
	for _, n := range []string{"chrome", "firefox", "safari", "edge", "ios"} {
		p, ok := Profiles[n]
		if !ok || p.Headers.Get("User-Agent") == "" || p.ClientHello.Str() == "" {
			t.Fatalf("profile %q incomplete", n)
		}
	}
}

func TestHeaderInjection(t *testing.T) {
	cap := &capture{}
	rt := headerRT{profile: Chrome, next: cap}
	req, _ := http.NewRequest("GET", "https://x.test", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if cap.req.Header.Get("User-Agent") != Chrome.Headers.Get("User-Agent") {
		t.Fatal("profile UA not injected")
	}
}

func TestHeaderInjectionNoOverwrite(t *testing.T) {
	cap := &capture{}
	rt := headerRT{profile: Chrome, next: cap}
	req, _ := http.NewRequest("GET", "https://x.test", nil)
	req.Header.Set("User-Agent", "custom/1.0")
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if cap.req.Header.Get("User-Agent") != "custom/1.0" {
		t.Fatal("caller UA was overwritten")
	}
}

func TestNewByNameUnknown(t *testing.T) {
	if _, ok := NewByName("nope"); ok {
		t.Fatal("unknown profile should return false")
	}
}

func TestH2FingerprintSet(t *testing.T) {
	for _, n := range []string{"chrome", "firefox", "safari", "edge", "ios"} {
		p := Profiles[n]
		if len(p.H2Settings) == 0 || p.H2ConnWindow == 0 || len(p.H2PseudoOrder) != 4 {
			t.Fatalf("profile %q missing HTTP/2 fingerprint", n)
		}
	}
}
