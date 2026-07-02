package impersonate

import (
	"net/http"
	"time"
)

// headerRT injects a profile's default headers into every request (without
// overwriting anything the caller set) before handing off to the uTLS
// transport.
type headerRT struct {
	profile Profile
	next    http.RoundTripper
}

func (h headerRT) RoundTrip(req *http.Request) (*http.Response, error) {
	for name, vals := range h.profile.Headers {
		if req.Header.Get(name) == "" {
			for _, v := range vals {
				req.Header.Add(name, v)
			}
		}
	}
	return h.next.RoundTrip(req)
}

// NewTransport returns a RoundTripper with the profile's TLS + headers.
func NewTransport(p Profile) http.RoundTripper {
	return headerRT{profile: p, next: newRoundTripper(p)}
}

// New returns an http.Client that impersonates the given browser profile.
func New(p Profile) *http.Client {
	return &http.Client{
		Transport: NewTransport(p),
		Timeout:   30 * time.Second,
	}
}

// NewByName looks a profile up by name (chrome/firefox/safari/edge/ios).
func NewByName(name string) (*http.Client, bool) {
	p, ok := Profiles[name]
	if !ok {
		return nil, false
	}
	return New(p), true
}
