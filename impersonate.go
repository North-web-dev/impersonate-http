package impersonate

import (
	"net/http"
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
func NewTransport(p Profile, opts ...Option) http.RoundTripper {
	cfg := defaults().apply(opts)
	return headerRT{profile: p, next: newRoundTripper(p, cfg.dial)}
}

// New returns an http.Client that impersonates the given browser profile.
func New(p Profile, opts ...Option) *http.Client {
	cfg := defaults().apply(opts)
	return &http.Client{
		Transport: headerRT{profile: p, next: newRoundTripper(p, cfg.dial)},
		Timeout:   cfg.timeout,
	}
}

// NewByName looks a profile up by name (chrome/firefox/safari/edge/ios).
func NewByName(name string, opts ...Option) (*http.Client, bool) {
	p, ok := Profiles[name]
	if !ok {
		return nil, false
	}
	return New(p, opts...), true
}
