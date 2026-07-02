// Package impersonate provides an http.Client whose TLS handshake is
// byte-identical to a real browser's, so requests survive JA3/JA4
// fingerprinting (Cloudflare, Akamai, etc.) without a headless browser.
package impersonate

import (
	"net/http"

	utls "github.com/refraction-networking/utls"
)

// Profile describes a browser to imitate: the exact TLS ClientHello it sends
// plus the default request headers (and their order) it would attach.
type Profile struct {
	Name        string
	ClientHello utls.ClientHelloID
	Headers     http.Header
	HeaderOrder []string
}

func hdr(pairs ...string) (http.Header, []string) {
	h := http.Header{}
	order := make([]string, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		h.Set(pairs[i], pairs[i+1])
		order = append(order, pairs[i])
	}
	return h, order
}

func chrome() Profile {
	h, o := hdr(
		"sec-ch-ua", `"Not(A:Brand";v="99", "Google Chrome";v="131", "Chromium";v="131"`,
		"sec-ch-ua-mobile", "?0",
		"sec-ch-ua-platform", `"Windows"`,
		"Upgrade-Insecure-Requests", "1",
		"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Sec-Fetch-Site", "none",
		"Sec-Fetch-Mode", "navigate",
		"Sec-Fetch-User", "?1",
		"Sec-Fetch-Dest", "document",
		"Accept-Encoding", "gzip, deflate, br, zstd",
		"Accept-Language", "en-US,en;q=0.9",
	)
	return Profile{"chrome", utls.HelloChrome_Auto, h, o}
}

func firefox() Profile {
	h, o := hdr(
		"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
		"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
		"Accept-Language", "en-US,en;q=0.5",
		"Accept-Encoding", "gzip, deflate, br, zstd",
		"Upgrade-Insecure-Requests", "1",
		"Sec-Fetch-Dest", "document",
		"Sec-Fetch-Mode", "navigate",
		"Sec-Fetch-Site", "none",
		"Sec-Fetch-User", "?1",
	)
	return Profile{"firefox", utls.HelloFirefox_Auto, h, o}
}

func safari() Profile {
	h, o := hdr(
		"User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
		"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language", "en-US,en;q=0.9",
		"Accept-Encoding", "gzip, deflate, br",
	)
	return Profile{"safari", utls.HelloSafari_Auto, h, o}
}

func edge() Profile {
	h, o := hdr(
		"sec-ch-ua", `"Microsoft Edge";v="131", "Chromium";v="131", "Not_A Brand";v="24"`,
		"sec-ch-ua-mobile", "?0",
		"sec-ch-ua-platform", `"Windows"`,
		"Upgrade-Insecure-Requests", "1",
		"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
		"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Accept-Encoding", "gzip, deflate, br, zstd",
		"Accept-Language", "en-US,en;q=0.9",
	)
	return Profile{"edge", utls.HelloEdge_Auto, h, o}
}

func ios() Profile {
	h, o := hdr(
		"User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
		"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language", "en-US,en;q=0.9",
		"Accept-Encoding", "gzip, deflate, br",
	)
	return Profile{"ios", utls.HelloIOS_Auto, h, o}
}

// Built-in browser profiles (latest stable at release time).
var (
	Chrome  = chrome()
	Firefox = firefox()
	Safari  = safari()
	Edge    = edge()
	IOS     = ios()
)

// Profiles maps names to profiles for lookup by string.
var Profiles = map[string]Profile{
	"chrome": Chrome, "firefox": Firefox, "safari": Safari, "edge": Edge, "ios": IOS,
}
