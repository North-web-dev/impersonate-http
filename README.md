# impersonate-http

[![Go Reference](https://pkg.go.dev/badge/github.com/North-web-dev/impersonate-http.svg)](https://pkg.go.dev/github.com/North-web-dev/impersonate-http)
[![CI](https://github.com/North-web-dev/impersonate-http/actions/workflows/ci.yml/badge.svg)](https://github.com/North-web-dev/impersonate-http/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/North-web-dev/impersonate-http)](https://goreportcard.com/report/github.com/North-web-dev/impersonate-http)
![Go version](https://img.shields.io/github/go-mod/go-version/North-web-dev/impersonate-http)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Go `http.Client` whose **TLS handshake and HTTP/2 frames are byte-identical to a
real browser's**, so requests survive **JA3 / JA4 / Akamai HTTP/2 fingerprinting**
(Cloudflare, Akamai, DataDome, PerimeterX, …).

Go-native: no headless browser, no CGo, no `libcurl`, no subprocess — just a stock
`*http.Client` built on [uTLS](https://github.com/refraction-networking/utls).

## 30-second quickstart

```
go get github.com/North-web-dev/impersonate-http
```

```go
package main

import (
	"fmt"
	"io"

	impersonate "github.com/North-web-dev/impersonate-http"
)

func main() {
	client := impersonate.New(impersonate.Chrome) // a stock *http.Client
	resp, err := client.Get("https://example.com")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Println(resp.Status, len(body), "bytes")
}
```

Use the returned client exactly as you would `http.DefaultClient`.

## Profiles

`Chrome`, `ChromeAndroid`, `Firefox`, `Safari`, `Edge`, `IOS` — each sets the
matching uTLS ClientHello, the browser's HTTP/2 SETTINGS/WINDOW_UPDATE/pseudo-header
fingerprint, **and** the browser's default headers (User-Agent, `sec-ch-ua`,
`Accept`, `Sec-Fetch-*`, …). Look one up by name:

```go
client, ok := impersonate.NewByName("firefox")
```

Or plug the transport into an existing client:

```go
c := &http.Client{Transport: impersonate.NewTransport(impersonate.Safari)}
```

Caller-set headers are never overwritten by a profile's defaults.

## Proxy

Route through a `socks5://` or `http(s)://` proxy (with optional credentials):

```go
client := impersonate.New(impersonate.Chrome,
    impersonate.WithProxy("http://user:pass@host:8080"),
    impersonate.WithTimeout(20*time.Second),
)
```

`WithDialer` accepts any custom dialer if you need full control; `ProxyDialer`
exposes the proxy dial function on its own.

## Measured fingerprints (parity table)

Captured with `go run ./cmd/measure` against [tls.peet.ws/api/all](https://tls.peet.ws)
on **2026-10-25**, uTLS **v1.8.2**. These are real, reproducible measurements — run
`cmd/measure` yourself to regenerate them.

| Profile | JA4 (stable identifier) | JA3 hash | JA3 stable? | HTTP/2 (Akamai) |
| --- | --- | --- | --- | --- |
| chrome  | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | varies per connection | no — by design | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| edge    | `t13d1515h2_8daaf6152771_de4a06bb82e3` | `b32309a26951912be7dba376398abc3b` | yes* | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` |
| firefox | `t13d1715h2_5b57614c22b0_5c2c66f702b0` | `b5001237acdf006056b409cc433726b0` | yes | `1:65536;4:131072;5:16384\|12517377\|0\|m,p,a,s` |
| safari  | `t13d2014h2_a09f3c656075_14788d8d241b` | `773906b0efdefa24a7f2b8eb6985bf37` | yes | `3:100;4:4194304\|10420225\|0\|m,s,p,a` |
| ios     | `t13d2613h2_2802a3db6c62_845d286b0d67` | `656b9a2f4de6ed4909e157482860ab3d` | yes | `3:100;4:2097152\|10420225\|0\|m,s,p,a` |

**JA4 is the fingerprint to match on, not JA3.** Chrome shuffles its TLS extension
order on every connection (Chromium ≥ 110), so its JA3 hash is non-deterministic —
exactly like a real Chrome. JA4 sorts extensions, so it is stable; the cipher core
(`8daaf6152771` Chrome/Edge, `5b57614c22b0` Firefox, `a09f3c656075` Safari) matches
the published desktop-browser values, and the HTTP/2 Akamai fingerprint is byte-exact
per profile.

`*` **Edge caveat:** real Edge 131 permutes extensions like Chrome, but uTLS's
`HelloEdge_Auto` preset does not, so the Edge ClientHello is close (correct TLS
version, cipher list, ALPN) but does not reproduce Chromium's per-connection shuffle.
Prefer `Chrome` if you need the shuffle behaviour.

Profiles track uTLS's `*_Auto` templates, so they follow the current stable browser
as uTLS updates; the exact JA4 third segment can shift by a browser point release.

## What it does / does not do

Does:

- **TLS ClientHello (JA3 / JA4)** — byte-exact per profile, via uTLS. For Chrome
  this includes the per-connection extension shuffle.
- **HTTP/2 fingerprint (Akamai)** — byte-exact: SETTINGS order + values,
  `WINDOW_UPDATE` increment, and pseudo-header order all match the browser. A custom
  HTTP/2 client (built on `http2.Framer` + `hpack`) emits every frame the way the
  browser does — not Go's `net/http` stack.
- **Default headers & values** — browser-accurate, injected only when the caller
  did not set them.

Does not:

- **HTTP/3 (QUIC)** — not implemented (on the roadmap).
- **Regular-header order** — pseudo-headers are exact; regular headers are
  best-effort (profile order first, then any extras the caller added).
- **Dynamic TLS session resumption tickets / 0-RTT** — each connection does a full
  handshake.
- **Replace a browser** — there is no JS engine, no DOM, no TLS-renegotiation
  challenge solving. This defeats *passive* network fingerprinting, not active
  browser-execution challenges.

## Compared to curl_cffi / utls

- **vs [curl_cffi](https://github.com/lexiforest/curl_cffi):** curl_cffi is Python
  bound to a patched `libcurl` (CGo / native BoringSSL). impersonate-http is pure Go
  — no CGo, no `libcurl`, compiles to a single static binary, and gives you a real
  `*http.Client` you drop into existing Go code and middleware.
- **vs [utls](https://github.com/refraction-networking/utls) directly:** uTLS gives
  you the ClientHello but stops at the TLS layer — you still have to wire up ALPN,
  the HTTP/2 framing fingerprint, connection pooling, headers and proxies yourself.
  This library is that wiring, packaged as a drop-in `http.Client`.

Neither this library nor curl_cffi runs a headless browser.

## WebSocket

The same TLS fingerprint works for `wss://` — plug the profile's dialer into any
WebSocket client:

```go
// coder/websocket
websocket.Dial(ctx, "wss://host/path", &websocket.DialOptions{
    HTTPClient: &http.Client{Transport: impersonate.NewTransport(impersonate.Chrome)},
})

// gorilla/websocket
d := websocket.Dialer{NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
    return impersonate.Chrome.DialTLSContext(ctx, network, addr)
}}
```

## HTTP API

`cmd/serve` wraps the library in a language-agnostic fetch API — POST a URL and a
profile, get back the response fetched with that browser's exact fingerprint. Handy
when the rest of your stack isn't Go.

```
go run ./cmd/serve -addr :8080
# or: docker build -t impersonate . && docker run -p 8080:8080 impersonate
```

```bash
curl -s localhost:8080/fetch -d '{
  "url": "https://example.com",
  "profile": "chrome",
  "proxy": "http://user:pass@host:8080"
}'
# -> {"status":200,"final_url":"...","headers":{...},"body":"<!doctype html>...","elapsed_ms":812}
```

| Endpoint | Purpose |
| --- | --- |
| `POST /fetch` | Fetch `url` with a profile. Fields: `profile`, `method`, `headers`, `body`, `proxy`, `timeout_ms`, `follow_redirects`. `br`/`zstd`/`gzip` bodies are decoded for you. |
| `GET /profiles` | List available profiles. |
| `GET /usage` | Caller's rate/quota usage (does not count against it). |
| `GET /healthz` | Liveness. |

**Auth & quotas** are optional. Pass a single key with `-key`, or a plans file with
`-keys keys.json` for per-key rate limits and daily quotas:

```json
[{"key": "acme-key", "name": "acme", "rps": 5, "daily": 10000}]
```

Present the key as `Authorization: Bearer <key>` or `X-API-Key: <key>`. Without
either flag the API is open.

## How it works

Each connection is dialed with uTLS: a raw TCP dial, then a `UClient` handshake using
the profile's `ClientHelloID`. ALPN is probed once per host to pick HTTP/2 or
HTTP/1.1; the chosen transport re-runs the uTLS handshake for every pooled connection,
so keep-alive and connection reuse work as usual. For HTTP/2, a hand-rolled client
over `http2.Framer` emits the browser's exact SETTINGS, connection `WINDOW_UPDATE`,
and pseudo-header order.

## Roadmap

- HTTP/3 (QUIC) ClientHello impersonation.
- Edge extension-permutation parity with current Chromium.
- Profile auto-update sourced from `fingerprint-db`.
- More browser variants (Firefox ESR, Opera/Brave).

## Reproduce the measurements

- **[cmd/measure](cmd/measure)** — in this repo; captures the JA3/JA4/Akamai this
  library emits per profile against `tls.peet.ws`.
- **[fingerprint-db](https://github.com/North-web-dev/fingerprint-db)** — the
  measured JA3/JA4/Akamai fingerprints these profiles reproduce (JSON + loaders).
- **[fpcheck](https://github.com/North-web-dev/fpcheck)** — self-hosted rig to read
  your own JA3/JA4/JA4H + HTTP/2 fingerprint.

## Support

If this project saves you time, you can support development:

⭐ Star the repo if it helped.

| Coin | Address |
|---|---|
| **BTC** | `bc1q0sfghv7yfl594gjurhyhlhdgm0dtwh4dkjha36` |
| **ETH / USDT-ERC20 / BNB-BEP20** | `0xB827b5a8B6c5111946c5D872933b2C23484E87dE` |
| **SOL** | `3ch5aHrPp3CierhiNXmqmtFH2dMHh6Gfv7a97KtLMMCh` |
| **USDT-TRC20 / TRX** | `TUAyz7TjgJdFVD2oFHWUUTNrzzAnBRgySG` |
| **TON** | `UQAJmYVuR3hh02etjaPKJF-h6jcpdSnq9ZIFvI64NEskS6tx` |

## Disclaimer

Provided **as is, without warranty of any kind**, for lawful automation, testing, and
research. You are solely responsible for complying with the terms and laws that apply
to the sites you access. The authors accept no liability for misuse.

## License

MIT — see [LICENSE](LICENSE).
