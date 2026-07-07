# impersonate-http

[![Go Reference](https://pkg.go.dev/badge/github.com/North-web-dev/impersonate-http.svg)](https://pkg.go.dev/github.com/North-web-dev/impersonate-http)
[![CI](https://github.com/North-web-dev/impersonate-http/actions/workflows/ci.yml/badge.svg)](https://github.com/North-web-dev/impersonate-http/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/North-web-dev/impersonate-http)](https://goreportcard.com/report/github.com/North-web-dev/impersonate-http)
![Go version](https://img.shields.io/github/go-mod/go-version/North-web-dev/impersonate-http)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Go `http.Client` whose **TLS handshake is byte-identical to a real browser's**,
so requests survive **JA3 / JA4 fingerprinting** (Cloudflare, Akamai, DataDome,
PerimeterX, …) — no headless browser, no CGo, no curl.

```go
client := impersonate.New(impersonate.Chrome)
resp, _ := client.Get("https://example.com")
```

That's it — a stock `*http.Client`. Use it exactly as you would `http.DefaultClient`.

## Install

```
go get github.com/North-web-dev/impersonate-http
```

## Profiles

`Chrome`, `ChromeAndroid`, `Firefox`, `Safari`, `Edge`, `IOS` — each sets the
matching uTLS ClientHello **and** the browser's default headers (User-Agent,
`sec-ch-ua`, `Accept`, `Sec-Fetch-*`, …). Look one up by name:

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

## Verified

Fingerprints measured against [tls.peet.ws](https://tls.peet.ws):

| Profile | JA4 | JA3 |
| --- | --- | --- |
| Chrome  | `t13d1516h2_8daaf6152771_…` | `1d03c132ce29d0d7936acc72f12dd7a7` |
| Firefox | `t13d1715h2_5b57614c22b0_…` | `b5001237acdf006056b409cc433726b0` |
| Safari  | `t13d2014h2_a09f3c656075_…` | `773906b0efdefa24a7f2b8eb6985bf37` |

HTTP/2 (Akamai), Chrome, measured at [tools.scrapfly.io](https://tools.scrapfly.io/api/fp/anything):
`1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p` — byte-identical to Chrome.

The `t13d1516h2_8daaf6152771` Chrome core (version + cipher list + ALPN + cipher
hash) matches a genuine Chrome handshake. Profiles track uTLS's `*_Auto`
templates, so they follow the current stable browser as uTLS updates.

## Scope

- ✅ **TLS ClientHello (JA3, JA4)** — byte-exact per profile.
- ✅ **HTTP/2 fingerprint (Akamai)** — byte-exact: SETTINGS order + values,
  `WINDOW_UPDATE` increment, and pseudo-header order all match the browser. A
  custom HTTP/2 client (built on `http2.Framer` + `hpack`) emits every frame the
  way the browser does — not Go's stack.
- ✅ **Default headers & values** — browser-accurate.
- ⚠️ **Header order** — pseudo-headers are exact; regular-header order is
  best-effort (profile order first, then extras).

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
profile, get back the response fetched with that browser's exact fingerprint.
Handy when the rest of your stack isn't Go.

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

**Auth & quotas** are optional. Pass a single key with `-key`, or a plans file
with `-keys keys.json` for per-key rate limits and daily quotas:

```json
[{"key": "acme-key", "name": "acme", "rps": 5, "daily": 10000}]
```

Present the key as `Authorization: Bearer <key>` or `X-API-Key: <key>`. Without
either flag the API is open.

## Related

- **[fingerprint-db](https://github.com/North-web-dev/fingerprint-db)** — the
  measured JA3/JA4/Akamai fingerprints these profiles reproduce (JSON + loaders).
- **[fpcheck](https://github.com/North-web-dev/fpcheck)** — self-hosted rig to
  read your own JA3/JA4/JA4H + HTTP/2 fingerprint.

## Roadmap

- HTTP/3 (QUIC) ClientHello impersonation.
- Profile auto-update sourced from `fingerprint-db`.
- More browser variants (Firefox ESR, Opera/Brave).

## How it works

Each connection is dialed with [uTLS](https://github.com/refraction-networking/utls):
a raw TCP dial, then a `UClient` handshake using the profile's `ClientHelloID`.
ALPN is probed once per host to pick HTTP/2 or HTTP/1.1; the chosen transport
re-runs the uTLS handshake for every pooled connection, so keep-alive and
connection reuse work as usual.

## Disclaimer

Provided **as is, without warranty of any kind**, for lawful automation,
testing, and research. You are solely responsible for complying with the terms
and laws that apply to the sites you access. The authors accept no liability for
misuse.

## License

MIT — see [LICENSE](LICENSE).
