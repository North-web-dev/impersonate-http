# impersonate-http

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

`Chrome`, `Firefox`, `Safari`, `Edge`, `IOS` — each sets the matching uTLS
ClientHello **and** the browser's default headers (User-Agent, `sec-ch-ua`,
`Accept`, `Sec-Fetch-*`, …). Look one up by name:

```go
client, ok := impersonate.NewByName("firefox")
```

Or plug the transport into an existing client:

```go
c := &http.Client{Transport: impersonate.NewTransport(impersonate.Safari)}
```

Caller-set headers are never overwritten by a profile's defaults.

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

## Related

- **[fingerprint-db](https://github.com/North-web-dev/fingerprint-db)** — the
  measured JA3/JA4/Akamai fingerprints these profiles reproduce (JSON + loaders).
- **[fpcheck](https://github.com/North-web-dev/fpcheck)** — self-hosted rig to
  read your own JA3/JA4/JA4H + HTTP/2 fingerprint.

## Roadmap

- HTTP/3 (QUIC) ClientHello impersonation.
- Profile auto-update sourced from `fingerprint-db`.
- More browser variants (Android Chrome, Firefox ESR, Opera/Brave).

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
