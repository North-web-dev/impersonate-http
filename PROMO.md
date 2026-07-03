# Куда вкинуть (каналы) + готовые посты

## Каналы (по отдаче)
1. r/golang + r/webscraping (Reddit) — прямая ЦА
2. Hacker News — Show HN
3. awesome-go PR (раздел HTTP Clients) — вечный трафик
4. X/Twitter — #golang #webscraping, тэгнуть авторов utls/curl_cffi
5. lobste.rs (go tag), dev.to кросспост

## Show HN
Title: Show HN: impersonate-http – Go http.Client with a browser-exact TLS+HTTP/2 fingerprint
Text:
A drop-in Go *http.Client whose ClientHello (JA3/JA4) AND HTTP/2 frames (Akamai:
SETTINGS order, WINDOW_UPDATE, pseudo-header order) are byte-identical to real
Chrome/Firefox/Safari — so requests survive fingerprint-based blocking without a
headless browser or CGo.

Most Go options only fix TLS; anti-bot stacks (Cloudflare/Akamai/DataDome) also
score the HTTP/2 layer. This does both — verified against tls.peet.ws and
scrapfly (Chrome akamai = 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p).

    client := impersonate.New(impersonate.Chrome)
    resp, _ := client.Get("https://example.com")

Custom HTTP/2 client on http2.Framer + hpack. MIT.
https://github.com/North-web-dev/impersonate-http

## r/golang
Title: I built a Go http.Client with a byte-exact browser TLS + HTTP/2 fingerprint
Body: (то же, что Show HN, + "feedback welcome, especially on the h2 flow-control edge cases")

## X/Twitter
Go devs fighting Cloudflare/JA3-JA4 blocks: impersonate-http — a drop-in
http.Client whose TLS *and* HTTP/2 (Akamai) fingerprint is byte-identical to
Chrome. No headless browser, no CGo. Verified vs scrapfly. MIT 👇
github.com/North-web-dev/impersonate-http
#golang #webscraping

## awesome-go PR
Файл README.md, секция "### HTTP Clients", строка:
- [impersonate-http](https://github.com/North-web-dev/impersonate-http) - Drop-in http.Client with a byte-exact browser TLS (JA3/JA4) and HTTP/2 (Akamai) fingerprint.
