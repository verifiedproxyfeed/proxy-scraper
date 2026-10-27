# Proxy Scraper CLI

An open-source proxy scraper: download the verified free proxy feed, scrape public proxy lists, and check
proxies from your own machine. A single static binary with no dependencies (Go standard library only).

The same verified list is on the web at https://proxyscraper.com, and as plain URLs for scripts, for example
https://api.proxyscraper.com/v1/socks5.txt.

```sh
proxy-scraper fetch -protocol socks5                     # the verified feed, fastest first
proxy-scraper scrape -protocol socks5 > candidates.txt   # public lists, unchecked
proxy-scraper check -protocol socks5 candidates.txt      # test them yourself, keep the working ones
proxy-scraper scrape -protocol http | proxy-scraper check -protocol http -format uri
```

## Install

Download a binary for Linux, macOS or Windows from the
[releases page](https://github.com/verifiedproxyfeed/proxy-scraper/releases) and check it against `SHA256SUMS`.
The binaries are not signed; on macOS, a copy downloaded in a browser may need
`xattr -d com.apple.quarantine proxy-scraper_*` before it runs.

Or build it with Go 1.24 or later:

    go install github.com/verifiedproxyfeed/proxy-scraper@latest

## What each command promises

- **`fetch`**: the feed's own rule. Every row passed our check within 15 minutes before its snapshot. Flags:
  `-protocol socks5|http`, `-max-latency 500|1000|1500|5000`, `-format ipport|uri|json`, `-stable` (up ≥90% of
  the last 7 days), `-base` (another data host), `-key` (below).
- **`scrape`**: downloads each list in the built-in source register (`sources.json`) marked `"publish": true`
  (its licence lets the feed publish from it), de-duplicates, and prints `ip:port`. The register also records
  the lists the feed does not publish from (`"publish": false`); `scrape` never downloads those. A source that
  fails is reported on stderr and skipped. Nothing is checked.
- **`check`**: fetches an HTTPS judge URL through every proxy with full certificate verification and prints the
  ones that answered, fastest first.
  - A proxy that passes therefore tunnelled TLS untouched.
  - An HTTPS judge that answers HTTP 429 has limited the rate, often because several proxies share one exit IP.
    The answer still came through the verified tunnel, so those proxies count as working and stderr says how
    many. With an `http://` judge, a 429 counts as a failure.
  - Flags: `-judge URL` (default: `https://api.proxyscraper.com/v1/ip`), `-timeout 10s`, `-concurrency 50`
    (max 500), `-format`.

## Key (optional)

`fetch` needs no key. The free URLs allow 10 requests in 10 seconds per address; a free key from
https://proxyscraper.com/account lifts that to 1,000 a minute and 100,000 a day. With a key, `fetch` asks
`https://api.proxyscraper.com/k/{key}/v1/…` instead of `/v1/…`, same paths and parameters, and gets the same
rows: a key never gets fresher, more or other ones.

```sh
export PROXY_SCRAPER_KEY=psk_…      # or, for one run: proxy-scraper fetch -key psk_…
proxy-scraper fetch -protocol socks5
```

- `-key` wins over `PROXY_SCRAPER_KEY`, and `-key ''` runs without one. Prefer the variable: a flag shows up in
  `ps` and in your shell history.
- Anything that is not `psk_` and 32 lower-case letters or digits is refused before a request is made. A key
  goes only to an `https` data host (or one on your own machine), since it travels in the URL.
- The key is never printed. Errors show its URL as `/k/psk_masked/v1/…`, as the server's own logs do.
- HTTP 404 means the key is unknown or revoked: make a new one on the account page. HTTP 429 means it is over a
  cap; the error says which one and when to retry (`Retry-After`).
- Without a key, `fetch`'s HTTP 429 names the free limit (10 requests in 10 seconds per address) and the account
  page.
- `check` never sends the key (its judge requests go through the proxies it tests), and neither does `scrape`.
- A key also opens a few documents the CLI does not fetch: every country in one file, per-proxy history and
  about the last two hours of snapshots, under the same `/k/{key}/v1/` root; https://proxyscraper.com/api#key
  lists them.

## Safety

- **Internal addresses are refused.** `check` will not dial loopback, private, link-local (including cloud
  metadata 169.254.169.254), CGNAT, multicast or reserved addresses. Host names are resolved first, so they are
  covered too. Use `-allow-private` only for proxies in your own lab.
- **Never send credentials or personal data through a public proxy.** Use `https://` targets.

## Data and licences

- The code is MIT-licensed (`LICENSE`).
- The feed that `fetch` downloads is published under CC BY 4.0: credit api.proxyscraper.com when you republish
  it. Its snapshots can include addresses first published by [proxio.io](https://proxio.io) (CC BY 4.0) and
  proxmint/free-proxy-list (CC BY 4.0).
- `scrape` prints what the `"publish": true` sources list, unchecked. Each source's licence is recorded in
  `sources.json`.

## Build

```sh
go test ./...
go build .
```

A plain build needs no flags: the data host, https://api.proxyscraper.com, is built in and also supplies the
default judge (`/v1/ip`). `fetch -base` and `check -judge` override them for one run. Release binaries are static,
stripped builds with the version stamped in (`CGO_ENABLED=0`, `-trimpath`, `-ldflags "-s -w -X main.version=0.1.0"`).
