package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

var timeZero time.Time

// Proxy is one endpoint; identity is protocol + host + port.
type Proxy struct {
	Protocol string // "socks5" or "http"
	Host     string
	Port     string
}

func (p Proxy) Address() string { return net.JoinHostPort(p.Host, p.Port) }
func (p Proxy) URI() string     { return p.Protocol + "://" + p.Address() }

// Result of one check.
type Result struct {
	Proxy
	OK        bool
	LatencyMs int64
	Err       string
	// JudgeLimited: the judge answered HTTP 429 through a verified TLS tunnel. The proxy works; the judge
	// refused the rate (proxies that share an exit IP share its limit).
	JudgeLimited bool
}

// judgeRoots verifies HTTPS judges; nil means the system roots. Tests set it.
var judgeRoots *x509.CertPool

// parseProxies reads `ip:port` or `scheme://ip:port` lines; blank lines and `#` comments
// are skipped, unknown schemes rejected, duplicates dropped.
func parseProxies(r io.Reader, defaultProtocol string) ([]Proxy, error) {
	var out []Proxy
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		protocol := defaultProtocol
		if i := strings.Index(text, "://"); i >= 0 {
			protocol = strings.ToLower(text[:i])
			text = text[i+3:]
		}
		if protocol == "socks5h" {
			protocol = "socks5"
		}
		if protocol != "socks5" && protocol != "http" {
			return nil, fmt.Errorf("line %d: unsupported protocol %q (socks5 or http)", line, protocol)
		}
		host, port, err := net.SplitHostPort(text)
		if err != nil || host == "" || port == "" {
			return nil, fmt.Errorf("line %d: expected host:port, got %q", line, text)
		}
		p := Proxy{Protocol: protocol, Host: host, Port: port}
		if !seen[p.URI()] {
			seen[p.URI()] = true
			out = append(out, p)
		}
	}
	return out, sc.Err()
}

func transportFor(p Proxy, allowPrivate bool) *http.Transport {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	t := &http.Transport{TLSHandshakeTimeout: 5 * time.Second, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{RootCAs: judgeRoots}}
	switch p.Protocol {
	case "socks5":
		t.DialContext = func(ctx context.Context, network, target string) (net.Conn, error) {
			conn, err := guardedDial(ctx, dialer, allowPrivate, "tcp", p.Address())
			if err != nil {
				return nil, err
			}
			tunnel, err := dialSOCKS5(ctx, conn, target)
			if err != nil {
				conn.Close()
				return nil, err
			}
			return tunnel, nil
		}
	default:
		t.Proxy = http.ProxyURL(&url.URL{Scheme: "http", Host: p.Address()})
		t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return guardedDial(ctx, dialer, allowPrivate, network, address)
		}
	}
	return t
}

// checkOne fetches the judge URL through the proxy. HTTPS judges get full
// certificate verification, so a passing proxy tunnelled TLS untouched.
func checkOne(ctx context.Context, p Proxy, judge string, timeout time.Duration, allowPrivate bool) Result {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := &http.Client{Transport: transportFor(p, allowPrivate)}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, judge, nil)
	if err != nil {
		return Result{Proxy: p, Err: err.Error()}
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Result{Proxy: p, Err: err.Error()}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusTooManyRequests && req.URL.Scheme == "https" {
		// Only the judge can answer inside a verified TLS session, so the tunnel worked. Over plain
		// HTTP the proxy could have answered itself, so there a 429 stays a failure.
		return Result{Proxy: p, OK: true, JudgeLimited: true, LatencyMs: time.Since(start).Milliseconds()}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Result{Proxy: p, Err: fmt.Sprintf("judge returned HTTP %d", resp.StatusCode)}
	}
	return Result{Proxy: p, OK: true, LatencyMs: time.Since(start).Milliseconds()}
}

// checkAll runs a bounded worker pool and returns working proxies, fastest first.
func checkAll(ctx context.Context, proxies []Proxy, judge string, timeout time.Duration, concurrency int, allowPrivate bool, progress func(Result)) []Result {
	jobs := make(chan Proxy)
	results := make(chan Result)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				results <- checkOne(ctx, p, judge, timeout, allowPrivate)
			}
		}()
	}
	go func() {
		for _, p := range proxies {
			select {
			case jobs <- p:
			case <-ctx.Done():
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	var working []Result
	for r := range results {
		if progress != nil {
			progress(r)
		}
		if r.OK {
			working = append(working, r)
		}
	}
	sort.Slice(working, func(i, j int) bool {
		if working[i].LatencyMs != working[j].LatencyMs {
			return working[i].LatencyMs < working[j].LatencyMs
		}
		return working[i].URI() < working[j].URI()
	})
	return working
}
