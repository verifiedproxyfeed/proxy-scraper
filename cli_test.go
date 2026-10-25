package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- fixtures -----------------------------------------------------------------

// startSOCKS5 is a minimal no-auth SOCKS5 server (CONNECT, IPv4 or domain).
func startSOCKS5(t *testing.T) (addr string, used *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	used = &atomic.Int64{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				hello := make([]byte, 3)
				if _, err := io.ReadFull(c, hello); err != nil {
					return
				}
				c.Write([]byte{5, 0})
				head := make([]byte, 4)
				if _, err := io.ReadFull(c, head); err != nil {
					return
				}
				var host string
				switch head[3] {
				case 1:
					ip := make([]byte, 4)
					io.ReadFull(c, ip)
					host = net.IP(ip).String()
				case 3:
					n := make([]byte, 1)
					io.ReadFull(c, n)
					name := make([]byte, n[0])
					io.ReadFull(c, name)
					host = string(name)
				default:
					return
				}
				pb := make([]byte, 2)
				io.ReadFull(c, pb)
				up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb)))))
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				used.Add(1)
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, c)
				io.Copy(c, up)
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), used
}

// startHTTPProxy forwards absolute-form requests and CONNECT tunnels.
func startHTTPProxy(t *testing.T) (addr string, used *atomic.Int64) {
	t.Helper()
	used = &atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		used.Add(1)
		if r.Method == http.MethodConnect {
			up, err := net.Dial("tcp", r.Host)
			if err != nil {
				http.Error(w, "bad gateway", http.StatusBadGateway)
				return
			}
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			go io.Copy(up, c)
			io.Copy(c, up)
			c.Close()
			up.Close()
			return
		}
		out := r.Clone(r.Context())
		out.RequestURI = "" // a server request cannot be sent as-is
		resp, err := http.DefaultTransport.RoundTrip(out)
		if err != nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://"), used
}

func judge(t *testing.T, status int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, "203.0.113.9\n")
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens here any more: connection refused
	return addr
}

// --- address guard ------------------------------------------------------------

func TestGuardBlocksInternalSpace(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "198.18.0.1", "::1", "fe80::1", "fe80::1%eth0", "fd00::1", "::ffff:127.0.0.1"} {
		if isPublic(netip.MustParseAddr(ip)) {
			t.Errorf("%s must be refused", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "203.0.113.7", "1.1.1.1", "2606:4700::1111"} {
		if !isPublic(netip.MustParseAddr(ip)) {
			t.Errorf("%s must be allowed", ip)
		}
	}
}

func TestGuardRefusesHostnamesThatResolveInside(t *testing.T) {
	_, err := guardedDial(context.Background(), &net.Dialer{Timeout: time.Second}, false, "tcp", "localhost:9")
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("want refusal, got %v", err)
	}
}

// --- input --------------------------------------------------------------------

func TestParseProxies(t *testing.T) {
	in := "# comment\n203.0.113.7:1080\nsocks5h://203.0.113.7:1080\nhttp://198.51.100.4:8080\n\n203.0.113.7:1080\n"
	got, err := parseProxies(strings.NewReader(in), "socks5")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"socks5://203.0.113.7:1080", "http://198.51.100.4:8080"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i, p := range got {
		if p.URI() != want[i] {
			t.Errorf("row %d: %s, want %s", i, p.URI(), want[i])
		}
	}
	for _, bad := range []string{"socks4://1.2.3.4:1080", "1.2.3.4", "ftp://1.2.3.4:21"} {
		if _, err := parseProxies(strings.NewReader(bad), "socks5"); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}

// --- SOCKS5 client ------------------------------------------------------------

func TestSOCKS5RejectsAuthRequiredProxy(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		io.ReadFull(server, make([]byte, 3))
		server.Write([]byte{5, 0xff}) // no acceptable methods
		server.Close()
	}()
	if _, err := dialSOCKS5(context.Background(), client, "example.com:443"); err == nil || !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("want auth error, got %v", err)
	}
}

// --- check end to end ---------------------------------------------------------

func TestCheckThroughRealProxies(t *testing.T) {
	socks, socksUsed := startSOCKS5(t)
	httpProxy, httpUsed := startHTTPProxy(t)
	j := judge(t, 200)
	host, port, _ := net.SplitHostPort(socks)
	hhost, hport, _ := net.SplitHostPort(httpProxy)
	dead := deadAddr(t)
	dhost, dport, _ := net.SplitHostPort(dead)
	proxies := []Proxy{
		{Protocol: "socks5", Host: dhost, Port: dport},
		{Protocol: "socks5", Host: host, Port: port},
		{Protocol: "http", Host: hhost, Port: hport},
	}
	working := checkAll(context.Background(), proxies, j, 5*time.Second, 4, true, nil)
	if len(working) != 2 {
		t.Fatalf("want 2 working, got %+v", working)
	}
	if socksUsed.Load() == 0 || httpUsed.Load() == 0 {
		t.Fatalf("both fixture proxies must be used (socks %d, http %d)", socksUsed.Load(), httpUsed.Load())
	}
	if working[0].LatencyMs > working[1].LatencyMs {
		t.Errorf("not sorted fastest first: %+v", working)
	}
}

func TestCheckRefusesInternalProxiesByDefault(t *testing.T) {
	socks, used := startSOCKS5(t)
	host, port, _ := net.SplitHostPort(socks)
	r := checkOne(context.Background(), Proxy{Protocol: "socks5", Host: host, Port: port}, judge(t, 200), 5*time.Second, false)
	if r.OK || !strings.Contains(r.Err, "non-public") || used.Load() != 0 {
		t.Fatalf("want refusal without a dial, got %+v (used %d)", r, used.Load())
	}
}

func TestCheckFailsOnJudgeError(t *testing.T) {
	socks, _ := startSOCKS5(t)
	host, port, _ := net.SplitHostPort(socks)
	r := checkOne(context.Background(), Proxy{Protocol: "socks5", Host: host, Port: port}, judge(t, 503), 5*time.Second, true)
	if r.OK || !strings.Contains(r.Err, "HTTP 503") {
		t.Fatalf("want judge failure, got %+v", r)
	}
}

// A judge's 429 over verified TLS came from the judge itself, through a working tunnel: proxies that
// share an exit IP trip its rate limit. It counts as working and is flagged; over plain HTTP the proxy
// could have answered itself, so there it stays a failure.
func TestCheckCountsAJudge429OverTLSAsWorking(t *testing.T) {
	tlsJudge := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "10")
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, "error code: 1015")
	}))
	defer tlsJudge.Close()
	judgeRoots = tlsJudge.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	defer func() { judgeRoots = nil }()

	socks, _ := startSOCKS5(t)
	httpProxy, httpUsed := startHTTPProxy(t)
	host, port, _ := net.SplitHostPort(socks)
	hhost, hport, _ := net.SplitHostPort(httpProxy)
	proxies := []Proxy{{Protocol: "socks5", Host: host, Port: port}, {Protocol: "http", Host: hhost, Port: hport}}
	working := checkAll(context.Background(), proxies, tlsJudge.URL, 5*time.Second, 2, true, nil)
	if len(working) != 2 || !working[0].JudgeLimited || !working[1].JudgeLimited {
		t.Fatalf("want both proxies working and flagged judge-limited, got %+v", working)
	}
	if httpUsed.Load() == 0 {
		t.Fatal("the HTTP proxy must carry the CONNECT tunnel")
	}

	r := checkOne(context.Background(), Proxy{Protocol: "socks5", Host: host, Port: port}, judge(t, http.StatusTooManyRequests), 5*time.Second, true)
	if r.OK || !strings.Contains(r.Err, "HTTP 429") {
		t.Fatalf("a plain-HTTP judge's 429 must stay a failure, got %+v", r)
	}

	var out, errOut bytes.Buffer
	in := strings.NewReader(socks + "\n")
	if code := run(context.Background(), []string{"check", "-allow-private", "-judge", tlsJudge.URL}, in, &out, &errOut); code != 0 {
		t.Fatalf("check exit %d: %s", code, errOut.String())
	}
	if strings.TrimSpace(out.String()) != socks || !strings.Contains(errOut.String(), "1 of 1 working (1 through a judge that answered HTTP 429") {
		t.Fatalf("stdout %q, stderr %q", out.String(), errOut.String())
	}
}

// --- commands -----------------------------------------------------------------

func TestFeedURLFollowsTheContract(t *testing.T) {
	cases := map[string][6]string{
		"https://d.example/v1/socks5.txt":                           {"https://d.example", "", "socks5", "", "ipport", ""},
		"https://d.example/v1/http.txt?format=uri&max_latency=1000": {"https://d.example/", "", "http", "1000", "uri", ""},
		"https://d.example/v1/http.json?max_latency=500":            {"https://d.example", "", "http", "500", "json", ""},
		"https://d.example/v1/socks5/stable.txt":                    {"https://d.example", "", "socks5", "", "ipport", "stable"},
		// With a key: the same path and query under /k/{key}.
		"https://d.example/k/" + testKey + "/v1/http.txt?format=uri&max_latency=1000": {"https://d.example/", testKey, "http", "1000", "uri", ""},
		"https://d.example/k/" + testKey + "/v1/socks5/stable.json":                   {"https://d.example", testKey, "socks5", "", "json", "stable"},
		"https://d.example/feed/k/" + testKey + "/v1/socks5.txt":                      {"https://d.example/feed", testKey, "socks5", "", "ipport", ""},
		"http://127.0.0.1:8080/k/" + testKey + "/v1/socks5.txt":                       {"http://127.0.0.1:8080", testKey, "socks5", "", "ipport", ""},
		"http://[::1]:8080/k/" + testKey + "/v1/socks5.txt":                           {"http://[::1]:8080", testKey, "socks5", "", "ipport", ""},
		"http://localhost/k/" + testKey + "/v1/socks5.txt":                            {"http://localhost", testKey, "socks5", "", "ipport", ""},
	}
	for want, c := range cases {
		got, err := feedURL(c[0], c[1], c[2], c[3], c[4], c[5] == "stable")
		if err != nil || got != want {
			t.Errorf("got %q (%v), want %q", got, err, want)
		}
	}
	if _, err := feedURL("ftp://x", "", "socks5", "", "ipport", false); err == nil {
		t.Error("non-http base must be rejected")
	}
	// The key is in the path: over plain http it would cross the network readable.
	for _, base := range []string{"http://d.example", "http://192.0.2.1:8080", "http://localhost.d.example"} {
		if _, err := feedURL(base, testKey, "socks5", "", "ipport", false); err == nil {
			t.Errorf("a key must not go to %s", base)
		}
	}
}

func TestRunExitCodes(t *testing.T) {
	var out, errOut bytes.Buffer
	ctx := context.Background()
	if code := run(ctx, nil, nil, &out, &errOut); code != 2 {
		t.Errorf("no args: %d", code)
	}
	if code := run(ctx, []string{"nope"}, nil, &out, &errOut); code != 2 {
		t.Errorf("unknown command: %d", code)
	}
	if code := run(ctx, []string{"fetch", "-protocol", "socks4", "-base", "https://x"}, nil, &out, &errOut); code != 2 {
		t.Errorf("bad protocol: %d", code)
	}
	if code := run(ctx, []string{"fetch", "-stable", "-max-latency", "500", "-base", "https://x"}, nil, &out, &errOut); code != 2 {
		t.Errorf("stable + latency: %d", code)
	}
	saved := defaultBase
	defaultBase = ""
	if code := run(ctx, []string{"fetch"}, nil, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "-base") {
		t.Errorf("fetch without a data host must explain -base: %d %q", code, errOut.String())
	}
	defaultBase = saved
	out.Reset()
	if code := run(ctx, []string{"version"}, nil, &out, &errOut); code != 0 || !strings.HasPrefix(out.String(), "proxy-scraper ") {
		t.Errorf("version: %d %q", code, out.String())
	}
}

func TestFetchPrintsTheFeed(t *testing.T) {
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/http.txt" || r.URL.Query().Get("max_latency") != "1000" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, "192.0.2.10:8080\n")
	}))
	defer feed.Close()
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"fetch", "-base", feed.URL, "-protocol", "http", "-max-latency", "1000"}, nil, &out, &errOut)
	if code != 0 || out.String() != "192.0.2.10:8080\n" {
		t.Fatalf("code %d out %q err %q", code, out.String(), errOut.String())
	}
}

// A `go install` build has no -ldflags: fetch must still find the data host on its own.
func TestFetchWithoutFlagsUsesTheBuiltInDataHost(t *testing.T) {
	if u, err := url.Parse(defaultBase); err != nil || u.Scheme != "https" || u.Host == "" {
		t.Fatalf("the source must name the data host over https, got %q", defaultBase)
	}
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "192.0.2.11:1080\n")
	}))
	defer feed.Close()
	saved := defaultBase
	defaultBase = feed.URL
	defer func() { defaultBase = saved }()
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"fetch"}, nil, &out, &errOut); code != 0 || out.String() != "192.0.2.11:1080\n" {
		t.Fatalf("code %d out %q err %q", code, out.String(), errOut.String())
	}
}

// --- key ----------------------------------------------------------------------

// testKey has the server's key format (psk_ and 32 of [a-z0-9]); built, so no file holds a key-shaped literal.
var testKey = "psk_" + strings.Repeat("k3", 16)

// recordingFeed is a data host that answers every request with status, header and body, and records it.
func recordingFeed(t *testing.T, status int, header http.Header, body string) (base string, requests func() []*http.Request) {
	t.Helper()
	var mu sync.Mutex
	var seen []*http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Clone(context.Background()))
		mu.Unlock()
		for name, values := range header {
			w.Header()[name] = values
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []*http.Request {
		mu.Lock()
		defer mu.Unlock()
		return append([]*http.Request(nil), seen...)
	}
}

func TestFetchWithAKeyAsksTheKeyedURL(t *testing.T) {
	base, requests := recordingFeed(t, http.StatusOK, nil, "192.0.2.12:1080\n")
	other := "psk_" + strings.Repeat("z9", 16)
	keyed := "/k/" + testKey + "/v1/http.txt?max_latency=1000"
	free := "/v1/http.txt?max_latency=1000"
	cases := []struct {
		name, env string
		flags     []string
		want      string
	}{
		{"flag", "", []string{"-key", testKey}, keyed},
		{"environment", testKey, nil, keyed},
		{"flag over environment", other, []string{"-key", testKey}, keyed},
		{"spaces around the key", " " + testKey + "\n", nil, keyed},
		{"empty flag over environment", testKey, []string{"-key", ""}, free},
		{"empty environment", "", nil, free},
	}
	for _, c := range cases {
		t.Setenv(keyEnv, c.env)
		var out, errOut bytes.Buffer
		args := append([]string{"fetch", "-base", base, "-protocol", "http", "-max-latency", "1000"}, c.flags...)
		code := run(context.Background(), args, nil, &out, &errOut)
		seen := requests()
		if code != 0 || out.String() != "192.0.2.12:1080\n" || errOut.Len() != 0 {
			t.Fatalf("%s: code %d out %q err %q", c.name, code, out.String(), errOut.String())
		}
		last := seen[len(seen)-1]
		if last.RequestURI != c.want || last.Header.Get("User-Agent") != "proxy-scraper-cli/"+version {
			t.Errorf("%s: asked %s with User-Agent %q, want %s", c.name, last.RequestURI, last.Header.Get("User-Agent"), c.want)
		}
	}
}

// Without a key, fetch asks exactly what v0.1.0 asked and reports a refusal in v0.1.0's words.
func TestFetchWithoutAKeyIsUnchanged(t *testing.T) {
	t.Setenv(keyEnv, "")
	base, requests := recordingFeed(t, http.StatusOK, nil, "192.0.2.13:1080\n")
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"fetch", "-base", base}, nil, &out, &errOut); code != 0 {
		t.Fatalf("code %d err %q", code, errOut.String())
	}
	r := requests()[0]
	var names []string
	for name := range r.Header {
		names = append(names, name)
	}
	if r.Method != http.MethodGet || r.RequestURI != "/v1/socks5.txt" || len(names) != 2 ||
		r.Header.Get("User-Agent") != "proxy-scraper-cli/"+version || r.Header.Get("Accept-Encoding") != "gzip" {
		t.Fatalf("%s %s with headers %v", r.Method, r.RequestURI, r.Header)
	}
	for _, status := range []int{http.StatusNotFound, http.StatusTooManyRequests} {
		refusing, _ := recordingFeed(t, status, http.Header{"Retry-After": {"60"}}, "no")
		out.Reset()
		errOut.Reset()
		code := run(context.Background(), []string{"fetch", "-base", refusing}, nil, &out, &errOut)
		if want := "error: fetch " + refusing + "/v1/socks5.txt: HTTP " + strconv.Itoa(status) + "\n"; code != 1 || errOut.String() != want {
			t.Errorf("code %d err %q, want %q", code, errOut.String(), want)
		}
	}
}

func TestFetchRefusesAMalformedKeyBeforeAnyRequest(t *testing.T) {
	base, requests := recordingFeed(t, http.StatusOK, nil, "")
	bad := []string{
		"psk_SHORTK3",
		strings.ToUpper(testKey),
		"pk_" + testKey[4:],
		testKey + "q",
		testKey[:20] + " " + testKey[21:],
		testKey[:35] + "-",
	}
	for _, value := range bad {
		for _, viaFlag := range []bool{false, true} {
			args := []string{"fetch", "-base", base}
			from := keyEnv
			t.Setenv(keyEnv, value)
			if viaFlag {
				t.Setenv(keyEnv, "")
				args = append(args, "-key", value)
				from = "-key"
			}
			var out, errOut bytes.Buffer
			code := run(context.Background(), args, nil, &out, &errOut)
			msg := errOut.String()
			if code != 2 || !strings.HasPrefix(msg, from+" is not a key") || !strings.Contains(msg, accountPage) {
				t.Errorf("%s %q: code %d err %q", from, value, code, msg)
			}
			if strings.Contains(msg, value) || strings.Contains(strings.ToLower(msg), "k3k3k3") {
				t.Errorf("%s: the error shows the value: %q", from, msg)
			}
		}
	}
	if n := len(requests()); n != 0 {
		t.Fatalf("a malformed key must not be sent; %d requests", n)
	}
}

// The server's keyed refusals are explained, and no error shows the key: the URL is masked the way the
// server's own logs mask it.
func TestFetchKeyErrorsExplainAndNeverShowTheKey(t *testing.T) {
	t.Setenv(keyEnv, testKey)
	cases := []struct {
		status     int
		retryAfter string
		want       string
	}{
		{http.StatusNotFound, "", "HTTP 404: the key is unknown or revoked; a new one: " + accountPage},
		{http.StatusTooManyRequests, "60", "HTTP 429: the key is over its per-minute cap; retry after 60 s (caps: " + accountPage + ")"},
		{http.StatusTooManyRequests, "3600", "HTTP 429: the key is over its daily cap; retry after 3600 s (caps: " + accountPage + ")"},
		{http.StatusTooManyRequests, "", "HTTP 429: over the burst limit for keyed requests; retry in a few seconds"},
		{http.StatusServiceUnavailable, "600", "HTTP 503\n"},
	}
	for _, c := range cases {
		header := http.Header{}
		if c.retryAfter != "" {
			header.Set("Retry-After", c.retryAfter)
		}
		base, _ := recordingFeed(t, c.status, header, "Unknown key. Keys: "+accountPage)
		var out, errOut bytes.Buffer
		code := run(context.Background(), []string{"fetch", "-base", base}, nil, &out, &errOut)
		msg := errOut.String()
		if code != 1 || !strings.HasPrefix(msg, "error: fetch "+base+"/k/"+maskedKey+"/v1/socks5.txt: ") || !strings.Contains(msg, c.want) {
			t.Errorf("HTTP %d: code %d err %q, want %q", c.status, code, msg, c.want)
		}
		if strings.Contains(msg, testKey[4:]) {
			t.Errorf("HTTP %d: the error shows the key: %q", c.status, msg)
		}
	}

	// Go's own transport error quotes the URL it asked.
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"fetch", "-base", "http://" + deadAddr(t)}, nil, &out, &errOut); code != 1 ||
		!strings.Contains(errOut.String(), "/k/"+maskedKey+"/v1/") || strings.Contains(errOut.String(), testKey[4:]) {
		t.Errorf("connection refused: code %d err %q", code, errOut.String())
	}
	errOut.Reset()
	if code := run(context.Background(), []string{"fetch", "-base", "http://192.0.2.1"}, nil, &out, &errOut); code != 2 ||
		!strings.Contains(errOut.String(), "https") || strings.Contains(errOut.String(), testKey[4:]) {
		t.Errorf("plain-http base: code %d err %q", code, errOut.String())
	}
}

// check's judge requests go through the proxies under test, so they never carry the key, even when the
// judge is the data host's /v1/ip.
func TestCheckNeverSendsTheKey(t *testing.T) {
	t.Setenv(keyEnv, testKey)
	judgeURL, requests := recordingFeed(t, http.StatusOK, nil, "203.0.113.9\n")
	saved := defaultBase
	defaultBase = judgeURL
	defer func() { defaultBase = saved }()
	socks, _ := startSOCKS5(t)
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"check", "-allow-private"}, strings.NewReader(socks+"\n"), &out, &errOut); code != 0 || strings.TrimSpace(out.String()) != socks {
		t.Fatalf("check exit %d: out %q err %q", code, out.String(), errOut.String())
	}
	if seen := requests(); len(seen) != 1 || seen[0].RequestURI != "/v1/ip" {
		t.Fatalf("want one judge request for /v1/ip, got %d (%v)", len(seen), seen)
	}
	if code := run(context.Background(), []string{"check", "-key", testKey}, strings.NewReader(""), &out, &errOut); code != 2 {
		t.Errorf("check takes no -key: exit %d", code)
	}
}

func TestResolveVersion(t *testing.T) {
	cases := []struct{ set, module, want string }{
		{"dev", "v0.1.0", "0.1.0"},   // go install …@v0.1.0
		{"dev", "(devel)", "dev"},    // a build from a checkout
		{"dev", "", "dev"},           // no build info
		{"0.2.0", "v0.1.0", "0.2.0"}, // -ldflags wins
	}
	for _, c := range cases {
		if got := resolveVersion(c.set, c.module); got != c.want {
			t.Errorf("resolveVersion(%q, %q) = %q, want %q", c.set, c.module, got, c.want)
		}
	}
}

func TestScrapeMergesAndSkipsBrokenSources(t *testing.T) {
	lists := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a.txt":
			io.WriteString(w, "203.0.113.7:1080\n198.51.100.4:4145\n")
		case "/b.txt":
			io.WriteString(w, "198.51.100.4:4145\n203.0.113.8:1080\n")
		default:
			http.NotFound(w, r)
		}
	}))
	defer lists.Close()
	sources := []source{
		{ID: "a", URL: lists.URL + "/a.txt", Protocol: "socks5", Publish: true},
		{ID: "b", URL: lists.URL + "/b.txt", Protocol: "socks5", Publish: true},
		{ID: "gone", URL: lists.URL + "/gone.txt", Protocol: "socks5", Publish: true},
		{ID: "h", URL: lists.URL + "/a.txt", Protocol: "http", Publish: true},
	}
	var notes []string
	got, err := scrape(context.Background(), http.DefaultClient, sources, "socks5", func(s string) { notes = append(notes, s) })
	if err != nil || len(got) != 3 {
		t.Fatalf("want 3 unique socks5 proxies, got %v (%v)", got, err)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "skip gone: HTTP 404") {
		t.Errorf("a broken source must be reported: %v", notes)
	}
}

// scrape reads only the lists whose licence lets us publish from them (publish: true).
// The others stay in the register for the record and are never requested.
func TestScrapeNeverRequestsUnpublishedSources(t *testing.T) {
	var hits sync.Map
	lists := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := hits.LoadOrStore(r.URL.Path, new(atomic.Int64))
		n.(*atomic.Int64).Add(1)
		io.WriteString(w, map[string]string{"/open.txt": "203.0.113.7:1080\n", "/closed.txt": "203.0.113.9:1080\n"}[r.URL.Path])
	}))
	defer lists.Close()
	sources := []source{
		{ID: "open", URL: lists.URL + "/open.txt", Protocol: "socks5", Publish: true},
		{ID: "closed", URL: lists.URL + "/closed.txt", Protocol: "socks5", Publish: false},
	}
	for _, protocol := range []string{"socks5", "all"} {
		got, err := scrape(context.Background(), http.DefaultClient, sources, protocol, func(string) {})
		if err != nil || len(got) != 1 || got[0].Host != "203.0.113.7" {
			t.Fatalf("%s: want only the published list's proxy, got %v (%v)", protocol, got, err)
		}
	}
	if n, ok := hits.Load("/closed.txt"); ok {
		t.Fatalf("an unpublished source was requested %d times", n.(*atomic.Int64).Load())
	}

	// The embedded register: every publish:false URL is never asked for, every publish:true one is.
	reg, err := loadSources()
	if err != nil {
		t.Fatal(err)
	}
	var asked sync.Map
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		asked.Store(r.URL.String(), true)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}
	if _, err := scrape(context.Background(), client, reg, "all", func(string) {}); err != nil {
		t.Fatal(err)
	}
	unpublished := 0
	for _, s := range reg {
		_, got := asked.Load(s.URL)
		if !s.Publish {
			unpublished++
		}
		if got != s.Publish {
			t.Errorf("%s (publish %v): requested %v", s.ID, s.Publish, got)
		}
	}
	if unpublished == 0 {
		t.Fatal("the register has no publish:false source, so this test proves nothing")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestEmbeddedSourcesMatchTheFeedRegister(t *testing.T) {
	feed, err := os.ReadFile("../feed/config/sources.json")
	if err != nil {
		t.Skip("feed register not present next to the CLI (standalone checkout)")
	}
	if !bytes.Equal(feed, sourcesJSON) {
		t.Fatal("cli/sources.json drifted from feed/config/sources.json; copy it again")
	}
	sources, err := loadSources()
	if err != nil || len(sources) == 0 {
		t.Fatalf("load: %v", err)
	}
	for _, s := range sources {
		if s.Protocol != "socks5" && s.Protocol != "http" {
			t.Errorf("%s: protocol %q", s.ID, s.Protocol)
		}
	}
}
