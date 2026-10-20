// Command proxy-scraper: fetch the verified feed, scrape public proxy lists, and
// check proxies from your own machine.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

var (
	// version is set at release with -ldflags "-X main.version=0.1.0"; a `go install`
	// build has no -ldflags and reports its module version instead (resolveVersion).
	version = "dev"
	// defaultBase is the feed's data host, so a `go install` build works without flags.
	// -ldflags "-X main.defaultBase=https://<data-host>" still overrides it.
	defaultBase = "https://api.proxyscraper.com"
)

const usage = `proxy-scraper — free proxies you can trust a little more

Usage:
  proxy-scraper fetch  [-protocol socks5|http] [-max-latency 500|1000|1500|5000] [-format ipport|uri|json] [-stable]
  proxy-scraper scrape [-protocol socks5|http|all]
  proxy-scraper check  [-protocol socks5|http] [-judge URL] [-timeout 10s] [-concurrency 50] [-format ipport|uri|json] [file]
  proxy-scraper version

fetch   prints the verified list (every row passed a check within 15 minutes before its snapshot).
scrape  downloads the public source lists and prints unique ip:port, unchecked.
check   tests proxies from stdin or a file through an HTTPS judge with certificate verification
        and prints the working ones, fastest first. Internal addresses are refused.

Example:
  proxy-scraper scrape -protocol socks5 | proxy-scraper check -protocol socks5 > working.txt
`

func main() {
	if info, ok := debug.ReadBuildInfo(); ok {
		version = resolveVersion(version, info.Main.Version)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "fetch":
		err = cmdFetch(ctx, args[1:], stdout)
	case "scrape":
		err = cmdScrape(ctx, args[1:], stdout, stderr)
	case "check":
		err = cmdCheck(ctx, args[1:], stdin, stdout, stderr)
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, "proxy-scraper", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	var u usageError
	if errors.As(err, &u) {
		fmt.Fprintf(stderr, "%v\n", err)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

// resolveVersion keeps a version set by -ldflags. Otherwise it takes the module version that
// `go install …@v0.1.0` records ("v0.1.0" → "0.1.0", the form release builds use, so the
// User-Agent is the same either way); a build from a checkout records "(devel)" and stays "dev".
func resolveVersion(set, module string) string {
	if set != "dev" || module == "" || module == "(devel)" {
		return set
	}
	return strings.TrimPrefix(module, "v")
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func oneOf(name, value string, allowed ...string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return usageError{fmt.Sprintf("-%s must be one of %s, got %q", name, strings.Join(allowed, ", "), value)}
}

func cmdFetch(ctx context.Context, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	protocol := fs.String("protocol", "socks5", "socks5 or http")
	maxLatency := fs.String("max-latency", "", "500, 1000, 1500 or 5000 (ms)")
	format := fs.String("format", "ipport", "ipport, uri or json")
	stable := fs.Bool("stable", false, "only proxies up ≥90% of the last 7 days")
	base := fs.String("base", defaultBase, "data host base URL")
	if err := fs.Parse(args); err != nil {
		return usageError{err.Error()}
	}
	if err := oneOf("protocol", *protocol, "socks5", "http"); err != nil {
		return err
	}
	if err := oneOf("format", *format, "ipport", "uri", "json"); err != nil {
		return err
	}
	if *maxLatency != "" {
		if err := oneOf("max-latency", *maxLatency, "500", "1000", "1500", "5000"); err != nil {
			return err
		}
		if *stable {
			return usageError{"-stable lists have no latency filter"}
		}
	}
	if *base == "" {
		return usageError{"no data host configured in this build; pass -base https://<data-host>"}
	}
	target, err := feedURL(*base, *protocol, *maxLatency, *format, *stable)
	if err != nil {
		return err
	}
	body, err := get(ctx, http.DefaultClient, target, 16<<20)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", target, err)
	}
	_, err = stdout.Write(body)
	return err
}

// feedURL builds a URL of the published /v1 contract.
func feedURL(base, protocol, maxLatency, format string, stable bool) (string, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", usageError{fmt.Sprintf("-base must be an http(s) URL, got %q", base)}
	}
	ext := "txt"
	if format == "json" {
		ext = "json"
	}
	if stable {
		u.Path += "/v1/" + protocol + "/stable." + ext
	} else {
		u.Path += "/v1/" + protocol + "." + ext
	}
	q := url.Values{}
	if maxLatency != "" {
		q.Set("max_latency", maxLatency)
	}
	if format == "uri" {
		q.Set("format", "uri")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func cmdScrape(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("scrape", flag.ContinueOnError)
	protocol := fs.String("protocol", "all", "socks5, http or all")
	quiet := fs.Bool("q", false, "no per-source report on stderr")
	if err := fs.Parse(args); err != nil {
		return usageError{err.Error()}
	}
	if err := oneOf("protocol", *protocol, "socks5", "http", "all"); err != nil {
		return err
	}
	report := func(line string) {
		if !*quiet {
			fmt.Fprintln(stderr, line)
		}
	}
	sources, err := loadSources()
	if err != nil {
		return err
	}
	proxies, err := scrape(ctx, &http.Client{}, sources, *protocol, report)
	if err != nil {
		return err
	}
	for _, p := range proxies {
		if *protocol == "all" {
			fmt.Fprintln(stdout, p.URI())
		} else {
			fmt.Fprintln(stdout, p.Address())
		}
	}
	return nil
}

func cmdCheck(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	protocol := fs.String("protocol", "socks5", "protocol for lines without a scheme: socks5 or http")
	judge := fs.String("judge", "", "HTTPS URL fetched through each proxy (default: the data host's /v1/ip)")
	timeout := fs.Duration("timeout", 10*time.Second, "per-proxy timeout")
	concurrency := fs.Int("concurrency", 50, "parallel checks (1-500)")
	format := fs.String("format", "ipport", "ipport, uri or json")
	allowPrivate := fs.Bool("allow-private", false, "allow internal addresses (your own lab only)")
	if err := fs.Parse(args); err != nil {
		return usageError{err.Error()}
	}
	if err := oneOf("protocol", *protocol, "socks5", "http"); err != nil {
		return err
	}
	if err := oneOf("format", *format, "ipport", "uri", "json"); err != nil {
		return err
	}
	if *concurrency < 1 || *concurrency > 500 {
		return usageError{"-concurrency must be 1-500"}
	}
	if *timeout <= 0 || *timeout > 2*time.Minute {
		return usageError{"-timeout must be between 0 and 2m"}
	}
	if *judge == "" {
		if defaultBase == "" {
			return usageError{"no judge configured in this build; pass -judge https://<any https URL you trust>"}
		}
		*judge = strings.TrimRight(defaultBase, "/") + "/v1/ip"
	}
	if j, err := url.Parse(*judge); err != nil || (j.Scheme != "https" && j.Scheme != "http") || j.Host == "" {
		return usageError{fmt.Sprintf("-judge must be an http(s) URL, got %q", *judge)}
	}

	input := stdin
	if fs.NArg() > 0 {
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			return err
		}
		defer f.Close()
		input = f
	}
	proxies, err := parseProxies(input, *protocol)
	if err != nil {
		return err
	}
	working := checkAll(ctx, proxies, *judge, *timeout, *concurrency, *allowPrivate, nil)
	limited := 0
	for _, r := range working {
		if r.JudgeLimited {
			limited++
		}
	}
	if limited > 0 {
		fmt.Fprintf(stderr, "%d of %d working (%d through a judge that answered HTTP 429 over verified TLS: the tunnel worked, the judge limited the rate)\n", len(working), len(proxies), limited)
	} else {
		fmt.Fprintf(stderr, "%d of %d working\n", len(working), len(proxies))
	}
	enc := json.NewEncoder(stdout)
	for _, r := range working {
		switch *format {
		case "uri":
			fmt.Fprintln(stdout, r.URI())
		case "json":
			_ = enc.Encode(map[string]any{"ip": r.Host, "port": mustPort(r.Port), "protocol": r.Protocol, "latency_ms": r.LatencyMs})
		default:
			fmt.Fprintln(stdout, r.Address())
		}
	}
	return nil
}

func mustPort(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
