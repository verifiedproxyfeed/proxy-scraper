package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// sources.json is a byte-for-byte copy of ../feed/config/sources.json; a test fails if
// they drift, so the CLI scrapes exactly the register the feed uses.
//
//go:embed sources.json
var sourcesJSON []byte

type source struct {
	ID       string `json:"id"`
	URL      string `json:"url"`
	Protocol string `json:"protocol"`
	Licence  string `json:"licence"`
	Publish  bool   `json:"publish"`
}

func loadSources() ([]source, error) {
	var reg struct {
		Sources []source `json:"sources"`
	}
	if err := json.Unmarshal(sourcesJSON, &reg); err != nil {
		return nil, err
	}
	// An "https" list holds HTTP proxies that tunnel TLS (CONNECT); the checker and the feed read it as HTTP too.
	for i := range reg.Sources {
		if reg.Sources[i].Protocol == "https" {
			reg.Sources[i].Protocol = "http"
		}
	}
	return reg.Sources, nil
}

// scrape downloads every source marked publish (its licence lets the feed publish from it) for the
// protocol(s) and returns unique proxies. The register keeps the other sources for the record; they are
// never requested. Each list is fetched once with a bounded size; one failing source is reported, not fatal.
func scrape(ctx context.Context, client *http.Client, sources []source, protocol string, report func(string)) ([]Proxy, error) {
	var all []Proxy
	seen := map[string]bool{}
	for _, s := range sources {
		if !s.Publish || (protocol != "all" && s.Protocol != protocol) {
			continue
		}
		body, err := get(ctx, client, s.URL, 8<<20)
		if err != nil {
			report(fmt.Sprintf("skip %s: %v", s.ID, err))
			continue
		}
		list, err := parseProxies(bytes.NewReader(body), s.Protocol)
		if err != nil {
			report(fmt.Sprintf("skip %s: %v", s.ID, err))
			continue
		}
		report(fmt.Sprintf("%s: %d", s.ID, len(list)))
		for _, p := range list {
			if !seen[p.URI()] {
				seen[p.URI()] = true
				all = append(all, p)
			}
		}
	}
	return all, nil
}

// statusError is an answer other than 200. Its text is v0.1.0's ("HTTP 404"); fetch -key reads the
// status and Retry-After to explain a keyed refusal.
type statusError struct {
	code   int
	header http.Header
}

func (e *statusError) Error() string { return fmt.Sprintf("HTTP %d", e.code) }

func get(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "proxy-scraper-cli/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &statusError{code: resp.StatusCode, header: resp.Header}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return body, nil
}
