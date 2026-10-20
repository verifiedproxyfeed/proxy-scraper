package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// Address guard (the rule the feed's own checker follows): a proxy list is
// untrusted input, so `check` never dials loopback, private, link-local, CGNAT,
// multicast, benchmarking or reserved space unless the user opts in for a lab.
var blockedPrefixes = mustPrefixes(
	"0.0.0.0/8",      // "this network"
	"10.0.0.0/8",     // RFC 1918
	"100.64.0.0/10",  // CGNAT
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link-local, incl. cloud metadata 169.254.169.254
	"172.16.0.0/12",  // RFC 1918
	"192.0.0.0/24",   // IETF protocol assignments
	"192.168.0.0/16", // RFC 1918
	"198.18.0.0/15",  // benchmarking
	"224.0.0.0/4",    // multicast
	"240.0.0.0/4",    // reserved, incl. broadcast
	"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "100::/64",
)

func mustPrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// isPublic reports whether addr may be dialed. The zone is dropped because
// netip.Prefix.Contains never matches a zoned address (fe80::1%eth0 would pass).
func isPublic(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// guardedDial resolves host, rejects any non-public address, and dials the first
// allowed one. Checking after resolution closes the "hostname that points inside" hole.
func guardedDial(ctx context.Context, dialer *net.Dialer, allowPrivate bool, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		if allowPrivate || isPublic(a) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
		}
	}
	return nil, fmt.Errorf("refused: %s resolves only to non-public addresses (use -allow-private for a lab)", host)
}
