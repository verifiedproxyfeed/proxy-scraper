package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// dialSOCKS5 opens a CONNECT tunnel through a no-auth SOCKS5 proxy (RFC 1928).
// The target host name is sent to the proxy (remote DNS, like socks5h), so the
// local resolver never learns which sites are visited.
func dialSOCKS5(ctx context.Context, proxyConn net.Conn, target string) (net.Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		_ = proxyConn.SetDeadline(deadline)
		defer proxyConn.SetDeadline(timeZero)
	}
	if _, err := proxyConn.Write([]byte{5, 1, 0}); err != nil {
		return nil, err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(proxyConn, reply); err != nil {
		return nil, err
	}
	if reply[0] != 5 || reply[1] != 0 {
		return nil, errors.New("socks5: proxy requires authentication or is not SOCKS5")
	}

	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("socks5: bad port %q", portText)
	}
	if len(host) > 255 {
		return nil, errors.New("socks5: host name too long")
	}
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := proxyConn.Write(req); err != nil {
		return nil, err
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(proxyConn, head); err != nil {
		return nil, err
	}
	if head[1] != 0 {
		return nil, fmt.Errorf("socks5: connect failed with code %d", head[1])
	}
	var skip int
	switch head[3] {
	case 1:
		skip = 4 + 2
	case 4:
		skip = 16 + 2
	case 3:
		n := make([]byte, 1)
		if _, err := io.ReadFull(proxyConn, n); err != nil {
			return nil, err
		}
		skip = int(n[0]) + 2
	default:
		return nil, fmt.Errorf("socks5: bad address type %d", head[3])
	}
	if _, err := io.CopyN(io.Discard, proxyConn, int64(skip)); err != nil {
		return nil, err
	}
	return proxyConn, nil
}
