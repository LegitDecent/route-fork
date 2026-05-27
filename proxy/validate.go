package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// Validate performs a raw SOCKS4/5 handshake to verify the proxy is alive.
// Returns success, latency in ms, and an error string.
func Validate(p *Proxy, timeout time.Duration, testHost string, testPort int) (bool, float64, string) {
	t0 := time.Now()

	conn, err := net.DialTimeout("tcp", p.Address(), timeout)
	if err != nil {
		return false, 0, err.Error()
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	var ok bool
	var errStr string
	if p.Proto == "socks5" {
		ok, errStr = socks5Handshake(conn, testHost, testPort, p.Username, p.Password)
	} else {
		ok, errStr = socks4Handshake(conn, testHost, testPort)
	}

	if ok {
		return true, float64(time.Since(t0).Milliseconds()), ""
	}
	return false, 0, errStr
}

func socks5Handshake(conn net.Conn, host string, port int, user, pass string) (bool, string) {
	var greeting []byte
	if user != "" {
		greeting = []byte{0x05, 0x02, 0x00, 0x02}
	} else {
		greeting = []byte{0x05, 0x01, 0x00}
	}
	if _, err := conn.Write(greeting); err != nil {
		return false, err.Error()
	}

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		return false, err.Error()
	}
	if resp[0] != 0x05 {
		return false, "not a SOCKS5 server"
	}

	switch resp[1] {
	case 0xFF:
		return false, "no acceptable auth method"
	case 0x02:
		if user == "" {
			return false, "auth required but no credentials"
		}
		ub, pb := []byte(user), []byte(pass)
		msg := append([]byte{0x01, byte(len(ub))}, ub...)
		msg = append(msg, byte(len(pb)))
		msg = append(msg, pb...)
		if _, err := conn.Write(msg); err != nil {
			return false, err.Error()
		}
		ar := make([]byte, 2)
		if _, err := conn.Read(ar); err != nil {
			return false, err.Error()
		}
		if ar[1] != 0x00 {
			return false, "authentication failed"
		}
	}

	hb := []byte(host)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(hb))}
	req = append(req, hb...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return false, err.Error()
	}

	buf := make([]byte, 262)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return false, "no CONNECT response"
	}
	if buf[1] != 0x00 {
		codes := map[byte]string{
			0x01: "general failure", 0x02: "not allowed", 0x03: "network unreachable",
			0x04: "host unreachable", 0x05: "connection refused", 0x06: "TTL expired",
		}
		if m, ok := codes[buf[1]]; ok {
			return false, m
		}
		return false, fmt.Sprintf("SOCKS5 error %#02x", buf[1])
	}
	return true, ""
}

func socks4Handshake(conn net.Conn, host string, port int) (bool, string) {
	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			return false, "DNS resolution failed"
		}
		ip = net.ParseIP(addrs[0])
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false, "SOCKS4 requires IPv4"
	}

	req := make([]byte, 9)
	req[0] = 0x04
	req[1] = 0x01
	binary.BigEndian.PutUint16(req[2:4], uint16(port))
	copy(req[4:8], ip4)
	req[8] = 0x00

	if _, err := conn.Write(req); err != nil {
		return false, err.Error()
	}

	resp := make([]byte, 8)
	if _, err := conn.Read(resp); err != nil {
		return false, err.Error()
	}
	if resp[1] == 0x5A {
		return true, ""
	}
	codes := map[byte]string{
		0x5B: "request rejected", 0x5C: "cannot connect to identd", 0x5D: "identd mismatch",
	}
	if m, ok := codes[resp[1]]; ok {
		return false, m
	}
	return false, fmt.Sprintf("SOCKS4 code %#02x", resp[1])
}
