// Package relay implements a local SOCKS4/4a→SOCKS4/5 bridge.
//
// nmap's --proxies flag accepts socks4:// but not socks5://.
// We start a throwaway listener on 127.0.0.1:0, hand nmap
// socks4://127.0.0.1:<port>, and forward every connection through
// the actual SOCKS4 or SOCKS5 proxy in the pool.
// Zero system dependencies — pure Go.
package relay

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"rofk/proxy"
)

// Relay is a running local SOCKS4 listener.
type Relay struct {
	ln      net.Listener
	px      *proxy.Proxy
	timeout time.Duration
}

// Start binds a random localhost port and begins serving.
// Returns the relay and its local address ("127.0.0.1:port").
func Start(px *proxy.Proxy, dialTimeout time.Duration) (*Relay, string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	r := &Relay{ln: ln, px: px, timeout: dialTimeout}
	go r.serve()
	return r, ln.Addr().String(), nil
}

// Stop shuts down the relay listener.
func (r *Relay) Stop() { r.ln.Close() }

func (r *Relay) serve() {
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			return
		}
		go r.handle(conn)
	}
}

// handle reads one SOCKS4/4a CONNECT request from the client (nmap),
// dials the real proxy, and splices the two connections together.
func (r *Relay) handle(client net.Conn) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(r.timeout))

	// ── SOCKS4 request header (8 bytes) ──────────────────────────────────
	// VER(1) CMD(1) PORT(2) IP(4)
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != 0x04 || hdr[1] != 0x01 { // must be SOCKS4 CONNECT
		return
	}

	dstPort := binary.BigEndian.Uint16(hdr[2:4])
	ipBytes := hdr[4:8]

	// Read null-terminated user-id (we don't use it, just drain it)
	if err := readUntilNull(client); err != nil {
		return
	}

	// ── Resolve target host ───────────────────────────────────────────────
	// SOCKS4a: IP field is 0.0.0.x (x ≠ 0) → hostname follows userid
	var dstHost string
	if ipBytes[0] == 0 && ipBytes[1] == 0 && ipBytes[2] == 0 && ipBytes[3] != 0 {
		host, err := readStringUntilNull(client)
		if err != nil {
			return
		}
		dstHost = host
	} else {
		dstHost = net.IP(ipBytes).String()
	}

	// ── Dial the real proxy and tunnel to target ──────────────────────────
	upstream, err := r.dialUpstream(dstHost, int(dstPort))
	if err != nil {
		// SOCKS4 rejection reply
		client.Write(socks4Reply(0x5B, dstPort, ipBytes))
		return
	}
	defer upstream.Close()

	// SOCKS4 success reply
	if _, err := client.Write(socks4Reply(0x5A, dstPort, ipBytes)); err != nil {
		return
	}

	// Clear deadline before the bidirectional splice
	client.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})

	errc := make(chan struct{}, 2)
	go func() { io.Copy(upstream, client); errc <- struct{}{} }()
	go func() { io.Copy(client, upstream); errc <- struct{}{} }()
	<-errc
}

// dialUpstream opens a connection through px to dstHost:dstPort.
func (r *Relay) dialUpstream(dstHost string, dstPort int) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", r.px.Address(), r.timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(r.timeout))

	if r.px.Proto == "socks5" {
		if err := socks5Connect(conn, dstHost, dstPort, r.px.Username, r.px.Password); err != nil {
			conn.Close()
			return nil, err
		}
	} else {
		if err := socks4aConnect(conn, dstHost, dstPort); err != nil {
			conn.Close()
			return nil, err
		}
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}

// ── SOCKS5 outbound handshake ─────────────────────────────────────────────────

func socks5Connect(conn net.Conn, host string, port int, user, pass string) error {
	var greeting []byte
	if user != "" {
		greeting = []byte{0x05, 0x02, 0x00, 0x02}
	} else {
		greeting = []byte{0x05, 0x01, 0x00}
	}
	if _, err := conn.Write(greeting); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("not a SOCKS5 server")
	}
	switch resp[1] {
	case 0xFF:
		return fmt.Errorf("no acceptable auth method")
	case 0x02:
		if user == "" {
			return fmt.Errorf("auth required")
		}
		ub, pb := []byte(user), []byte(pass)
		msg := append([]byte{0x01, byte(len(ub))}, ub...)
		msg = append(msg, byte(len(pb)))
		msg = append(msg, pb...)
		if _, err := conn.Write(msg); err != nil {
			return err
		}
		ar := make([]byte, 2)
		if _, err := io.ReadFull(conn, ar); err != nil {
			return err
		}
		if ar[1] != 0x00 {
			return fmt.Errorf("authentication failed")
		}
	}

	hb := []byte(host)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(hb))}
	req = append(req, hb...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}

	// Read variable-length response
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[1] != 0x00 {
		msgs := map[byte]string{
			0x01: "general failure", 0x02: "not allowed",
			0x03: "network unreachable", 0x04: "host unreachable",
			0x05: "connection refused",
		}
		if m, ok := msgs[hdr[1]]; ok {
			return fmt.Errorf("SOCKS5: %s", m)
		}
		return fmt.Errorf("SOCKS5 error %#02x", hdr[1])
	}
	// Drain the bound address from the response
	switch hdr[3] {
	case 0x01: // IPv4
		io.ReadFull(conn, make([]byte, 4+2))
	case 0x03: // domain
		lb := make([]byte, 1)
		io.ReadFull(conn, lb)
		io.ReadFull(conn, make([]byte, int(lb[0])+2))
	case 0x04: // IPv6
		io.ReadFull(conn, make([]byte, 16+2))
	}
	return nil
}

// ── SOCKS4a outbound handshake ────────────────────────────────────────────────

func socks4aConnect(conn net.Conn, host string, port int) error {
	// SOCKS4a: put 0.0.0.1 as the IP so the proxy knows to expect a hostname
	req := []byte{
		0x04, 0x01,
		byte(port >> 8), byte(port),
		0x00, 0x00, 0x00, 0x01, // 0.0.0.1 → SOCKS4a marker
		0x00,                    // empty user-id (null-terminated)
	}
	req = append(req, []byte(host)...)
	req = append(req, 0x00) // null-terminate hostname

	if _, err := conn.Write(req); err != nil {
		return err
	}
	resp := make([]byte, 8)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x5A {
		return fmt.Errorf("SOCKS4a rejected (code %02x)", resp[1])
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func readUntilNull(r io.Reader) error {
	b := make([]byte, 1)
	for {
		if _, err := r.Read(b); err != nil {
			return err
		}
		if b[0] == 0x00 {
			return nil
		}
	}
}

func readStringUntilNull(r io.Reader) (string, error) {
	b := make([]byte, 1)
	var out []byte
	for {
		if _, err := r.Read(b); err != nil {
			return "", err
		}
		if b[0] == 0x00 {
			return string(out), nil
		}
		out = append(out, b[0])
	}
}

func socks4Reply(code byte, port uint16, ip []byte) []byte {
	r := make([]byte, 8)
	r[0] = 0x00
	r[1] = code
	binary.BigEndian.PutUint16(r[2:4], port)
	copy(r[4:8], ip)
	return r
}

// NmapProxyArg starts the relay and returns the --proxies flag value
// nmap should receive: "socks4://127.0.0.1:<port>".
// Caller must call stop() when the scan finishes.
func NmapProxyArg(px *proxy.Proxy, dialTimeout time.Duration) (arg string, stop func(), err error) {
	r, addr, err := Start(px, dialTimeout)
	if err != nil {
		return "", nil, err
	}
	host, portStr, _ := net.SplitHostPort(addr)
	return "socks4://" + host + ":" + portStr, r.Stop, nil
}

// ensure strconv is used
var _ = strconv.Itoa
