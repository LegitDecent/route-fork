package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	xproxy "golang.org/x/net/proxy"

	"rofk/proxy"
)

type Result struct {
	Host   string
	Port   int
	Open   bool
	Proxy  *proxy.Proxy // proxy that opened this connection (nil if direct)
	Banner string       // service banner grabbed at connect time (may be empty)
}

type Options struct {
	Ports       string
	Concurrency int
	Timeout     time.Duration
}

func DefaultOptions() Options {
	return Options{Ports: "1-65535", Concurrency: 200, Timeout: 5 * time.Second}
}

// ParsePorts converts a spec like "22,80,443,1000-2000" into a slice of port ints.
func ParsePorts(spec string) ([]int, error) {
	var ports []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, e1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			end, e2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if e1 != nil || e2 != nil || start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid range: %s", part)
			}
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			n, err := strconv.Atoi(part)
			if err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			ports = append(ports, n)
		}
	}
	return ports, nil
}

// ExpandTarget returns all host addresses for target.
// CIDR notation (e.g. "10.0.0.0/24") is expanded to individual host IPs.
// Plain hostnames and IPs are returned as a single-element slice.
func ExpandTarget(target string) ([]string, error) {
	if !strings.Contains(target, "/") {
		return []string{target}, nil
	}
	_, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", target, err)
	}
	var hosts []string
	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)
	for ipNet.Contains(ip) {
		hosts = append(hosts, ip.String())
		incIP(ip)
	}
	// Drop network address (first) and broadcast (last) for IPv4 subnets larger than /31
	ones, bits := ipNet.Mask.Size()
	if bits == 32 && (bits-ones) > 1 && len(hosts) > 2 {
		hosts = hosts[1 : len(hosts)-1]
	}
	return hosts, nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] > 0 {
			break
		}
	}
}

// Scan runs a TCP connect scan on each host:port combination derived from target and opts.
// target may be a single host/IP or a CIDR (e.g. "10.0.0.0/24").
// getProxy is called once per goroutine, enabling true per-connection proxy rotation.
func Scan(ctx context.Context, getProxy func() *proxy.Proxy, target string, opts Options,
	results chan<- Result, progress func(scanned, total int)) error {

	hosts, err := ExpandTarget(target)
	if err != nil {
		return err
	}

	ports, err := ParsePorts(opts.Ports)
	if err != nil {
		return err
	}

	total := len(hosts) * len(ports)
	var scanned atomic.Int64
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for _, host := range hosts {
		for _, port := range ports {
			select {
			case <-ctx.Done():
				wg.Wait()
				return ctx.Err()
			default:
			}

			sem <- struct{}{}
			wg.Add(1)
			go func(host string, port int) {
				defer wg.Done()
				defer func() { <-sem }()

				px := getProxy()
				dialer, err := buildDialer(px, opts.Timeout)
				if err != nil {
					scanned.Add(1)
					return
				}

				addr := fmt.Sprintf("%s:%d", host, port)
				connCh := make(chan net.Conn, 1)

				go func() {
					conn, err := dialer.Dial("tcp", addr)
					if err != nil {
						connCh <- nil
					} else {
						connCh <- conn
					}
				}()

				select {
				case <-ctx.Done():
				case <-time.After(opts.Timeout):
				case conn := <-connCh:
					if conn != nil {
						// Grab a short service banner before closing (services
						// that speak first, e.g. SSH/FTP/SMTP).
						var banner string
						conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
						bbuf := make([]byte, 256)
						bn, _ := conn.Read(bbuf)
						if bn > 0 {
							banner = CleanBanner(bbuf[:bn])
						}
						conn.Close()
						select {
						case results <- Result{Host: host, Port: port, Open: true, Proxy: px, Banner: banner}:
						case <-ctx.Done():
						}
					}
				}

				n := int(scanned.Add(1))
				if progress != nil {
					progress(n, total)
				}
			}(host, port)
		}
	}

	wg.Wait()
	return nil
}

// CompressPorts converts a slice of port numbers into a compact spec string like "22,80,443,1000-2000".
func CompressPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	sorted := make([]int, len(ports))
	copy(sorted, ports)
	sort.Ints(sorted)
	var parts []string
	start, end := sorted[0], sorted[0]
	for _, p := range sorted[1:] {
		if p == end+1 {
			end = p
		} else {
			if start == end {
				parts = append(parts, strconv.Itoa(start))
			} else {
				parts = append(parts, fmt.Sprintf("%d-%d", start, end))
			}
			start, end = p, p
		}
	}
	if start == end {
		parts = append(parts, strconv.Itoa(start))
	} else {
		parts = append(parts, fmt.Sprintf("%d-%d", start, end))
	}
	return strings.Join(parts, ",")
}

// MergePortSpecs merges two port spec strings, deduplicating and compressing the result.
func MergePortSpecs(a, b string) string {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "1-65535" || b == "1-65535" || a == "0-65535" || b == "0-65535" {
		return "1-65535"
	}
	set := make(map[int]bool)
	for _, spec := range []string{a, b} {
		if ports, err := ParsePorts(spec); err == nil {
			for _, p := range ports {
				set[p] = true
			}
		}
	}
	merged := make([]int, 0, len(set))
	for p := range set {
		merged = append(merged, p)
	}
	return CompressPorts(merged)
}

// buildDialer returns a net.Conn-producing Dialer that routes through the proxy.
func buildDialer(p *proxy.Proxy, timeout time.Duration) (xproxy.Dialer, error) {
	proxyAddr := p.Address()
	if p.Proto == "socks5" {
		var auth *xproxy.Auth
		if p.Username != "" {
			auth = &xproxy.Auth{User: p.Username, Password: p.Password}
		}
		base := &net.Dialer{Timeout: timeout}
		return xproxy.SOCKS5("tcp", proxyAddr, auth, base)
	}
	// SOCKS4 - implement our own dialer since x/net/proxy doesn't export one
	return &socks4Dialer{addr: proxyAddr, timeout: timeout}, nil
}

// socks4Dialer wraps a SOCKS4 proxy connection.
type socks4Dialer struct {
	addr    string
	timeout time.Duration
}

func (d *socks4Dialer) Dial(network, address string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", d.addr, d.timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(d.timeout))

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		conn.Close()
		return nil, err
	}

	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupHost(host)
		if err != nil || len(ips) == 0 {
			conn.Close()
			return nil, fmt.Errorf("socks4: DNS failed for %s", host)
		}
		ip = net.ParseIP(ips[0])
	}
	ip4 := ip.To4()
	if ip4 == nil {
		conn.Close()
		return nil, fmt.Errorf("socks4: IPv4 required, got %s", host)
	}

	req := []byte{0x04, 0x01, byte(port >> 8), byte(port),
		ip4[0], ip4[1], ip4[2], ip4[3], 0x00}
	if _, err = conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	resp := make([]byte, 8)
	if _, err = io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] != 0x5A {
		conn.Close()
		return nil, fmt.Errorf("socks4: rejected (code %02x)", resp[1])
	}

	conn.SetDeadline(time.Time{})
	return conn, nil
}
