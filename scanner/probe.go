package scanner

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// tlsPorts and httpPorts hint how to actively probe a silent service. They are
// hints only: identification still falls back to the static service name.
var tlsPorts = map[int]bool{
	443: true, 8443: true, 993: true, 995: true, 465: true,
	990: true, 636: true, 989: true, 992: true, 994: true, 9443: true,
}

var httpPorts = map[int]bool{
	80: true, 81: true, 591: true, 3000: true, 5000: true,
	8000: true, 8008: true, 8080: true, 8081: true, 8888: true,
}

// IdentifyService inspects an open connection and returns a refined service
// name, a version/detail string, and any raw banner observed. It is best-effort
// and time-bounded: TLS ports get a handshake, services that speak first get a
// passive read, and silent HTTP ports get one GET request. When nothing can be
// learned it falls back to the static port-to-service name.
//
// The connection is consumed (read/written) but not closed; the caller closes.
func IdentifyService(conn net.Conn, host string, port int, timeout time.Duration) (service, version, banner string) {
	if tlsPorts[port] {
		if s, v, info := probeTLS(conn, host, timeout); s != "" {
			return s, v, info
		}
		// TLS handshake failed: the connection is now unusable, so don't try a
		// plaintext read on it. Report the static name.
		return PortService(port), "", ""
	}

	banner = readBanner(conn, timeout)
	if banner != "" {
		if s, v := ParseBanner(port, banner); s != "" {
			return s, v, banner
		}
		return PortService(port), "", banner
	}

	// Silent server: actively poke likely HTTP ports.
	if httpPorts[port] {
		if resp := probeHTTP(conn, host, timeout); resp != "" {
			if s, v := ParseBanner(port, resp); s != "" {
				return s, v, firstLine(resp)
			}
		}
	}
	return PortService(port), "", ""
}

// readBanner reads whatever a server volunteers within a short window.
func readBanner(conn net.Conn, timeout time.Duration) string {
	d := 800 * time.Millisecond
	if timeout > 0 && timeout < d {
		d = timeout
	}
	_ = conn.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n > 0 {
		return CleanBanner(buf[:n])
	}
	return ""
}

// probeHTTP sends a minimal request and returns the response head (status line
// plus headers, cleaned), or "" on failure.
func probeHTTP(conn net.Conn, host string, timeout time.Duration) string {
	if host == "" {
		host = "scan"
	}
	d := 2 * time.Second
	if timeout > 0 {
		d = timeout
	}
	_ = conn.SetWriteDeadline(time.Now().Add(d))
	req := "GET / HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: rofk\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return ""
	}
	_ = conn.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	if n == 0 {
		return ""
	}
	// Return the raw response head: header line structure must survive for
	// httpServer() to find the Server: header (CleanBanner would flatten it).
	return string(buf[:n])
}

// probeTLS performs a TLS handshake and reports the negotiated version and the
// certificate's subject. Returns ("","","") if the peer does not speak TLS.
func probeTLS(conn net.Conn, host string, timeout time.Duration) (service, version, info string) {
	d := 5 * time.Second
	if timeout > 0 {
		d = timeout
	}
	_ = conn.SetDeadline(time.Now().Add(d))
	tc := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //#nosec G402 -- scanner: we inspect the cert, never trust it
		ServerName:         host,
	})
	if err := tc.Handshake(); err != nil {
		return "", "", ""
	}
	st := tc.ConnectionState()
	ver := tlsVersionName(st.Version)
	subject := ""
	if len(st.PeerCertificates) > 0 {
		subject = st.PeerCertificates[0].Subject.CommonName
	}
	info = ver
	if subject != "" {
		info += " (CN=" + subject + ")"
	}
	return "ssl", ver, info
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS10:
		return "TLSv1.0"
	default:
		return fmt.Sprintf("TLS(0x%04x)", v)
	}
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// ParseBanner derives a service name and version string from a raw banner (or
// an HTTP response head). Returns ("","") when the banner is unrecognised, so
// the caller can fall back to the static port name.
func ParseBanner(port int, raw string) (service, version string) {
	b := strings.TrimSpace(raw)
	if b == "" {
		return "", ""
	}
	upper := strings.ToUpper(b)

	switch {
	case strings.HasPrefix(b, "SSH-"):
		// SSH-2.0-OpenSSH_9.6p1 Debian-...
		parts := strings.SplitN(b, "-", 3)
		v := ""
		if len(parts) == 3 {
			v = strings.TrimSpace(parts[2])
		}
		return "ssh", v

	case strings.HasPrefix(upper, "HTTP/"):
		return "http", httpServer(raw)

	case strings.HasPrefix(b, "220") && strings.Contains(upper, "FTP"):
		return "ftp", afterCode(b)

	case strings.HasPrefix(b, "220") && (strings.Contains(upper, "SMTP") || strings.Contains(upper, "ESMTP") || strings.Contains(upper, "MAIL")):
		return "smtp", afterCode(b)

	case strings.HasPrefix(b, "+OK"):
		return "pop3", strings.TrimSpace(strings.TrimPrefix(b, "+OK"))

	case strings.HasPrefix(b, "* OK") && strings.Contains(upper, "IMAP"):
		return "imap", strings.TrimSpace(strings.TrimPrefix(b, "* OK"))

	case strings.HasPrefix(b, "220 ") || strings.HasPrefix(b, "220-"):
		// Generic 220 greeting we couldn't classify further.
		return "", ""
	}
	return "", ""
}

// httpServer extracts the Server header value from an HTTP response head.
func httpServer(resp string) string {
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		if len(line) >= 7 && strings.EqualFold(line[:7], "server:") {
			return strings.TrimSpace(line[7:])
		}
	}
	return ""
}

// afterCode returns the text after a leading 3-digit reply code (e.g. "220 ").
func afterCode(b string) string {
	if len(b) > 4 && (b[3] == ' ' || b[3] == '-') {
		return strings.TrimSpace(b[4:])
	}
	return strings.TrimSpace(b)
}
