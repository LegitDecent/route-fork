package scanner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseBanner(t *testing.T) {
	cases := []struct {
		name        string
		port        int
		raw         string
		wantService string
		wantVerSub  string // substring expected in version ("" => version must be empty)
	}{
		{"ssh", 22, "SSH-2.0-OpenSSH_9.6p1 Debian-5\r\n", "ssh", "OpenSSH_9.6p1"},
		{"http server header", 80, "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Type: text/html\r\n\r\n", "http", "nginx/1.25.3"},
		{"http no server header", 80, "HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n", "http", ""},
		{"ftp", 21, "220 ProFTPD 1.3.8 Server ready\r\n", "ftp", "ProFTPD 1.3.8"},
		{"smtp esmtp", 25, "220 mail.example.com ESMTP Postfix\r\n", "smtp", "Postfix"},
		{"pop3", 110, "+OK Dovecot ready.\r\n", "pop3", "Dovecot"},
		{"imap", 143, "* OK [CAPABILITY IMAP4rev1] Dovecot ready\r\n", "imap", "Dovecot"},
		{"unknown", 9999, "random noise here", "", ""},
		{"empty", 80, "   ", "", ""},
		{"generic 220 unclassified", 12345, "220 welcome\r\n", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc, ver := ParseBanner(c.port, c.raw)
			if svc != c.wantService {
				t.Fatalf("service = %q, want %q", svc, c.wantService)
			}
			if c.wantVerSub == "" {
				if ver != "" {
					t.Fatalf("version = %q, want empty", ver)
				}
			} else if !strings.Contains(ver, c.wantVerSub) {
				t.Fatalf("version = %q, want substring %q", ver, c.wantVerSub)
			}
		})
	}
}

func TestIdentifyService_PassiveBanner(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		_, _ = server.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
		// keep open briefly so the client read wins
		time.Sleep(50 * time.Millisecond)
	}()
	svc, ver, banner := IdentifyService(client, "h", 22, 300*time.Millisecond)
	if svc != "ssh" || !strings.Contains(ver, "OpenSSH_9.6") {
		t.Fatalf("got (%q,%q), want ssh/OpenSSH_9.6", svc, ver)
	}
	if !strings.Contains(banner, "SSH-2.0") {
		t.Fatalf("banner = %q", banner)
	}
}

func TestIdentifyService_SilentHTTP(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		buf := make([]byte, 512)
		_, _ = server.Read(buf) // consume the GET request
		_, _ = server.Write([]byte("HTTP/1.1 200 OK\r\nServer: Apache/2.4.59\r\n\r\n<html>"))
		time.Sleep(50 * time.Millisecond)
	}()
	// Port 80 server stays silent until requested => passive read times out,
	// then the active HTTP probe identifies it.
	svc, ver, _ := IdentifyService(client, "h", 80, 200*time.Millisecond)
	if svc != "http" || !strings.Contains(ver, "Apache/2.4.59") {
		t.Fatalf("got (%q,%q), want http/Apache", svc, ver)
	}
}

func TestIdentifyService_TLS(t *testing.T) {
	cert := selfSignedCert(t, "test.example")
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		srv := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}})
		_ = srv.Handshake()
		time.Sleep(50 * time.Millisecond)
	}()
	svc, ver, info := IdentifyService(client, "test.example", 443, 2*time.Second)
	if svc != "ssl" {
		t.Fatalf("service = %q, want ssl", svc)
	}
	if !strings.HasPrefix(ver, "TLS") {
		t.Fatalf("version = %q, want TLS...", ver)
	}
	if !strings.Contains(info, "test.example") {
		t.Fatalf("info = %q, want CN test.example", info)
	}
}

func TestIdentifyService_TLSPortNotTLS(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		defer server.Close()
		// Plaintext on a TLS port: handshake must fail, fall back to static name.
		_, _ = server.Write([]byte("not tls\r\n"))
		time.Sleep(50 * time.Millisecond)
	}()
	svc, _, _ := IdentifyService(client, "h", 443, 200*time.Millisecond)
	if svc != PortService(443) {
		t.Fatalf("service = %q, want static %q", svc, PortService(443))
	}
}

// selfSignedCert returns a throwaway TLS certificate for tests.
func selfSignedCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}
