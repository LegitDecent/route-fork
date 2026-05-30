package scanner

import "strings"

// wellKnownPorts maps the most common TCP port numbers to their IANA service name.
var wellKnownPorts = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain",
	80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
	139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
	445: "microsoft-ds", 465: "smtps", 587: "submission",
	636: "ldaps", 993: "imaps", 995: "pop3s",
	1080: "socks", 1194: "openvpn", 1433: "ms-sql-s", 1521: "oracle",
	1723: "pptp", 2049: "nfs", 2375: "docker", 2376: "docker-tls",
	3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql",
	5900: "vnc", 5985: "wsman", 5986: "wsmans",
	6379: "redis", 6443: "k8s-api",
	8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
	9200: "elasticsearch", 9300: "elasticsearch-tcp",
	27017: "mongodb", 27018: "mongodb-shard",
}

// PortService returns the common IANA service name for the given TCP port,
// or an empty string if the port is not in the well-known list.
func PortService(port int) string {
	return wellKnownPorts[port]
}

// CleanBanner strips non-printable bytes from a raw banner read.
// Control characters are replaced with a space; the result is trimmed.
func CleanBanner(raw []byte) string {
	var b strings.Builder
	b.Grow(len(raw))
	for _, c := range raw {
		if c >= 32 && c < 127 {
			b.WriteByte(c)
		} else if c == '\t' || c == '\n' || c == '\r' {
			b.WriteByte(' ')
		}
	}
	// Collapse runs of spaces
	s := b.String()
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	return strings.TrimSpace(s)
}
