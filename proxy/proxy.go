package proxy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Status int

const (
	StatusPending Status = iota
	StatusValid
	StatusInvalid
)

type Proxy struct {
	Host     string
	Port     int
	Proto    string // "socks4" | "socks5"
	Username string
	Password string

	LatencyMs  float64
	Status     Status
	FailReason string
}

func (p *Proxy) Address() string {
	return fmt.Sprintf("%s:%d", p.Host, p.Port)
}

func (p *Proxy) URI() string {
	if p.Username != "" {
		return fmt.Sprintf("%s://%s:%s@%s:%d", p.Proto, p.Username, p.Password, p.Host, p.Port)
	}
	return fmt.Sprintf("%s://%s:%d", p.Proto, p.Host, p.Port)
}

func (p *Proxy) DisplayValid() string {
	return fmt.Sprintf("%-24s  %-7s  %.0f ms", p.Address(), p.Proto, p.LatencyMs)
}

func (p *Proxy) DisplayFailed() string {
	return fmt.Sprintf("%-24s  %-7s  %s", p.Address(), p.Proto, p.FailReason)
}

var uriRE = regexp.MustCompile(`(?i)^(socks[45])://(?:([^:@\s]+):([^@\s]*)@)?([^:\s]+):(\d+)$`)

func ParseLine(line string) *Proxy {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	if m := uriRE.FindStringSubmatch(line); m != nil {
		port, _ := strconv.Atoi(m[5])
		if port < 1 || port > 65535 {
			return nil
		}
		return &Proxy{
			Proto: strings.ToLower(m[1]), Username: m[2],
			Password: m[3], Host: m[4], Port: port,
		}
	}

	parts := strings.Split(line, ":")
	switch len(parts) {
	case 4:
		port, err := strconv.Atoi(parts[1])
		if err != nil || port < 1 || port > 65535 {
			break
		}
		return &Proxy{Host: parts[0], Port: port, Proto: "socks5",
			Username: parts[2], Password: parts[3]}
	case 2:
		port, err := strconv.Atoi(parts[1])
		if err != nil || port < 1 || port > 65535 {
			break
		}
		return &Proxy{Host: parts[0], Port: port, Proto: "socks5"}
	}

	sp := strings.Fields(line)
	if len(sp) == 2 {
		port, err := strconv.Atoi(sp[1])
		if err == nil && port >= 1 && port <= 65535 {
			return &Proxy{Host: sp[0], Port: port, Proto: "socks5"}
		}
	}
	return nil
}

func ParseAll(text string) []*Proxy {
	seen := make(map[string]bool)
	var out []*Proxy
	for _, line := range strings.Split(text, "\n") {
		p := ParseLine(line)
		if p == nil {
			continue
		}
		key := fmt.Sprintf("%s:%d:%s", p.Host, p.Port, p.Proto)
		if !seen[key] {
			seen[key] = true
			out = append(out, p)
		}
	}
	return out
}
