package gui

import (
	"bufio"
	"context"
	"os/exec"
	"regexp"
	"strings"
)

// execRun streams cmd stdout+stderr to log line-by-line.
func execRun(ctx context.Context, cmd []string, log func(string)) {
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	stdout, err := c.StdoutPipe()
	if err != nil {
		log("[-] pipe: " + err.Error() + "\n")
		return
	}
	c.Stderr = c.Stdout
	if err := c.Start(); err != nil {
		log("[-] start: " + err.Error() + "\n")
		return
	}
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		log("  " + sc.Text() + "\n")
	}
	c.Wait()
}

// openPortRE matches lines like "80/tcp   open  http"
var openPortRE = regexp.MustCompile(`(\d+)/(tcp|udp)\s+open`)

// nmapReportRE matches "Nmap scan report for 1.2.3.4" or "Nmap scan report for hostname (1.2.3.4)"
var nmapReportRE = regexp.MustCompile(`Nmap scan report for (\S+)`)

// Finding records a single open-port result from a scan.
type Finding struct {
	Host     string   // IP/hostname from "Nmap scan report for X" (empty if unknown)
	Line     string   // port line: "80/tcp   open  http" or full nmap line
	ProxyURI string   // primary proxy that discovered this port
	Proxies  []string // all proxies that agreed the port is open (quorum)
	Banner   string   // service banner grabbed at connect time (may be empty)
}

// PortDetail holds parsed fields from a nmap/built-in port line.
type PortDetail struct {
	Port    string
	Proto   string
	Service string
	Version string
}

var portDetailRE = regexp.MustCompile(`^(\d+)/(tcp|udp)\s+\S+\s*(\S*)\s*(.*)$`)

// parsePortLine extracts port, proto, service, and version from a nmap port line.
func parsePortLine(line string) PortDetail {
	if m := portDetailRE.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
		return PortDetail{Port: m[1], Proto: m[2], Service: m[3], Version: strings.TrimSpace(m[4])}
	}
	return PortDetail{Port: strings.TrimSpace(line)}
}

// execNmapParsed streams nmap output in real-time, highlights open ports,
// annotates each with the proxy that found it, and returns findings.
func execNmapParsed(ctx context.Context, cmd []string, proxyURI string, log func(string)) (openPorts int, hostDown bool, findings []Finding) {
	c := exec.CommandContext(ctx, cmd[0], cmd[1:]...)
	stdout, err := c.StdoutPipe()
	if err != nil {
		log("[-] pipe: " + err.Error() + "\n")
		return
	}
	c.Stderr = c.Stdout
	if err := c.Start(); err != nil {
		log("[-] start: " + err.Error() + "\n")
		return
	}

	var currentHost string
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := sc.Text()
		if m := nmapReportRE.FindStringSubmatch(line); m != nil {
			currentHost = m[1]
		}
		if m := openPortRE.FindStringSubmatch(line); m != nil {
			openPorts++
			log("  ► OPEN  " + line + "\n")
			log("      └─ via " + proxyURI + "\n")
			findings = append(findings, Finding{Host: currentHost, Line: line, ProxyURI: proxyURI})
		} else {
			log("  " + line + "\n")
		}
		if strings.Contains(line, "Host seems down") {
			hostDown = true
		}
	}
	c.Wait()
	return
}
