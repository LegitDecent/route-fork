package cli

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// ScanResult holds one open-port finding from any scan tool.
type ScanResult struct {
	Host    string `json:"host"              xml:"-"`
	Port    int    `json:"port"              xml:"portid,attr"`
	Proto   string `json:"proto"             xml:"protocol,attr"`
	Service string `json:"service,omitempty" xml:"service,attr,omitempty"`
	Version string `json:"version,omitempty" xml:"version,attr,omitempty"`
	Proxy   string `json:"proxy,omitempty"   xml:"proxy,attr,omitempty"`
}

// WriteResults writes results to w in the given format (txt | json | xml | csv).
func WriteResults(w io.Writer, results []ScanResult, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	case "xml":
		return writeXML(w, results)
	case "csv":
		return writeCSV(w, results)
	default: // txt
		return writeTXT(w, results)
	}
}

func writeTXT(w io.Writer, results []ScanResult) error {
	for _, r := range results {
		line := fmt.Sprintf("%-20s  %d/%s", r.Host, r.Port, r.Proto)
		if r.Service != "" {
			line += "  " + r.Service
		}
		if r.Version != "" {
			line += "  " + r.Version
		}
		if r.Proxy != "" {
			line += "  via " + r.Proxy
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

func writeCSV(w io.Writer, results []ScanResult) error {
	if _, err := fmt.Fprintln(w, "host,port,proto,service,version,proxy"); err != nil {
		return err
	}
	for _, r := range results {
		if _, err := fmt.Fprintf(w, "%s,%d,%s,%s,%s,%s\n",
			csvEsc(r.Host), r.Port, r.Proto,
			csvEsc(r.Service), csvEsc(r.Version), csvEsc(r.Proxy),
		); err != nil {
			return err
		}
	}
	return nil
}

func csvEsc(s string) string {
	if strings.ContainsAny(s, `,"`) {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// ── XML ──────────────────────────────────────────────────────────────────────

type xmlReport struct {
	XMLName xml.Name  `xml:"proxymgr"`
	Hosts   []xmlHost `xml:"host"`
}

type xmlHost struct {
	Addr  string    `xml:"addr,attr"`
	Ports []xmlPort `xml:"port"`
}

type xmlPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
	State    string `xml:"state,attr"`
	Service  string `xml:"service,attr,omitempty"`
	Version  string `xml:"version,attr,omitempty"`
	Proxy    string `xml:"proxy,attr,omitempty"`
}

func writeXML(w io.Writer, results []ScanResult) error {
	hostMap := make(map[string]*xmlHost)
	var order []string
	for _, r := range results {
		if _, ok := hostMap[r.Host]; !ok {
			hostMap[r.Host] = &xmlHost{Addr: r.Host}
			order = append(order, r.Host)
		}
		hostMap[r.Host].Ports = append(hostMap[r.Host].Ports, xmlPort{
			Protocol: r.Proto,
			PortID:   r.Port,
			State:    "open",
			Service:  r.Service,
			Version:  r.Version,
			Proxy:    r.Proxy,
		})
	}
	report := xmlReport{}
	for _, h := range order {
		report.Hosts = append(report.Hosts, *hostMap[h])
	}
	fmt.Fprintln(w, `<?xml version="1.0"?>`)
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(report); err != nil {
		return err
	}
	_, err := fmt.Fprintln(w)
	return err
}
