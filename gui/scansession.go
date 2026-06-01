package gui

import (
	"fmt"
	"strings"

	"rofk/scanner"
)

// This file holds the pure, UI-free pieces of the scan controller - the glue
// that historically carried the bugs (target assembly, quorum mapping, the
// quiet flag, finding mapping, summary rendering). Keeping them as plain
// functions lets the scan flow be unit-tested without a Fyne window.

// buildTargetList assembles the ordered, de-duplicated target list from the
// single-target field and the optional multi-line queue. The single target (if
// any and not already present) goes first, then queue lines in order. Blank
// lines and a queue equal to its placeholder are ignored.
func buildTargetList(single, queue, queuePlaceholder string) []string {
	var targets []string
	seen := map[string]bool{}
	add := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		targets = append(targets, t)
	}

	single = strings.TrimSpace(single)
	if single != "" {
		add(single)
	}
	if queue != "" && queue != queuePlaceholder {
		for _, line := range strings.Split(queue, "\n") {
			add(line)
		}
	}
	return targets
}

// quorumForMode maps a Scan-mode select label to the number of proxies that
// must agree a port is open. Unknown labels default to 1 (Fast).
func quorumForMode(mode string) int {
	switch mode {
	case "Confirmed (2 proxies)":
		return 2
	case "Paranoid (3 proxies)":
		return 3
	default:
		return 1
	}
}

// quietScan reports whether per-port closed/unreachable lines should be
// suppressed: true for multi-target runs or any CIDR target, where logging a
// line per host:port would flood the UI.
func quietScan(targets []string) bool {
	if len(targets) > 1 {
		return true
	}
	for _, t := range targets {
		if strings.Contains(t, "/") {
			return true
		}
	}
	return false
}

// scanFindingToGui maps a scanner.ScanFinding to the GUI Finding type.
func scanFindingToGui(f scanner.ScanFinding) Finding {
	return Finding{
		Host:     f.Host,
		Port:     f.Port,
		Proto:    f.Proto,
		Service:  f.Service,
		Version:  f.Version,
		Banner:   f.Banner,
		ProxyURI: f.Primary,
		Proxies:  f.Proxies,
	}
}

// hostScan is one target's findings, used to render the final summary.
type hostScan struct {
	host     string
	findings []Finding
}

// formatOpenLine renders the summary line for one finding (without the leading
// "  ► OPEN  "), including the host prefix when present.
func formatOpenLine(f Finding) string {
	svc := f.Service
	if f.Version != "" {
		svc += "  " + f.Version
	}
	line := fmt.Sprintf("%d/%s   open  %s", f.Port, f.Proto, svc)
	if f.Host != "" {
		line = f.Host + "  " + line
	}
	return line
}

// renderSummary produces the final open-port summary as a flat list of log
// lines (each without a trailing newline), given each target's findings. It is
// pure so the summary format is unit-tested independently of the log widget.
func renderSummary(results []hostScan) []string {
	var out []string
	out = append(out, "[=] ─────────────── OPEN PORT SUMMARY ───────────────")

	multiHost := len(results) > 1
	anyOpen := false
	for _, hr := range results {
		if len(hr.findings) > 0 {
			anyOpen = true
			break
		}
	}
	if !anyOpen {
		out = append(out, "    (no open ports found)")
	} else {
		for i, hr := range results {
			if multiHost {
				if i > 0 {
					out = append(out, "")
				}
				out = append(out, "HOST: "+hr.host)
			}
			for _, f := range hr.findings {
				out = append(out, "  ► OPEN  "+formatOpenLine(f))
				switch {
				case len(f.Proxies) > 0:
					for vi, lbl := range f.Proxies {
						branch := "├─"
						if vi == len(f.Proxies)-1 {
							branch = "└─"
						}
						out = append(out, "      "+branch+" via "+lbl)
					}
				case f.ProxyURI != "":
					out = append(out, "      └─ via "+f.ProxyURI)
				}
			}
			if multiHost && len(hr.findings) == 0 {
				out = append(out, "    (no open ports)")
			}
		}
	}
	out = append(out, "[=] ─────────────────────────────────────────────────")
	return out
}
