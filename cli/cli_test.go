package cli

import (
	"strings"
	"testing"
)

// ── buildNmapArgv ─────────────────────────────────────────────────────────────

func TestBuildNmapArgvBasic(t *testing.T) {
	cmd := buildNmapArgv("80,443", "", "socks4://127.0.0.1:9000", "192.168.1.1", false)
	if cmd[0] != "nmap" {
		t.Errorf("cmd[0] = %q, want nmap", cmd[0])
	}
	if !contains(cmd, "-sT") {
		t.Error("missing -sT")
	}
	if !contains(cmd, "-p") {
		t.Error("missing -p")
	}
	if !contains(cmd, "80,443") {
		t.Error("missing ports")
	}
	if !contains(cmd, "192.168.1.1") {
		t.Error("missing target")
	}
	if !containsPrefix(cmd, "--proxies=") {
		t.Error("missing --proxies=")
	}
}

func TestBuildNmapArgvAddPn(t *testing.T) {
	cmd := buildNmapArgv("80", "", "socks4://127.0.0.1:9000", "host", true)
	if !contains(cmd, "-Pn") {
		t.Error("addPn=true should add -Pn")
	}
}

func TestBuildNmapArgvNoPnWhenFalse(t *testing.T) {
	cmd := buildNmapArgv("80", "", "socks4://127.0.0.1:9000", "host", false)
	if contains(cmd, "-Pn") {
		t.Error("addPn=false should not add -Pn")
	}
}

func TestBuildNmapArgvNoDuplicatePn(t *testing.T) {
	// extra already has -Pn; addPn=true should not duplicate
	cmd := buildNmapArgv("80", "-Pn", "socks4://127.0.0.1:9000", "host", true)
	count := 0
	for _, a := range cmd {
		if a == "-Pn" || a == "-P0" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("-Pn count = %d, want 1: %v", count, cmd)
	}
}

func TestBuildNmapArgvExtraFields(t *testing.T) {
	cmd := buildNmapArgv("80", "-sV --script=default", "socks4://127.0.0.1:9000", "host", false)
	if !contains(cmd, "-sV") {
		t.Errorf("extra -sV missing: %v", cmd)
	}
	if !contains(cmd, "--script=default") {
		t.Errorf("extra --script=default missing: %v", cmd)
	}
}

// ── mergeCommonPorts ──────────────────────────────────────────────────────────

func TestMergeCommonPortsFullRange(t *testing.T) {
	for _, spec := range []string{"1-65535", "0-65535"} {
		got := mergeCommonPorts(spec)
		if got != spec {
			t.Errorf("mergeCommonPorts(%q) = %q, want unchanged", spec, got)
		}
	}
}

func TestMergeCommonPortsAddsCommon(t *testing.T) {
	// Starting with just port 9999, merging should include common ports like 80
	got := mergeCommonPorts("9999")
	if !strings.Contains(got, "80") {
		t.Errorf("mergeCommonPorts(9999) = %q, expected common port 80 to be included", got)
	}
	if !strings.Contains(got, "443") {
		t.Errorf("mergeCommonPorts(9999) = %q, expected common port 443 to be included", got)
	}
	if !strings.Contains(got, "9999") {
		t.Errorf("mergeCommonPorts(9999) = %q, original port 9999 should be kept", got)
	}
}

func TestMergeCommonPortsWhitespace(t *testing.T) {
	// Should handle leading/trailing whitespace without panicking
	got := mergeCommonPorts("  80  ")
	if got == "" {
		t.Error("mergeCommonPorts with whitespace returned empty string")
	}
}
