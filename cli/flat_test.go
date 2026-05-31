package cli

import (
	"reflect"
	"strings"
	"testing"
)

// ── parseFlatArgs ─────────────────────────────────────────────────────────────

func TestParseFlatArgsDefaults(t *testing.T) {
	fa := parseFlatArgs([]string{"-proxlist", "p.txt", "-ip", "1.2.3.4"})
	if fa.proxList != "p.txt" {
		t.Errorf("proxList = %q, want p.txt", fa.proxList)
	}
	if len(fa.targets) != 1 || fa.targets[0] != "1.2.3.4" {
		t.Errorf("targets = %v, want [1.2.3.4]", fa.targets)
	}
	if fa.tool != "builtin" {
		t.Errorf("default tool = %q, want builtin", fa.tool)
	}
	if fa.timeout != 5 {
		t.Errorf("default timeout = %v, want 5", fa.timeout)
	}
	if fa.conc != 200 {
		t.Errorf("default conc = %d, want 200", fa.conc)
	}
	if !fa.rotate {
		t.Error("default rotate should be true")
	}
	if !fa.wrap {
		t.Error("default wrap should be true")
	}
	if fa.outType != "txt" {
		t.Errorf("default outType = %q, want txt", fa.outType)
	}
}

func TestParseFlatArgsConfirm(t *testing.T) {
	fa := parseFlatArgs([]string{"-proxlist", "p.txt", "-ip", "1.2.3.4", "-confirm", "3"})
	if fa.confirm != 3 {
		t.Fatalf("confirm = %d, want 3", fa.confirm)
	}
	def := parseFlatArgs([]string{"-proxlist", "p.txt", "-ip", "1.2.3.4"})
	if def.confirm != 1 {
		t.Fatalf("default confirm = %d, want 1", def.confirm)
	}
}

func TestParseFlatArgsAllFlags(t *testing.T) {
	args := []string{
		"-proxlist", "proxies.txt",
		"-ip", "10.0.0.1",
		"-p", "80,443",
		"-out", "results.json",
		"-type", "json",
		"-tool", "builtin",
		"-conc", "50",
		"-timeout", "10",
		"-nmap-path", "/usr/bin/nmap",
		"-no-rotate",
		"-no-wrap",
	}
	fa := parseFlatArgs(args)
	if fa.proxList != "proxies.txt" {
		t.Errorf("proxList = %q", fa.proxList)
	}
	if fa.ports != "80,443" {
		t.Errorf("ports = %q, want 80,443", fa.ports)
	}
	if fa.outFile != "results.json" {
		t.Errorf("outFile = %q", fa.outFile)
	}
	if fa.outType != "json" {
		t.Errorf("outType = %q", fa.outType)
	}
	if fa.tool != "builtin" {
		t.Errorf("tool = %q", fa.tool)
	}
	if fa.conc != 50 {
		t.Errorf("conc = %d", fa.conc)
	}
	if fa.timeout != 10 {
		t.Errorf("timeout = %v", fa.timeout)
	}
	if fa.nmapPath != "/usr/bin/nmap" {
		t.Errorf("nmapPath = %q", fa.nmapPath)
	}
	if fa.rotate {
		t.Error("rotate should be false with -no-rotate")
	}
	if fa.wrap {
		t.Error("wrap should be false with -no-wrap")
	}
}

func TestParseFlatArgsPositionalTarget(t *testing.T) {
	fa := parseFlatArgs([]string{"-proxlist", "p.txt", "192.168.1.1"})
	if len(fa.targets) != 1 || fa.targets[0] != "192.168.1.1" {
		t.Errorf("positional target: got %v, want [192.168.1.1]", fa.targets)
	}
}

func TestParseFlatArgsMultipleTargets(t *testing.T) {
	fa := parseFlatArgs([]string{"-proxlist", "p.txt", "-ip", "1.1.1.1", "-ip", "2.2.2.2"})
	if len(fa.targets) != 2 {
		t.Errorf("multiple targets: got %v, want 2", fa.targets)
	}
}

func TestParseFlatArgsNmapPassThrough(t *testing.T) {
	fa := parseFlatArgs([]string{
		"-proxlist", "p.txt", "-ip", "1.2.3.4",
		"-sV", "-A", "-T4", "--script=vuln",
	})
	for _, flag := range []string{"-sV", "-A", "-T4", "--script=vuln"} {
		found := false
		for _, e := range fa.nmapExtra {
			if e == flag {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("nmap flag %q not found in nmapExtra: %v", flag, fa.nmapExtra)
		}
	}
}

func TestParseFlatArgsNmapValueFlagConsumed(t *testing.T) {
	// -oX consumes the next token; both should appear in nmapExtra
	fa := parseFlatArgs([]string{
		"-proxlist", "p.txt", "-ip", "1.2.3.4",
		"-oX", "/tmp/out.xml",
	})
	if !reflect.DeepEqual(fa.nmapExtra, []string{"-oX", "/tmp/out.xml"}) {
		t.Errorf("nmapExtra = %v, want [-oX /tmp/out.xml]", fa.nmapExtra)
	}
}

func TestParseFlatArgsPForwardedToNmap(t *testing.T) {
	fa := parseFlatArgs([]string{"-proxlist", "p.txt", "-ip", "h", "-p", "80,443"})
	found := false
	for i, e := range fa.nmapExtra {
		if e == "-p" && i+1 < len(fa.nmapExtra) && fa.nmapExtra[i+1] == "80,443" {
			found = true
		}
	}
	if !found {
		t.Errorf("-p should be forwarded to nmap: nmapExtra = %v", fa.nmapExtra)
	}
}

func TestParseFlatArgsAlternateFlagForms(t *testing.T) {
	// --proxlist and --ip should work the same as -proxlist and -ip
	fa := parseFlatArgs([]string{"--proxlist", "p.txt", "--ip", "1.2.3.4"})
	if fa.proxList != "p.txt" {
		t.Errorf("--proxlist: got %q", fa.proxList)
	}
	if len(fa.targets) != 1 || fa.targets[0] != "1.2.3.4" {
		t.Errorf("--ip: got %v", fa.targets)
	}
}

func TestParseFlatArgsRotateToggle(t *testing.T) {
	fa := parseFlatArgs([]string{"-rotate"})
	if !fa.rotate {
		t.Error("-rotate should set rotate=true")
	}
	fa2 := parseFlatArgs([]string{"-no-rotate"})
	if fa2.rotate {
		t.Error("-no-rotate should set rotate=false")
	}
}

// ── buildFlatNmapCmd ──────────────────────────────────────────────────────────

func TestBuildFlatNmapCmdBasic(t *testing.T) {
	cmd := buildFlatNmapCmd("nmap", "socks4://127.0.0.1:9999", "192.168.1.1", nil, false)
	if cmd[0] != "nmap" {
		t.Errorf("cmd[0] = %q, want nmap", cmd[0])
	}
	if !contains(cmd, "-sT") {
		t.Error("cmd missing -sT")
	}
	if !containsPrefix(cmd, "--proxies=") {
		t.Error("cmd missing --proxies=")
	}
	if !contains(cmd, "--open") {
		t.Error("cmd missing --open")
	}
	if !contains(cmd, "192.168.1.1") {
		t.Error("cmd missing target")
	}
	if contains(cmd, "-Pn") {
		t.Error("cmd should not have -Pn when addPn=false")
	}
}

func TestBuildFlatNmapCmdAddPn(t *testing.T) {
	cmd := buildFlatNmapCmd("nmap", "socks4://127.0.0.1:9999", "host", nil, true)
	if !contains(cmd, "-Pn") {
		t.Error("cmd should include -Pn when addPn=true")
	}
}

func TestBuildFlatNmapCmdNoDuplicatePn(t *testing.T) {
	// If -Pn is already in extra, addPn=true should not duplicate it
	cmd := buildFlatNmapCmd("nmap", "socks4://127.0.0.1:9999", "host", []string{"-Pn"}, true)
	count := 0
	for _, a := range cmd {
		if a == "-Pn" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("-Pn appears %d times, want exactly 1", count)
	}
}

func TestBuildFlatNmapCmdCustomBin(t *testing.T) {
	cmd := buildFlatNmapCmd("/opt/nmap/bin/nmap", "socks4://127.0.0.1:9999", "host", nil, false)
	if cmd[0] != "/opt/nmap/bin/nmap" {
		t.Errorf("cmd[0] = %q, want /opt/nmap/bin/nmap", cmd[0])
	}
}

func TestBuildFlatNmapCmdExtraFlags(t *testing.T) {
	extra := []string{"-sV", "-T4", "--script=vuln"}
	cmd := buildFlatNmapCmd("nmap", "socks4://127.0.0.1:9999", "host", extra, false)
	for _, flag := range extra {
		if !contains(cmd, flag) {
			t.Errorf("extra flag %q missing from cmd: %v", flag, cmd)
		}
	}
}

// ── nmapMissingMsg ────────────────────────────────────────────────────────────

func TestNmapMissingMsgNoPath(t *testing.T) {
	msg := nmapMissingMsg("")
	if !strings.Contains(msg, "nmap.org") {
		t.Error("message should mention nmap.org")
	}
	if !strings.Contains(msg, "brew install nmap") {
		t.Error("message should include macOS install instruction")
	}
}

func TestNmapMissingMsgWithPath(t *testing.T) {
	msg := nmapMissingMsg("/custom/path/nmap")
	if !strings.Contains(msg, "/custom/path/nmap") {
		t.Errorf("message should mention the tried path, got: %s", msg)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func containsPrefix(slice []string, prefix string) bool {
	for _, v := range slice {
		if strings.HasPrefix(v, prefix) {
			return true
		}
	}
	return false
}
