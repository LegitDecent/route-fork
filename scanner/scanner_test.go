package scanner

import (
	"reflect"
	"sort"
	"testing"
)

// ── ParsePorts ────────────────────────────────────────────────────────────────

func TestParsePortsSingle(t *testing.T) {
	ports, err := ParsePorts("80")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ports, []int{80}) {
		t.Errorf("got %v, want [80]", ports)
	}
}

func TestParsePortsCSV(t *testing.T) {
	ports, err := ParsePorts("22,80,443")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ports, []int{22, 80, 443}) {
		t.Errorf("got %v, want [22 80 443]", ports)
	}
}

func TestParsePortsRange(t *testing.T) {
	ports, err := ParsePorts("1-5")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ports, []int{1, 2, 3, 4, 5}) {
		t.Errorf("got %v, want [1 2 3 4 5]", ports)
	}
}

func TestParsePortsMixed(t *testing.T) {
	ports, err := ParsePorts("22,80-82,443")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ports, []int{22, 80, 81, 82, 443}) {
		t.Errorf("got %v, want [22 80 81 82 443]", ports)
	}
}

func TestParsePortsInvalid(t *testing.T) {
	cases := []string{
		"0",       // port zero
		"65536",   // too high
		"abc",     // not a number
		"80-70",   // reversed range
		"80-99999",// range end too high
		"-1",      // negative
	}
	for _, tc := range cases {
		_, err := ParsePorts(tc)
		if err == nil {
			t.Errorf("ParsePorts(%q) expected error, got nil", tc)
		}
	}
}

// ── CompressPorts ─────────────────────────────────────────────────────────────

func TestCompressPortsEmpty(t *testing.T) {
	if got := CompressPorts(nil); got != "" {
		t.Errorf("CompressPorts(nil) = %q, want %q", got, "")
	}
}

func TestCompressPortsSingle(t *testing.T) {
	if got := CompressPorts([]int{80}); got != "80" {
		t.Errorf("got %q, want %q", got, "80")
	}
}

func TestCompressPortsRange(t *testing.T) {
	if got := CompressPorts([]int{1, 2, 3, 4, 5}); got != "1-5" {
		t.Errorf("got %q, want %q", got, "1-5")
	}
}

func TestCompressPortsMixed(t *testing.T) {
	got := CompressPorts([]int{22, 80, 81, 82, 443})
	if got != "22,80-82,443" {
		t.Errorf("got %q, want %q", got, "22,80-82,443")
	}
}

func TestCompressPortsUnsorted(t *testing.T) {
	// should sort before compressing
	got := CompressPorts([]int{443, 80, 22})
	if got != "22,80,443" {
		t.Errorf("got %q, want %q", got, "22,80,443")
	}
}

func TestCompressPortsRoundTrip(t *testing.T) {
	original := []int{22, 80, 81, 82, 443, 8080, 8081, 8082, 9000}
	spec := CompressPorts(original)
	recovered, err := ParsePorts(spec)
	if err != nil {
		t.Fatalf("ParsePorts(%q) error: %v", spec, err)
	}
	sort.Ints(recovered)
	if !reflect.DeepEqual(original, recovered) {
		t.Errorf("round-trip failed: got %v, want %v", recovered, original)
	}
}

// ── MergePortSpecs ────────────────────────────────────────────────────────────

func TestMergePortSpecsFullRange(t *testing.T) {
	cases := [][2]string{
		{"1-65535", "80,443"},
		{"80,443", "1-65535"},
		{"0-65535", "22"},
	}
	for _, tc := range cases {
		got := MergePortSpecs(tc[0], tc[1])
		if got != "1-65535" {
			t.Errorf("MergePortSpecs(%q, %q) = %q, want 1-65535", tc[0], tc[1], got)
		}
	}
}

func TestMergePortSpecsDeduplication(t *testing.T) {
	got := MergePortSpecs("80,443", "443,8080")
	ports, err := ParsePorts(got)
	if err != nil {
		t.Fatal(err)
	}
	set := make(map[int]bool)
	for _, p := range ports {
		if set[p] {
			t.Errorf("duplicate port %d in merged spec %q", p, got)
		}
		set[p] = true
	}
	for _, want := range []int{80, 443, 8080} {
		if !set[want] {
			t.Errorf("port %d missing from merged spec %q", want, got)
		}
	}
}

// ── ExpandTarget ──────────────────────────────────────────────────────────────

func TestExpandTargetHostname(t *testing.T) {
	hosts, err := ExpandTarget("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(hosts, []string{"example.com"}) {
		t.Errorf("got %v, want [example.com]", hosts)
	}
}

func TestExpandTargetSingleIP(t *testing.T) {
	hosts, err := ExpandTarget("192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(hosts, []string{"192.168.1.1"}) {
		t.Errorf("got %v, want [192.168.1.1]", hosts)
	}
}

func TestExpandTargetCIDR30(t *testing.T) {
	// /30 has 4 IPs: network, 2 hosts, broadcast → returns 2 hosts
	hosts, err := ExpandTarget("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Errorf("/30 expand: got %d hosts, want 2: %v", len(hosts), hosts)
	}
	if hosts[0] != "192.168.1.1" || hosts[1] != "192.168.1.2" {
		t.Errorf("/30 expand: got %v, want [192.168.1.1 192.168.1.2]", hosts)
	}
}

func TestExpandTargetCIDR32(t *testing.T) {
	// /32 is a single host, no trimming
	hosts, err := ExpandTarget("10.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0] != "10.0.0.1" {
		t.Errorf("/32 expand: got %v, want [10.0.0.1]", hosts)
	}
}

func TestExpandTargetInvalidCIDR(t *testing.T) {
	_, err := ExpandTarget("not-a-cidr/99")
	if err == nil {
		t.Error("expected error for invalid CIDR, got nil")
	}
}
