package geo

import (
	"net"
	"strings"
	"testing"
)

func TestTableLookup(t *testing.T) {
	tbl := table{
		{start: 10, end: 20, cc: [2]byte{'U', 'S'}},
		{start: 30, end: 40, cc: [2]byte{'C', 'N'}},
		{start: 41, end: 50, cc: [2]byte{'D', 'E'}},
	}
	cases := []struct {
		ip   uint32
		want string
		ok   bool
	}{
		{15, "US", true},
		{10, "US", true}, // low boundary
		{20, "US", true}, // high boundary
		{35, "CN", true},
		{41, "DE", true}, // adjacent range start
		{25, "", false},  // gap between ranges
		{5, "", false},   // below all
		{99, "", false},  // above all
	}
	for _, c := range cases {
		got, ok := tbl.lookup(c.ip)
		if got != c.want || ok != c.ok {
			t.Errorf("lookup(%d) = (%q,%v), want (%q,%v)", c.ip, got, ok, c.want, c.ok)
		}
	}
}

func TestParseTableSortsAndParses(t *testing.T) {
	// Intentionally out of order to exercise the sort.
	in := "30,40,CN\n10,20,US\nbad line\n50,60,\n41,49,DE\n"
	tbl, err := parseTable(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	// "bad line" (no commas) and "50,60," (empty cc) are skipped.
	if len(tbl) != 3 {
		t.Fatalf("want 3 valid entries, got %d (%v)", len(tbl), tbl)
	}
	if tbl[0].start != 10 || tbl[1].start != 30 || tbl[2].start != 41 {
		t.Fatalf("table not sorted by start: %v", tbl)
	}
	if cc, ok := tbl.lookup(15); !ok || cc != "US" {
		t.Fatalf("lookup(15) = (%q,%v), want US,true", cc, ok)
	}
}

func TestParseNames(t *testing.T) {
	m := parseNames(strings.NewReader("US\tUnited States\nCN\tChina\nBADLINE\n"))
	if m["US"] != "United States" || m["CN"] != "China" {
		t.Fatalf("unexpected names map: %v", m)
	}
	if _, ok := m["BADLINE"]; ok {
		t.Fatalf("malformed line should be skipped")
	}
}

func TestIPv4ToUint(t *testing.T) {
	n, ok := ipv4ToUint(net.ParseIP("8.8.8.8"))
	if !ok || n != 134744072 {
		t.Fatalf("8.8.8.8 => (%d,%v), want 134744072,true", n, ok)
	}
	if _, ok := ipv4ToUint(net.ParseIP("2001:4860:4860::8888")); ok {
		t.Fatalf("IPv6 should not convert to uint32")
	}
}

func TestFlag(t *testing.T) {
	if f := Flag("US"); f != "\U0001F1FA\U0001F1F8" {
		t.Fatalf("Flag(US) = %q, want US flag", f)
	}
	if Flag("U") != "" || Flag("12") != "" || Flag("") != "" {
		t.Fatalf("invalid codes should yield empty flag")
	}
}

// ── real embedded-data sanity checks ────────────────────────────────────────

func TestLookupRealData(t *testing.T) {
	cases := map[string]string{
		"8.8.8.8":   "US", // Google
		"1.1.1.1":   "AU", // Cloudflare (APNIC research, registered AU)
		"10.0.0.1":  "",   // RFC1918 private, not in DB
		"127.0.0.1": "",   // loopback
		"not-an-ip": "",
		"::1":       "", // IPv6 unsupported
	}
	for ip, want := range cases {
		if got := Lookup(ip); got != want {
			t.Errorf("Lookup(%q) = %q, want %q", ip, got, want)
		}
	}
}

func TestNameRealData(t *testing.T) {
	if got := Name("US"); got != "United States of America" {
		t.Fatalf("Name(US) = %q, want United States of America", got)
	}
	if got := Name("us"); got != "United States of America" {
		t.Fatalf("Name should be case-insensitive, got %q", got)
	}
	if got := Name("ZQ"); got != "ZQ" { // not a real code => echoes back
		t.Fatalf("Name(ZQ) = %q, want ZQ", got)
	}
	if got := Name(""); got != "" {
		t.Fatalf("Name(\"\") = %q, want empty", got)
	}
}
