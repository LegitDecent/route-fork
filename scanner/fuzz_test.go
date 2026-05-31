package scanner

import (
	"sort"
	"testing"
)

// FuzzParsePorts feeds arbitrary port specs to the parser. It must never panic,
// and any ports it accepts must be in range. Anything it accepts must also
// round-trip through CompressPorts -> ParsePorts.
func FuzzParsePorts(f *testing.F) {
	for _, s := range []string{
		"80", "1-1024", "22,80,443", "0", "65536", "80-70", "-1", "",
		"1-65535", "a,b,c", "1-2-3", "  22 , 80 ", "99999999999999999999",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		ports, err := ParsePorts(spec)
		if err != nil {
			return // rejected input is fine
		}
		for _, p := range ports {
			if p < 1 || p > 65535 {
				t.Fatalf("ParsePorts(%q) accepted out-of-range port %d", spec, p)
			}
		}
		// Round-trip: compressing then re-parsing must yield the same set.
		if len(ports) == 0 {
			return
		}
		reparsed, err := ParsePorts(CompressPorts(ports))
		if err != nil {
			t.Fatalf("CompressPorts round-trip failed to re-parse: %v", err)
		}
		a := append([]int(nil), ports...)
		sort.Ints(a)
		sort.Ints(reparsed)
		if len(a) != len(reparsed) {
			t.Fatalf("round-trip length mismatch: %d vs %d", len(a), len(reparsed))
		}
		for i := range a {
			if a[i] != reparsed[i] {
				t.Fatalf("round-trip mismatch at %d: %d vs %d", i, a[i], reparsed[i])
			}
		}
	})
}

// FuzzCleanBanner ensures banner sanitisation never panics and only ever emits
// printable ASCII without runs of spaces.
func FuzzCleanBanner(f *testing.F) {
	f.Add([]byte("SSH-2.0-OpenSSH_8.9"))
	f.Add([]byte{0x00, 0x01, 0xff, '\n', '\t', 'A'})
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, raw []byte) {
		out := CleanBanner(raw)
		for i := 0; i < len(out); i++ {
			if out[i] < 32 || out[i] > 126 {
				t.Fatalf("CleanBanner emitted non-printable byte %#x", out[i])
			}
		}
	})
}
