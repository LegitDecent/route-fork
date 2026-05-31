// Package geo maps IPv4 addresses to ISO 3166-1 alpha-2 country codes using an
// embedded offline database. It never makes a network call, which keeps proxy
// egress IPs from leaking to a third-party geolocation service.
//
// IP-to-country data is the "GeoFeed + Whois + ASN" set from
// github.com/sapics/ip-location-db, derived from Regional Internet Registry
// whois data and licensed CC BY 4.0 by the NRO (https://www.nro.net/).
// See geo/ATTRIBUTION.md.
package geo

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//go:embed country_ipv4.csv.gz
var ipv4GZ []byte

//go:embed country_names.tsv
var namesTSV []byte

// entry is one contiguous IPv4 range that maps to a single country.
type entry struct {
	start, end uint32
	cc         [2]byte
}

type table []entry

// lookup returns the country code whose range contains ip. The table must be
// sorted by start and contain non-overlapping ranges.
func (t table) lookup(ip uint32) (string, bool) {
	i := sort.Search(len(t), func(i int) bool { return t[i].end >= ip })
	if i < len(t) && t[i].start <= ip && ip <= t[i].end {
		return string(t[i].cc[:]), true
	}
	return "", false
}

var (
	loadOnce sync.Once
	tbl      table
	nameMap  map[string]string
)

func ensureLoaded() {
	loadOnce.Do(func() {
		if gz, err := gzip.NewReader(bytes.NewReader(ipv4GZ)); err == nil {
			tbl, _ = parseTable(gz)
			_ = gz.Close()
		}
		nameMap = parseNames(bytes.NewReader(namesTSV))
	})
}

// parseTable reads "start_int,end_int,CC" lines into a table sorted by start.
func parseTable(r io.Reader) (table, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	t := make(table, 0, 350000)
	for sc.Scan() {
		line := sc.Text()
		a := strings.IndexByte(line, ',')
		if a < 0 {
			continue
		}
		b := strings.IndexByte(line[a+1:], ',')
		if b < 0 {
			continue
		}
		b += a + 1
		cc := line[b+1:]
		if len(cc) < 2 {
			continue
		}
		start, err1 := strconv.ParseUint(line[:a], 10, 32)
		end, err2 := strconv.ParseUint(line[a+1:b], 10, 32)
		if err1 != nil || err2 != nil {
			continue
		}
		t = append(t, entry{start: uint32(start), end: uint32(end), cc: [2]byte{cc[0], cc[1]}})
	}
	if err := sc.Err(); err != nil {
		return t, err
	}
	if !sort.SliceIsSorted(t, func(i, j int) bool { return t[i].start < t[j].start }) {
		sort.Slice(t, func(i, j int) bool { return t[i].start < t[j].start })
	}
	return t, nil
}

// parseNames reads tab-separated "CC<TAB>Name" lines into a code->name map.
func parseNames(r io.Reader) map[string]string {
	m := make(map[string]string, 256)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		code, name, ok := strings.Cut(sc.Text(), "\t")
		if ok && len(code) == 2 {
			m[code] = name
		}
	}
	return m
}

func ipv4ToUint(ip net.IP) (uint32, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(v4), true
}

// Lookup returns the ISO 3166-1 alpha-2 country code for an IPv4 address, or ""
// if the address is invalid, IPv6, private, or absent from the database.
func Lookup(ipStr string) string {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return ""
	}
	n, ok := ipv4ToUint(ip)
	if !ok {
		return ""
	}
	ensureLoaded()
	cc, _ := tbl.lookup(n)
	return cc
}

// Name returns the English country name for an alpha-2 code, or the upper-cased
// code itself when unknown. An empty code returns "".
func Name(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return ""
	}
	ensureLoaded()
	if n, ok := nameMap[code]; ok {
		return n
	}
	return code
}

// Flag returns the Unicode regional-indicator flag emoji for a two-letter
// alpha-2 code, or "" when the code is not two ASCII letters.
func Flag(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	const base = 0x1F1E6 // regional indicator symbol letter A
	return string(rune(base+int(code[0]-'A'))) + string(rune(base+int(code[1]-'A')))
}
