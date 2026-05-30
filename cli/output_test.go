package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

var testResults = []ScanResult{
	{Host: "192.168.1.1", Port: 80, Proto: "tcp", Service: "http", Version: "nginx 1.18", Proxy: "socks5://1.2.3.4:1080"},
	{Host: "192.168.1.1", Port: 443, Proto: "tcp", Service: "https"},
	{Host: "10.0.0.1", Port: 22, Proto: "tcp", Service: "ssh", Version: "OpenSSH 8.0"},
}

// ── txt ───────────────────────────────────────────────────────────────────────

func TestWriteResultsTXT(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResults(&buf, testResults, "txt"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// Each result should appear
	if !strings.Contains(out, "192.168.1.1") {
		t.Error("txt output missing host 192.168.1.1")
	}
	if !strings.Contains(out, "80/tcp") {
		t.Error("txt output missing 80/tcp")
	}
	if !strings.Contains(out, "nginx 1.18") {
		t.Error("txt output missing version")
	}
	if !strings.Contains(out, "via socks5://1.2.3.4:1080") {
		t.Error("txt output missing proxy attribution")
	}
}

func TestWriteResultsTXTNoVersion(t *testing.T) {
	var buf bytes.Buffer
	results := []ScanResult{{Host: "1.2.3.4", Port: 443, Proto: "tcp"}}
	if err := WriteResults(&buf, results, "txt"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "via") {
		t.Error("txt output should not include 'via' when proxy is empty")
	}
}

func TestWriteResultsTXTEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResults(&buf, nil, "txt"); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("empty results should produce empty txt output, got %q", buf.String())
	}
}

// ── json ──────────────────────────────────────────────────────────────────────

func TestWriteResultsJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResults(&buf, testResults, "json"); err != nil {
		t.Fatal(err)
	}
	var got []ScanResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("JSON output is not valid: %v\nOutput: %s", err, buf.String())
	}
	if len(got) != len(testResults) {
		t.Errorf("JSON: got %d results, want %d", len(got), len(testResults))
	}
	if got[0].Host != "192.168.1.1" || got[0].Port != 80 {
		t.Errorf("JSON first result = %+v, want host=192.168.1.1 port=80", got[0])
	}
}

func TestWriteResultsJSONEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResults(&buf, []ScanResult{}, "json"); err != nil {
		t.Fatal(err)
	}
	var got []ScanResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("empty JSON invalid: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty array, got %v", got)
	}
}

// ── xml ───────────────────────────────────────────────────────────────────────

func TestWriteResultsXML(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResults(&buf, testResults, "xml"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, `<?xml version="1.0"?>`) {
		t.Error("XML missing declaration")
	}
	if !strings.Contains(out, `<rofk>`) {
		t.Error("XML missing root element <rofk>")
	}
	if !strings.Contains(out, `addr="192.168.1.1"`) {
		t.Error("XML missing host addr")
	}
	if !strings.Contains(out, `portid="80"`) {
		t.Error("XML missing portid=80")
	}
}

func TestWriteResultsXMLGroupsByHost(t *testing.T) {
	// both ports for 192.168.1.1 should be under one <host> element
	var buf bytes.Buffer
	if err := WriteResults(&buf, testResults, "xml"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	count := strings.Count(out, `addr="192.168.1.1"`)
	if count != 1 {
		t.Errorf("192.168.1.1 should appear once as host, got %d", count)
	}
}

// ── csv ───────────────────────────────────────────────────────────────────────

func TestWriteResultsCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteResults(&buf, testResults, "csv"); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	// header + 3 data rows
	if len(lines) != 4 {
		t.Errorf("CSV: got %d lines, want 4 (header + 3 results)", len(lines))
	}
	if lines[0] != "host,port,proto,service,version,banner,proxy" {
		t.Errorf("CSV header = %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "192.168.1.1,80,tcp") {
		t.Errorf("CSV first row = %q", lines[1])
	}
}

func TestWriteResultsCSVEscaping(t *testing.T) {
	results := []ScanResult{
		{Host: "1.2.3.4", Port: 80, Proto: "tcp", Version: `Apache "httpd" 2.4`},
	}
	var buf bytes.Buffer
	if err := WriteResults(&buf, results, "csv"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// Version with quotes should be CSV-escaped
	if !strings.Contains(out, `"Apache ""httpd"" 2.4"`) {
		t.Errorf("CSV escaping failed, output: %s", out)
	}
}

// ── default falls through to txt ──────────────────────────────────────────────

func TestWriteResultsDefaultIsTXT(t *testing.T) {
	var bufDefault, bufTXT bytes.Buffer
	_ = WriteResults(&bufDefault, testResults, "")
	_ = WriteResults(&bufTXT, testResults, "txt")
	if bufDefault.String() != bufTXT.String() {
		t.Error("default format should produce same output as txt")
	}
}

// ── csvEsc ────────────────────────────────────────────────────────────────────

func TestCsvEscNoQuoting(t *testing.T) {
	cases := []string{"plain", "with spaces", "http/1.1", ""}
	for _, tc := range cases {
		if got := csvEsc(tc); got != tc {
			t.Errorf("csvEsc(%q) = %q, want unchanged", tc, got)
		}
	}
}

func TestCsvEscComma(t *testing.T) {
	got := csvEsc("a,b")
	if got != `"a,b"` {
		t.Errorf("csvEsc(\"a,b\") = %q, want %q", got, `"a,b"`)
	}
}

func TestCsvEscQuote(t *testing.T) {
	got := csvEsc(`say "hello"`)
	if got != `"say ""hello"""` {
		t.Errorf("csvEsc quote = %q, want %q", got, `"say ""hello"""`)
	}
}
