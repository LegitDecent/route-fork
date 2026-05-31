package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// redirectHome points the config functions at a temp dir for the duration of the test.
func redirectHome(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", tmp)
	}
	return tmp
}

// ── SaveConfig / LoadConfig round-trip ───────────────────────────────────────

func TestSaveLoadRoundTrip(t *testing.T) {
	redirectHome(t)

	want := map[string]string{
		"nmap_path": "/usr/local/bin/nmap",
		"key2":      "value2",
	}
	if err := SaveConfig(want); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	got := LoadConfig()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("key %q: got %q, want %q", k, got[k], v)
		}
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	redirectHome(t)
	// No file written - should return empty map, not error
	got := LoadConfig()
	if len(got) != 0 {
		t.Errorf("LoadConfig with no file: got %v, want empty map", got)
	}
}

func TestLoadConfigIgnoresComments(t *testing.T) {
	redirectHome(t)
	_ = SaveConfig(map[string]string{"k": "v"})
	// Manually prepend a comment to the file
	path := configFilePath()
	existing, _ := os.ReadFile(path)
	_ = os.WriteFile(path, append([]byte("# a comment\n"), existing...), 0o600)
	got := LoadConfig()
	if got["k"] != "v" {
		t.Errorf("LoadConfig after comment: k = %q, want v", got["k"])
	}
}

// ── SetConfigKey ──────────────────────────────────────────────────────────────

func TestSetConfigKeyNewKey(t *testing.T) {
	redirectHome(t)
	if err := SetConfigKey("nmap_path", "/opt/nmap"); err != nil {
		t.Fatalf("SetConfigKey: %v", err)
	}
	got := LoadConfig()
	if got["nmap_path"] != "/opt/nmap" {
		t.Errorf("nmap_path = %q, want /opt/nmap", got["nmap_path"])
	}
}

func TestSetConfigKeyOverwrites(t *testing.T) {
	redirectHome(t)
	_ = SetConfigKey("nmap_path", "/first/path")
	_ = SetConfigKey("nmap_path", "/second/path")
	got := LoadConfig()
	if got["nmap_path"] != "/second/path" {
		t.Errorf("nmap_path = %q, want /second/path", got["nmap_path"])
	}
}

func TestSetConfigKeyPreservesOtherKeys(t *testing.T) {
	redirectHome(t)
	_ = SaveConfig(map[string]string{"other": "stays", "nmap_path": "old"})
	_ = SetConfigKey("nmap_path", "new")
	got := LoadConfig()
	if got["other"] != "stays" {
		t.Errorf("other key got clobbered: %v", got)
	}
	if got["nmap_path"] != "new" {
		t.Errorf("nmap_path = %q, want new", got["nmap_path"])
	}
}

// ── FindNmap ──────────────────────────────────────────────────────────────────

func TestFindNmapCustomPathExists(t *testing.T) {
	tmp := t.TempDir()
	fakeNmap := filepath.Join(tmp, "nmap")
	if err := os.WriteFile(fakeNmap, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	path, found := FindNmap(fakeNmap)
	if !found {
		t.Errorf("FindNmap(%q) found=false, want true", fakeNmap)
	}
	if path != fakeNmap {
		t.Errorf("FindNmap path = %q, want %q", path, fakeNmap)
	}
}

func TestFindNmapCustomPathMissing(t *testing.T) {
	_, found := FindNmap("/nonexistent/path/to/nmap")
	if found {
		t.Error("FindNmap with nonexistent path should return found=false")
	}
}

func TestFindNmapFromConfig(t *testing.T) {
	redirectHome(t)
	tmp := t.TempDir()
	fakeNmap := filepath.Join(tmp, "nmap")
	_ = os.WriteFile(fakeNmap, []byte("#!/bin/sh\n"), 0o755)

	_ = SetConfigKey("nmap_path", fakeNmap)

	path, found := FindNmap("") // no custom path - should pick up from config
	if !found {
		t.Errorf("FindNmap from config: found=false, path=%q", path)
	}
	if path != fakeNmap {
		t.Errorf("FindNmap from config: path = %q, want %q", path, fakeNmap)
	}
}

func TestFindNmapFallback(t *testing.T) {
	redirectHome(t) // empty config dir
	// PATH won't have nmap in the test environment (probably)
	// We just verify it returns a non-empty string and doesn't panic
	path, _ := FindNmap("")
	if path == "" {
		t.Error("FindNmap fallback returned empty string")
	}
}
