package cli

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const cfgDirName = ".config/proxymgr"
const cfgFileName = "config"

func configFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, cfgDirName, cfgFileName)
}

// LoadConfig reads key=value pairs from ~/.config/proxymgr/config.
func LoadConfig() map[string]string {
	m := make(map[string]string)
	f, err := os.Open(configFilePath())
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '='); i > 0 {
			m[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
		}
	}
	return m
}

// SaveConfig writes key=value pairs to the config file.
func SaveConfig(m map[string]string) error {
	home, _ := os.UserHomeDir()
	dir := filepath.Join(home, cfgDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.Create(configFilePath())
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "# proxymgr configuration — do not edit manually while the app is running")
	for k, v := range m {
		fmt.Fprintf(w, "%s = %s\n", k, v)
	}
	return w.Flush()
}

// SetConfigKey updates a single key in the config file.
func SetConfigKey(key, value string) error {
	m := LoadConfig()
	m[key] = value
	return SaveConfig(m)
}

// FindNmap locates the nmap binary and reports whether it was confirmed to exist.
// customPath, if non-empty, is tried first.
// Falls back to config → PATH → common install locations.
// Always returns a non-empty path string ("nmap" as last resort so callers can
// still attempt exec and let the OS report the error).
func FindNmap(customPath string) (path string, found bool) {
	if customPath != "" {
		if isExec(customPath) {
			return customPath, true
		}
		return customPath, false
	}
	// config file
	if p := LoadConfig()["nmap_path"]; p != "" {
		if isExec(p) {
			return p, true
		}
	}
	// PATH
	if p, err := exec.LookPath("nmap"); err == nil {
		return p, true
	}
	// common static locations
	for _, c := range nmapCandidates() {
		if isExec(c) {
			return c, true
		}
	}
	return "nmap", false
}

func nmapCandidates() []string {
	paths := []string{
		"/usr/bin/nmap",
		"/usr/local/bin/nmap",
		"/opt/homebrew/bin/nmap",
		"/snap/bin/nmap",
		"/usr/sbin/nmap",
	}
	if runtime.GOOS == "windows" {
		paths = append(paths,
			`C:\Program Files (x86)\Nmap\nmap.exe`,
			`C:\Program Files\Nmap\nmap.exe`,
		)
	}
	return paths
}

func isExec(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return !info.IsDir()
	}
	return !info.IsDir() && info.Mode()&0o111 != 0
}
