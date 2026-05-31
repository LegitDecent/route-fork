package gui

import (
	"context"
	"fmt"
	"image/color"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"rofk/cli"
	"rofk/pool"
	"rofk/proxy"
	"rofk/relay"
	"rofk/scanner"
)

// ── State ─────────────────────────────────────────────────────────────────────

// PortEntry is one open port on a host, deduplicated across rescans. Each rescan
// merges any newly-validating proxies into Proxies rather than adding a new row.
type PortEntry struct {
	Port    int
	Proto   string
	Service string
	Version string
	Banner  string
	Proxies []string // every distinct proxy that has validated this port
}

// HostRecord accumulates open ports for a single discovered host.
type HostRecord struct {
	IP      string
	Ports   []*PortEntry
	portIdx map[string]int // "port/proto" → index into Ports
}

// dedupeAppend appends each item from add to base, skipping values already present.
func dedupeAppend(base, add []string) []string {
	seen := make(map[string]bool, len(base))
	for _, b := range base {
		seen[b] = true
	}
	for _, a := range add {
		if a != "" && !seen[a] {
			seen[a] = true
			base = append(base, a)
		}
	}
	return base
}

type state struct {
	pool *pool.Pool

	validMu   sync.RWMutex
	validRows []string // formatted display rows

	failedMu   sync.RWMutex
	failedRows []string

	valCancel   context.CancelFunc
	scanCancel  context.CancelFunc
	valRunning  atomic.Bool
	scanRunning atomic.Bool

	// discovered hosts (Hosts tab)
	hostsMu      sync.RWMutex
	hostsMap     map[string]int // IP → index in hostsSlice
	hostsSlice   []*HostRecord
	hostsRefresh func() // set by buildHostsTab

	// settings
	threads  int
	timeout  float64
	testHost string
	testPort int
	wrap     bool

	// auto-revalidation
	revalDone   chan struct{}  // nil when not running
	revalStatus binding.String // shown in Settings tab

	// UI refresh callbacks (set by buildProxiesTab)
	refreshValidList func()
	refreshCounts    func()
}

func newState() *state {
	return &state{
		pool:        pool.New(),
		hostsMap:    make(map[string]int),
		threads:     100,
		timeout:     10,
		testHost:    "www.google.com",
		testPort:    80,
		wrap:        true,
		revalStatus: binding.NewString(),
	}
}

// startAutoReval begins background periodic re-validation of the proxy pool.
// Calling it again replaces any running timer.
func (st *state) startAutoReval(interval time.Duration) {
	st.stopAutoReval()
	done := make(chan struct{})
	st.revalDone = done
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				st.revalidatePool()
			}
		}
	}()
}

// stopAutoReval stops the background revalidation goroutine if running.
func (st *state) stopAutoReval() {
	if st.revalDone != nil {
		close(st.revalDone)
		st.revalDone = nil
	}
}

// revalidatePool re-checks every proxy in the valid pool and removes dead ones.
func (st *state) revalidatePool() {
	snapshot := st.pool.Valid()
	if len(snapshot) == 0 {
		return
	}
	st.revalStatus.Set(fmt.Sprintf("Revalidating %d proxies…", len(snapshot)))

	to := time.Duration(float64(time.Second) * st.timeout)
	var mu sync.Mutex
	var kept []*proxy.Proxy
	sem := make(chan struct{}, st.threads)
	var wg sync.WaitGroup

	for _, p := range snapshot {
		sem <- struct{}{}
		wg.Add(1)
		go func(p *proxy.Proxy) {
			defer wg.Done()
			defer func() { <-sem }()
			ok, ms, _ := proxy.Validate(p, to, st.testHost, st.testPort)
			if ok {
				p.LatencyMs = ms
				mu.Lock()
				kept = append(kept, p)
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	removed := len(snapshot) - len(kept)
	st.pool.SetValid(kept)

	st.validMu.Lock()
	st.validRows = st.validRows[:0]
	for _, px := range kept {
		st.validRows = append(st.validRows, px.DisplayValid())
	}
	st.validMu.Unlock()

	if st.refreshValidList != nil {
		st.refreshValidList()
	}
	if st.refreshCounts != nil {
		st.refreshCounts()
	}

	st.revalStatus.Set(fmt.Sprintf("Last revalidation: %d alive, %d removed",
		len(kept), removed))
}

// pushFindings groups findings by host IP and notifies the Hosts tab.
func (st *state) pushFindings(findings []Finding) {
	if len(findings) == 0 {
		return
	}
	st.hostsMu.Lock()
	for _, f := range findings {
		if f.Host == "" {
			continue
		}
		idx, ok := st.hostsMap[f.Host]
		if !ok {
			idx = len(st.hostsSlice)
			st.hostsMap[f.Host] = idx
			st.hostsSlice = append(st.hostsSlice, &HostRecord{IP: f.Host, portIdx: map[string]int{}})
		}
		hr := st.hostsSlice[idx]
		if hr.portIdx == nil {
			hr.portIdx = map[string]int{}
		}

		pd := parsePortLine(f.Line)
		key := pd.Port + "/" + pd.Proto

		// All proxies that validated this finding.
		provs := f.Proxies
		if len(provs) == 0 && f.ProxyURI != "" {
			provs = []string{f.ProxyURI}
		}

		if pi, exists := hr.portIdx[key]; exists {
			// Rescan of a known port - merge in any new proxies, dedup.
			pe := hr.Ports[pi]
			pe.Proxies = dedupeAppend(pe.Proxies, provs)
			if pe.Service == "" {
				pe.Service = pd.Service
			}
			if pe.Version == "" {
				pe.Version = pd.Version
			}
			if pe.Banner == "" {
				pe.Banner = f.Banner
			}
		} else {
			portNum, _ := strconv.Atoi(pd.Port)
			pe := &PortEntry{
				Port:    portNum,
				Proto:   pd.Proto,
				Service: pd.Service,
				Version: pd.Version,
				Banner:  f.Banner,
				Proxies: dedupeAppend(nil, provs),
			}
			hr.portIdx[key] = len(hr.Ports)
			hr.Ports = append(hr.Ports, pe)
		}
	}
	refresh := st.hostsRefresh
	st.hostsMu.Unlock()
	if refresh != nil {
		refresh()
	}
}

// clearHosts resets the host store.
func (st *state) clearHosts() {
	st.hostsMu.Lock()
	st.hostsMap = make(map[string]int)
	st.hostsSlice = nil
	st.hostsMu.Unlock()
}

// forcedDarkTheme wraps the default theme and always reports the dark variant,
// keeping the app dark regardless of the OS appearance. This replaces the
// deprecated theme.DarkTheme() (removed in favour of variant-based theming).
type forcedDarkTheme struct{ fyne.Theme }

func (forcedDarkTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	return theme.DefaultTheme().Color(name, theme.VariantDark)
}

// ── Entry point ───────────────────────────────────────────────────────────────

func Run() {
	a := app.NewWithID("com.rofk.app")
	a.Settings().SetTheme(forcedDarkTheme{theme.DefaultTheme()})

	w := a.NewWindow("SOCKS Proxy Manager")
	w.Resize(fyne.NewSize(1100, 720))
	w.SetMaster()

	st := newState()
	hostsTab := buildHostsTab(st) // must be built before scannerTab so hostsRefresh is set
	tabs := container.NewAppTabs(
		container.NewTabItem("  Proxies  ", buildProxiesTab(w, st, a)),
		container.NewTabItem("  Scanner  ", buildScannerTab(w, st)),
		container.NewTabItem("  Hosts  ", hostsTab),
		container.NewTabItem("  Settings  ", buildSettingsTab(st)),
	)
	tabs.SetTabLocation(container.TabLocationTop)
	w.SetContent(tabs)
	w.ShowAndRun()
}

// ── Proxies tab ───────────────────────────────────────────────────────────────

func buildProxiesTab(w fyne.Window, st *state, a fyne.App) fyne.CanvasObject {
	// ── Input ──
	inputEntry := widget.NewMultiLineEntry()
	inputEntry.SetPlaceHolder("Paste proxies here, one per line\n\nFormats:\n  host:port\n  socks5://host:port\n  socks4://host:port\n  socks5://user:pass@host:port\n  host:port:user:pass")
	inputEntry.Wrapping = fyne.TextWrapOff

	// ── Progress / status bindings ──
	progressBind := binding.NewFloat()
	statusBind := binding.NewString()
	statusBind.Set("Ready")

	progressBar := widget.NewProgressBarWithData(progressBind)
	statusLabel := widget.NewLabelWithData(statusBind)
	statusLabel.Truncation = fyne.TextTruncateEllipsis

	// ── Valid pool list ──
	validList := widget.NewList(
		func() int {
			st.validMu.RLock()
			defer st.validMu.RUnlock()
			return len(st.validRows)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			st.validMu.RLock()
			defer st.validMu.RUnlock()
			if id < len(st.validRows) {
				obj.(*widget.Label).SetText(st.validRows[id])
			}
		},
	)

	// ── Failed pool list ──
	failedList := widget.NewList(
		func() int {
			st.failedMu.RLock()
			defer st.failedMu.RUnlock()
			return len(st.failedRows)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			st.failedMu.RLock()
			defer st.failedMu.RUnlock()
			if id < len(st.failedRows) {
				obj.(*widget.Label).SetText(st.failedRows[id])
			}
		},
	)

	validCountBind := binding.NewString()
	failedCountBind := binding.NewString()
	validCountBind.Set("0 proxies")
	failedCountBind.Set("0 proxies")

	refreshCounts := func() {
		v := st.pool.ValidCount()
		f := st.pool.FailedCount()
		validCountBind.Set(fmt.Sprintf("%d proxies", v))
		failedCountBind.Set(fmt.Sprintf("%d proxies", f))
		statusBind.Set(fmt.Sprintf("Valid: %d   Failed: %d   Total: %d", v, f, v+f))
	}
	// Expose refresh hooks for auto-revalidation and mid-scan pruning.
	st.refreshValidList = func() { fyne.Do(func() { validList.Refresh() }) }
	st.refreshCounts = refreshCounts

	// ── Toolbar buttons ──
	var btnValidate *widget.Button

	btnImport := widget.NewButton("Import File", func() {
		dialog.ShowFileOpen(func(f fyne.URIReadCloser, err error) {
			if err != nil || f == nil {
				return
			}
			defer f.Close()
			data, err := os.ReadFile(f.URI().Path())
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			existing := inputEntry.Text
			if existing != "" {
				inputEntry.SetText(strings.TrimRight(existing, "\n") + "\n" + string(data))
			} else {
				inputEntry.SetText(string(data))
			}
		}, w)
	})

	btnAddDirect := widget.NewButton("Add to Pool (skip validation)", func() {
		proxies := proxy.ParseAll(inputEntry.Text)
		if len(proxies) == 0 {
			dialog.ShowInformation("Nothing parsed", "No proxy entries detected.", w)
			return
		}

		msg := fmt.Sprintf(
			"You are about to add %d proxy/proxies to the pool without any validation.\n\n"+
				"Unvalidated proxies:\n"+
				"  • May be dead or unreachable\n"+
				"  • May leak your real IP if they fail mid-scan\n"+
				"  • Have no measured latency or verified egress IP\n\n"+
				"Use \"Validate All\" instead unless you have a specific reason to skip it.",
			len(proxies),
		)

		dialog.ShowConfirm("Skip Validation: Are You Sure?", msg, func(confirmed bool) {
			if !confirmed {
				return
			}
			existing := make(map[string]bool)
			for _, p := range st.pool.Valid() {
				existing[p.Address()] = true
			}
			added := 0
			for _, p := range proxies {
				if !existing[p.Address()] {
					p.Status = proxy.StatusValid
					p.LatencyMs = 0
					st.pool.AddValid(p)
					st.validMu.Lock()
					st.validRows = append(st.validRows, p.Address()+"  "+p.Proto+"  unverified")
					st.validMu.Unlock()
					added++
				}
			}
			validList.Refresh()
			refreshCounts()
			dialog.ShowInformation("Added", fmt.Sprintf("%d proxies added (unverified).", added), w)
		}, w)
	})

	btnClearInput := widget.NewButton("Clear Input", func() {
		inputEntry.SetText("")
	})

	btnValidate = widget.NewButton("▶  Validate All", func() {
		if st.valRunning.Load() {
			if st.valCancel != nil {
				st.valCancel()
			}
			return
		}

		proxies := proxy.ParseAll(inputEntry.Text)
		if len(proxies) == 0 {
			dialog.ShowInformation("Nothing parsed", "No proxy entries detected in input.", w)
			return
		}

		ctx, cancel := context.WithCancel(context.Background())
		st.valCancel = cancel
		st.valRunning.Store(true)
		btnValidate.SetText("■  Stop")

		go func() {
			defer func() {
				st.valRunning.Store(false)
				fyne.Do(func() { btnValidate.SetText("▶  Validate All") })
			}()

			total := len(proxies)
			var done atomic.Int64
			sem := make(chan struct{}, st.threads)
			var wg sync.WaitGroup
			to := time.Duration(float64(time.Second) * st.timeout)

			for _, p := range proxies {
				select {
				case <-ctx.Done():
					wg.Wait()
					statusBind.Set(fmt.Sprintf("Stopped. Valid: %d  Failed: %d",
						st.pool.ValidCount(), st.pool.FailedCount()))
					return
				default:
				}

				sem <- struct{}{}
				wg.Add(1)
				go func(p *proxy.Proxy) {
					defer wg.Done()
					defer func() { <-sem }()

					ok, ms, errStr := proxy.Validate(p, to, st.testHost, st.testPort)
					if ok {
						_, _ = proxy.FetchEgressIP(p, to) // fills p.EgressIP inline
						p.Status = proxy.StatusValid
						p.LatencyMs = ms
						st.pool.AddValid(p)
						st.validMu.Lock()
						st.validRows = append(st.validRows, p.DisplayValid())
						st.validMu.Unlock()
						fyne.Do(func() { validList.Refresh() })
					} else {
						p.Status = proxy.StatusInvalid
						p.FailReason = errStr
						st.pool.AddFailed(p)
						st.failedMu.Lock()
						st.failedRows = append(st.failedRows, p.DisplayFailed())
						st.failedMu.Unlock()
						fyne.Do(func() { failedList.Refresh() })
					}
					n := done.Add(1)
					pct := float64(n) / float64(total)
					progressBind.Set(pct)
					statusBind.Set(fmt.Sprintf("Validating %d / %d  (%.0f%%)", n, total, pct*100))
					refreshCounts()
				}(p)
			}
			wg.Wait()
			progressBind.Set(1.0)

			// ── Egress deduplication ──────────────────────────────────────────
			valid := st.pool.Valid()
			byEgress := make(map[string][]*proxy.Proxy)
			for _, px := range valid {
				if px.EgressIP != "" {
					byEgress[px.EgressIP] = append(byEgress[px.EgressIP], px)
				}
			}

			type dupeGroup struct {
				ip      string
				proxies []*proxy.Proxy
			}
			var dupeGroups []dupeGroup
			totalDupes := 0
			for ip, group := range byEgress {
				if len(group) > 1 {
					sort.Slice(group, func(i, j int) bool {
						return group[i].LatencyMs < group[j].LatencyMs
					})
					dupeGroups = append(dupeGroups, dupeGroup{ip, group})
					totalDupes += len(group) - 1
				}
			}
			sort.Slice(dupeGroups, func(i, j int) bool {
				return dupeGroups[i].ip < dupeGroups[j].ip
			})

			// count proxies where egress fetch failed
			unknownCount := 0
			for _, px := range valid {
				if px.EgressIP == "" {
					unknownCount++
				}
			}

			if len(dupeGroups) == 0 && unknownCount == 0 {
				statusBind.Set(fmt.Sprintf("Done. Valid: %d  Failed: %d  Total: %d",
					st.pool.ValidCount(), st.pool.FailedCount(), total))
				return
			}

			// Build scrollable summary
			var lines []fyne.CanvasObject

			if len(dupeGroups) > 0 {
				lines = append(lines, widget.NewLabelWithStyle(
					fmt.Sprintf("%d duplicate egress IP(s). %d redundant proxies share an exit IP with a faster one.",
						len(dupeGroups), totalDupes),
					fyne.TextAlignLeading, fyne.TextStyle{Bold: true},
				))
				for _, g := range dupeGroups {
					lines = append(lines, widget.NewSeparator())
					lines = append(lines, widget.NewLabelWithStyle(
						"Egress IP: "+g.ip,
						fyne.TextAlignLeading, fyne.TextStyle{Bold: true},
					))
					for i, px := range g.proxies {
						marker := "keep"
						if i > 0 {
							marker = "dupe"
						}
						lines = append(lines, widget.NewLabel(
							fmt.Sprintf("  [%s]  %s  %.0f ms", marker, px.Address(), px.LatencyMs),
						))
					}
				}
			}

			if unknownCount > 0 {
				lines = append(lines, widget.NewSeparator())
				lines = append(lines, widget.NewLabelWithStyle(
					fmt.Sprintf("%d proxy/proxies could not have their egress IP verified. Exit node unknown, untrustworthy.",
						unknownCount),
					fyne.TextAlignLeading, fyne.TextStyle{Bold: true},
				))
				for _, px := range valid {
					if px.EgressIP == "" {
						lines = append(lines, widget.NewLabel(
							fmt.Sprintf("  [cut]  %s  %.0f ms", px.Address(), px.LatencyMs),
						))
					}
				}
			}

			scroll := container.NewScroll(container.NewVBox(lines...))
			scroll.SetMinSize(fyne.NewSize(580, 340))

			removed := totalDupes + unknownCount
			fyne.Do(func() {
				d := dialog.NewCustomConfirm(
					"Pool Cleanup Required",
					fmt.Sprintf("Remove %d Bad Proxies", removed),
					"Keep All",
					scroll,
					func(remove bool) {
						if !remove {
							statusBind.Set(fmt.Sprintf("Done. Valid: %d  Failed: %d  Total: %d",
								st.pool.ValidCount(), st.pool.FailedCount(), total))
							return
						}
						// Keep: fastest per duplicate group + verified unique egress only
						// Drop: slower duplicates, unknown-egress proxies
						keepSet := make(map[string]bool)
						for _, g := range dupeGroups {
							keepSet[g.proxies[0].Address()] = true // fastest only
						}
						var kept []*proxy.Proxy
						for _, px := range valid {
							if px.EgressIP == "" {
								continue // unverified egress: cut
							} else if len(byEgress[px.EgressIP]) == 1 {
								kept = append(kept, px) // unique egress: keep
							} else if keepSet[px.Address()] {
								kept = append(kept, px) // fastest in dupe group: keep
							}
							// slower duplicates: drop
						}
						st.pool.SetValid(kept)
						st.validMu.Lock()
						st.validRows = st.validRows[:0]
						for _, px := range kept {
							st.validRows = append(st.validRows, px.DisplayValid())
						}
						st.validMu.Unlock()
						validList.Refresh()
						refreshCounts()
						statusBind.Set(fmt.Sprintf("Done. Valid: %d  Failed: %d  Total: %d  (%d removed)",
							st.pool.ValidCount(), st.pool.FailedCount(), total, removed))
					},
					w,
				)
				d.Resize(fyne.NewSize(620, 480))
				d.Show()
			})
		}()
	})

	btnExportValid := widget.NewButton("Export", func() {
		proxies := st.pool.Valid()
		if len(proxies) == 0 {
			dialog.ShowInformation("Empty", "No valid proxies to export.", w)
			return
		}
		dialog.ShowFileSave(func(f fyne.URIWriteCloser, err error) {
			if err != nil || f == nil {
				return
			}
			defer f.Close()
			for _, p := range proxies {
				f.Write([]byte(p.URI() + "\n"))
			}
		}, w)
	})

	btnClearValid := widget.NewButton("Clear Pool", func() {
		st.pool.ClearValid()
		st.validMu.Lock()
		st.validRows = st.validRows[:0]
		st.validMu.Unlock()
		validList.Refresh()
		refreshCounts()
	})

	btnRetryFailed := widget.NewButton("Retry Failed", func() {
		failed := st.pool.Failed()
		if len(failed) == 0 {
			return
		}
		var lines []string
		for _, p := range failed {
			lines = append(lines, p.URI())
		}
		inputEntry.SetText(strings.Join(lines, "\n"))
		// clear failed pool
		st.pool.ClearFailed()
		st.failedMu.Lock()
		st.failedRows = st.failedRows[:0]
		st.failedMu.Unlock()
		failedList.Refresh()
		refreshCounts()
		// kick off validation
		btnValidate.OnTapped()
	})

	btnClearFailed := widget.NewButton("Clear", func() {
		st.pool.ClearFailed()
		st.failedMu.Lock()
		st.failedRows = st.failedRows[:0]
		st.failedMu.Unlock()
		failedList.Refresh()
		refreshCounts()
	})

	// ── Layout ──
	toolbar := container.NewHBox(
		btnImport, btnAddDirect, btnClearInput,
		widget.NewSeparator(),
		btnValidate,
		widget.NewSeparator(),
		statusLabel,
		layout.NewSpacer(),
		progressBar,
	)

	validSection := container.NewBorder(
		container.NewHBox(
			widget.NewLabelWithStyle("Validated Pool", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			layout.NewSpacer(),
			widget.NewLabelWithData(validCountBind),
			btnExportValid, btnClearValid,
		),
		nil, nil, nil,
		validList,
	)

	failedSection := container.NewBorder(
		container.NewHBox(
			widget.NewLabelWithStyle("Failed Pool", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			layout.NewSpacer(),
			widget.NewLabelWithData(failedCountBind),
			btnRetryFailed, btnClearFailed,
		),
		nil, nil, nil,
		failedList,
	)

	rightSplit := container.NewVSplit(validSection, failedSection)
	rightSplit.Offset = 0.6

	inputSection := container.NewBorder(
		widget.NewLabelWithStyle("Raw Input", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		nil, nil, nil,
		inputEntry,
	)

	mainSplit := container.NewHSplit(inputSection, rightSplit)
	mainSplit.Offset = 0.3

	return container.NewBorder(
		container.NewVBox(toolbar, progressBar),
		nil, nil, nil,
		mainSplit,
	)
}

// ── Scanner helpers ───────────────────────────────────────────────────────────

const commonPortSpec = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995," +
	"1723,3306,3389,5900,8080,8443,8888"

// mergeCommonPorts merges spec with the common port list, deduplicating.
func mergeCommonPorts(spec string) string {
	s := strings.TrimSpace(spec)
	if s == "1-65535" || s == "0-65535" {
		return s
	}
	return scanner.MergePortSpecs(s, commonPortSpec)
}

// nmapCmd builds the nmap argv slice.
// bin is the nmap binary path (use cli.FindNmap to resolve it).
// proxyViaLabel returns the display label for a proxy in scan output.
// When an egress IP is known (from validation) it is shown alongside the
// proxy address so the user can see what IP the target server actually sees.
func proxyViaLabel(p *proxy.Proxy) string {
	if p.EgressIP != "" {
		return p.URI() + " [exit: " + p.EgressIP + "]"
	}
	return p.URI()
}

// target may be a single host/CIDR or space-separated IPs (for chunk rotation).
// addPn=true adds -Pn (skip host discovery) for the retry pass.
func nmapCmd(bin, ports, extra, proxyArg, target string, addPn bool) []string {
	args := []string{bin, "-sT", "-p", ports, "--proxies=" + proxyArg, "--open"}
	if addPn {
		args = append(args, "-Pn")
	}
	for _, a := range strings.Fields(extra) {
		if (a == "-Pn" || a == "-P0") && addPn {
			continue
		}
		args = append(args, a)
	}
	args = append(args, strings.Fields(target)...) // handles single IP, CIDR, or space-sep list
	return args
}

// dialThroughProxyCtx wraps proxy.DialThroughProxy so a context cancellation
// (Stop button) returns immediately instead of blocking until the dial timeout.
// The underlying dial goroutine is left to finish on its own timeout; it holds
// no locks and self-terminates, so leaking it briefly is harmless.
func dialThroughProxyCtx(ctx context.Context, p *proxy.Proxy, host string, port int, to time.Duration) (net.Conn, error) {
	type res struct {
		c net.Conn
		e error
	}
	ch := make(chan res, 1)
	go func() {
		c, e := proxy.DialThroughProxy(p, host, port, to)
		ch <- res{c, e}
	}()
	select {
	case <-ctx.Done():
		// Close the connection if the dial happens to complete after cancel.
		go func() {
			if r := <-ch; r.c != nil {
				r.c.Close()
			}
		}()
		return nil, ctx.Err()
	case r := <-ch:
		return r.c, r.e
	}
}

// guiBuiltinScan runs the built-in TCP scanner, logs open ports in real-time,
// annotates each with proxyLabel, and returns the count and findings.
func guiBuiltinScan(ctx context.Context, getProxy func() *proxy.Proxy, target, ports string,
	conc int, timeout time.Duration, prog binding.Float, log func(string), proxyLabel string) (int, []Finding) {

	opts := scanner.Options{
		Ports:       ports,
		Concurrency: conc,
		Timeout:     timeout,
	}
	results := make(chan scanner.Result, 512)
	go func() {
		scanner.Scan(ctx, getProxy, target, opts, results,
			func(done, total int) {
				prog.Set(float64(done) / float64(total))
			})
		close(results)
	}()

	var open int
	var findings []Finding
	for r := range results {
		if r.Open {
			open++
			label := proxyLabel
			if r.Proxy != nil {
				label = proxyViaLabel(r.Proxy)
			}
			svc := scanner.PortService(r.Port)
			if svc == "" {
				svc = "unknown"
			}
			log(fmt.Sprintf("  ► OPEN  %s:%d  [%s]\n", r.Host, r.Port, svc))
			if r.Banner != "" {
				log("      │  " + r.Banner + "\n")
			}
			if label != "" {
				log("      └─ via " + label + "\n")
			}
			findings = append(findings, Finding{
				Host:     r.Host,
				Line:     fmt.Sprintf("%d/tcp   open  %s", r.Port, svc),
				ProxyURI: label,
				Banner:   r.Banner,
			})
		}
	}
	return open, findings
}

// ── Scanner tab ───────────────────────────────────────────────────────────────

func buildScannerTab(w fyne.Window, st *state) fyne.CanvasObject {
	toolSelect := widget.NewSelect([]string{"nmap", "Built-in (TCP connect)", "custom"}, nil)
	toolSelect.Selected = "nmap"

	targetEntry := widget.NewEntry()
	targetEntry.SetPlaceHolder("e.g. 192.168.1.1 or scanme.nmap.org")

	portsEntry := widget.NewEntry()
	portsEntry.SetText("1-65535")
	// Checking "Add common ports" merges the common-port list (deduped) directly
	// into the Ports field so you can see exactly what will be scanned.
	// Unchecking restores what you had before.
	var portsBeforeCommon string
	var haveCommonSnap bool
	commonPortsCheck := widget.NewCheck("Add common ports", func(checked bool) {
		if checked {
			portsBeforeCommon = portsEntry.Text
			haveCommonSnap = true
			portsEntry.SetText(mergeCommonPorts(portsEntry.Text))
		} else if haveCommonSnap {
			portsEntry.SetText(portsBeforeCommon)
			haveCommonSnap = false
		}
	})

	concEntry := widget.NewEntry()
	concEntry.SetText("200")

	extraEntry := widget.NewEntry()
	extraEntry.SetPlaceHolder("Extra args passed to external tool")

	customEntry := widget.NewEntry()
	customEntry.SetPlaceHolder("{proxy}  {target}  {ports}  (tokens replaced at runtime)")
	customEntry.Disable()

	timingSelect := widget.NewSelect([]string{"Default (T3)", "Aggressive (T4)", "Insane (T5)"}, nil)
	timingSelect.Selected = "Aggressive (T4)"

	minRateEntry := widget.NewEntry()
	minRateEntry.SetPlaceHolder("pkts/sec (e.g. 1000)")

	maxRetriesEntry := widget.NewEntry()
	maxRetriesEntry.SetText("2")

	// Scan mode controls how many proxies must agree a port is open before it's
	// reported. Guards against lying proxies that fake a successful CONNECT.
	// Only applies to per-port rotation (built-in TCP scan).
	verifyBlurbs := map[string]string{
		"Fast (1 proxy)":        "Fastest. First proxy that connects decides. A lying proxy can report a false open.",
		"Confirmed (2 proxies)": "Recommended. Two independent proxies must agree before a port is reported open, stopping single-liar false positives.",
		"Paranoid (3 proxies)":  "Strongest. Three proxies must agree, beating multiple liars, but slower and may miss opens on small or flaky pools.",
	}
	verifyBlurb := widget.NewLabel(verifyBlurbs["Confirmed (2 proxies)"])
	verifyBlurb.Wrapping = fyne.TextWrapWord
	verifySelect := widget.NewSelect(
		[]string{"Fast (1 proxy)", "Confirmed (2 proxies)", "Paranoid (3 proxies)"},
		func(s string) { verifyBlurb.SetText(verifyBlurbs[s]) },
	)
	verifySelect.Selected = "Confirmed (2 proxies)"

	// Proxy burn protection (off by default): spaces out reuse of each proxy so
	// a free SOCKS pool isn't hammered into rate-limits/bans mid-scan. This
	// protects your own proxies. It is not a target-evasion feature.
	burnCheck := widget.NewCheck("Proxy burn protection", nil)
	burnIntervalEntry := widget.NewEntry()
	burnIntervalEntry.SetText("2")
	burnIntervalEntry.SetPlaceHolder("sec")
	// (i) info button explains the small-pool trade-off on click.
	const smallPoolThreshold = 50
	burnInfoBtn := widget.NewButtonWithIcon("", theme.InfoIcon(), func() {
		n := st.pool.ValidCount()
		msg := "Proxy burn protection spaces out reuse of each proxy so a free SOCKS\n" +
			"pool isn't hammered into rate-limits or bans during a scan. It protects\n" +
			"your own proxies. It does not evade the target.\n\n" +
			"Works best with large pools.\n" +
			"Each port needs a few freshly-rested proxies per round. With a small\n" +
			"pool, ports run out of rested proxies and report \"unconfirmed\" (treated\n" +
			"as closed) sooner, so you can miss genuinely open ports.\n\n" +
			fmt.Sprintf("Rule of thumb: only enable this with a comfortably large pool\n"+
				"(roughly %d+ proxies). Below that, leave it off.\n\n", smallPoolThreshold)
		if n < smallPoolThreshold {
			msg += fmt.Sprintf("Warning: your pool has only %d valid proxy/proxies, which is small.\n"+
				"Burn protection may cause false negatives. Recommended: leave it off.", n)
		} else {
			msg += fmt.Sprintf("Your pool has %d valid proxies, large enough to use this safely.", n)
		}
		dialog.ShowInformation("Proxy burn protection", msg, w)
	})
	burnInfoBtn.Importance = widget.LowImportance
	burnRow := container.NewBorder(nil, nil, burnCheck,
		container.NewHBox(widget.NewLabel("min gap/proxy:"), burnIntervalEntry, widget.NewLabel("s"), burnInfoBtn), nil)

	configForm := container.New(layout.NewFormLayout(),
		widget.NewLabel("Tool:"), toolSelect,
		widget.NewLabel("Target:"), targetEntry,
		widget.NewLabel("Ports:"), container.NewBorder(nil, nil, nil, commonPortsCheck, portsEntry),
		widget.NewLabel("Timing:"), timingSelect,
		widget.NewLabel("Min-rate:"), minRateEntry,
		widget.NewLabel("Max-retries:"), maxRetriesEntry,
		widget.NewLabel("Concurrency:"), concEntry,
		widget.NewLabel("Scan mode:"), verifySelect,
		widget.NewLabel(""), verifyBlurb,
		widget.NewLabel("Burn protect:"), burnRow,
		widget.NewLabel("Extra args:"), extraEntry,
		widget.NewLabel("Custom cmd:"), customEntry,
	)

	// ── Controls ──
	activeProxyBind := binding.NewString()
	activeProxyBind.Set("—")
	scanCountBind := binding.NewString()
	scanCountBind.Set("0")
	scanProgressBind := binding.NewFloat()

	activeLabel := widget.NewLabelWithData(activeProxyBind)
	countLabel := widget.NewLabelWithData(scanCountBind)
	scanProgress := widget.NewProgressBarWithData(scanProgressBind)

	rotateCheck := widget.NewCheck("Rotate proxy per scan", nil)
	rotateCheck.SetChecked(true)
	wrapCheck := widget.NewCheck("Wrap pool when exhausted", nil)

	toolSelect.OnChanged = func(s string) {
		switch s {
		case "custom":
			customEntry.Enable()
			extraEntry.Enable()
			verifySelect.Disable()
			timingSelect.Disable()
			minRateEntry.Disable()
			maxRetriesEntry.Disable()
		case "nmap":
			customEntry.Disable()
			extraEntry.Enable()
			verifySelect.Enable()
			timingSelect.Enable()
			minRateEntry.Enable()
			maxRetriesEntry.Enable()
		default: // Built-in
			customEntry.Disable()
			extraEntry.Disable()
			verifySelect.Enable()
			timingSelect.Disable()
			minRateEntry.Disable()
			maxRetriesEntry.Disable()
		}
	}
	wrapCheck.SetChecked(true)

	// ── Log ──
	logBind := binding.NewString()
	logRich := widget.NewRichText()
	logRich.Wrapping = fyne.TextWrapOff
	logScroll := container.NewVScroll(logRich)

	var logMu sync.Mutex
	// appendLog is called from scan worker goroutines, so all widget mutation
	// runs through fyne.Do (Fyne 2.6+ requires UI updates on the main thread).
	appendLog := func(line string) {
		fyne.Do(func() {
			logMu.Lock()
			defer logMu.Unlock()
			cur, _ := logBind.Get()
			logBind.Set(cur + line)

			text := strings.TrimRight(line, "\n")
			trimmed := strings.TrimSpace(text)
			style := widget.RichTextStyle{TextStyle: fyne.TextStyle{Monospace: true}}
			switch {
			case strings.Contains(text, "► OPEN"):
				style.ColorName = theme.ColorNameForeground
				style.TextStyle = fyne.TextStyle{Bold: true, Monospace: true}
				text = "❗ " + text
			case strings.HasPrefix(trimmed, "[-]"):
				style.ColorName = theme.ColorNameError
			case strings.HasPrefix(trimmed, "[!]"):
				style.ColorName = theme.ColorNameWarning
			case strings.HasPrefix(trimmed, "[+]"), strings.HasPrefix(trimmed, "[=]"):
				style.ColorName = theme.ColorNameSuccess
			case strings.HasPrefix(trimmed, "[*]"):
				style.ColorName = theme.ColorNamePrimary
			}
			logRich.Segments = append(logRich.Segments, &widget.TextSegment{Text: text, Style: style})
			logRich.Refresh()
			logScroll.ScrollToBottom()
		})
	}
	clearLog := func() {
		logMu.Lock()
		defer logMu.Unlock()
		logBind.Set("")
		logRich.Segments = nil
		logRich.Refresh()
	}

	// buildNmapExtras assembles timing + user extra flags for nmap commands.
	// -Pn is always included: host discovery doesn't work through SOCKS proxies.
	buildNmapExtras := func() string {
		parts := []string{"-Pn"}
		switch timingSelect.Selected {
		case "Aggressive (T4)":
			parts = append(parts, "-T4")
		case "Insane (T5)":
			parts = append(parts, "-T5")
			// Default (T3) needs no flag - it's nmap's built-in default
		}
		if v := strings.TrimSpace(minRateEntry.Text); v != "" {
			parts = append(parts, "--min-rate", v)
		}
		if v := strings.TrimSpace(maxRetriesEntry.Text); v != "" {
			parts = append(parts, "--max-retries", v)
		}
		if ex := strings.TrimSpace(extraEntry.Text); ex != "" {
			parts = append(parts, ex)
		}
		return strings.Join(parts, " ")
	}

	// ── Queue (multi-target) ──
	queueEntry := widget.NewMultiLineEntry()
	queueEntry.SetPlaceHolder("Optional: one target per line\nEach target gets one proxy from the pool, then rotates\n(Leave empty to use single target above)")
	queueEntry.Wrapping = fyne.TextWrapOff

	var btnStart *widget.Button
	btnStop := widget.NewButton("■  Stop", func() {
		if st.scanCancel != nil {
			appendLog("[!] Stopping scan… (in-flight connections cancelled)\n")
			st.scanCancel()
		}
	})
	btnStop.Disable()

	btnStart = widget.NewButton("▶  Start Scan", func() {
		if st.scanRunning.Load() {
			return
		}
		if st.pool.ValidCount() == 0 {
			dialog.ShowInformation("No proxies", "Validate or add proxies to the pool first.", w)
			return
		}

		// Build target list
		var targets []string
		if queueEntry.Text != "" && queueEntry.Text != queueEntry.PlaceHolder {
			for _, t := range strings.Split(queueEntry.Text, "\n") {
				t = strings.TrimSpace(t)
				if t != "" {
					targets = append(targets, t)
				}
			}
		}
		if single := strings.TrimSpace(targetEntry.Text); single != "" {
			found := false
			for _, t := range targets {
				if t == single {
					found = true
					break
				}
			}
			if !found {
				targets = append([]string{single}, targets...)
			}
		}
		if len(targets) == 0 {
			dialog.ShowInformation("No target", "Enter a target host or IP.", w)
			return
		}

		conc, _ := strconv.Atoi(concEntry.Text)
		if conc <= 0 {
			conc = 200
		}

		ctx, cancel := context.WithCancel(context.Background())
		st.scanCancel = cancel
		st.scanRunning.Store(true)
		btnStart.Disable()
		btnStop.Enable()
		scanCountBind.Set("0")

		go func() {
			defer func() {
				st.scanRunning.Store(false)
				fyne.Do(func() {
					btnStart.Enable()
					btnStop.Disable()
				})
				activeProxyBind.Set("—")
				cancel()
			}()

			// Resolve nmap binary once per scan session
			nmapBin, nmapOK := cli.FindNmap("")
			if !nmapOK && toolSelect.Selected == "nmap" {
				appendLog("[!] nmap not found. Check Settings tab to configure path\n")
				appendLog("    (will still attempt: " + nmapBin + ")\n")
			}

			type hostResult struct {
				host     string
				findings []Finding
			}
			var scanResults []hostResult

			completed := 0
			wrap := wrapCheck.Checked
			rotate := rotateCheck.Checked

			for _, target := range targets {
				select {
				case <-ctx.Done():
					appendLog("[!] Scan stopped\n")
					return
				default:
				}

				px := st.pool.Next(wrap)
				if px == nil {
					appendLog("[-] Proxy pool exhausted, stopping\n")
					return
				}
				activeProxyBind.Set(px.Address())

				to := time.Duration(float64(time.Second) * st.timeout)
				portSpec := portsEntry.Text

				var targetFindings []Finding
				tool := toolSelect.Selected
				switch tool {

				case "Built-in (TCP connect)", "nmap":
					// Proxy-pool TCP scan governed by Scan mode (Fast/Confirmed/
					// Paranoid = 1/2/3 proxies must agree a port is open). Applies
					// regardless of any rotation checkbox - Scan mode is the authority.
					snap := st.pool.Valid()
					n := len(snap)
					if n == 0 {
						appendLog("[-] No proxies in pool\n")
						continue
					}
					{
						var totalOpenAtomic atomic.Int64
						var findingsMu sync.Mutex
						var chunkWg sync.WaitGroup
						var chunksDone atomic.Int64
						var chunksLaunched int // set before goroutines start
						scanProgressBind.Set(0)

						runChunk := func(idx int, proxyX *proxy.Proxy, chunkTarget, chunkPorts string) {
							defer func() {
								chunkWg.Done()
								done := chunksDone.Add(1)
								if chunksLaunched > 0 {
									scanProgressBind.Set(float64(done) / float64(chunksLaunched))
								}
							}()
							if ctx.Err() != nil {
								return
							}
							extras := buildNmapExtras()
							pArg, pStop, pErr := relay.NmapProxyArg(proxyX, to, appendLog)
							if pErr != nil {
								appendLog(fmt.Sprintf("[-] relay chunk %d: %v\n", idx, pErr))
								return
							}
							defer pStop()

							cmd := nmapCmd(nmapBin, chunkPorts, extras, pArg, chunkTarget, false)
							appendLog("  CMD: " + strings.Join(cmd, " ") + "\n")
							open, hostDown, chunkF := execNmapParsed(ctx, cmd, proxyX.URI(), appendLog)
							if open == 0 {
								if hostDown {
									appendLog(fmt.Sprintf("[!] Chunk %d/%d: hosts seem down, retrying with -Pn\n", idx, n))
								} else {
									appendLog(fmt.Sprintf("[!] Chunk %d/%d: 0 open, retrying with -Pn\n", idx, n))
								}
								retryCmd := nmapCmd(nmapBin, chunkPorts, extras, pArg, chunkTarget, true)
								appendLog("  CMD: " + strings.Join(retryCmd, " ") + "\n")
								retryOpen, _, retryF := execNmapParsed(ctx, retryCmd, proxyX.URI(), appendLog)
								open = retryOpen
								chunkF = append(chunkF, retryF...)
							}
							findingsMu.Lock()
							targetFindings = append(targetFindings, chunkF...)
							findingsMu.Unlock()
							totalOpenAtomic.Add(int64(open))
							appendLog(fmt.Sprintf("[+] Chunk %d/%d: %d open\n", idx, n, open))
						}

						// failedSet tracks proxies that failed (proxy-side) during this
						// scan so we can retry with others and prune them afterwards.
						var failedMu sync.Mutex
						failedSet := make(map[string]bool)
						markFailed := func(px *proxy.Proxy) {
							failedMu.Lock()
							failedSet[px.Address()] = true
							failedMu.Unlock()
						}
						isFailed := func(px *proxy.Proxy) bool {
							failedMu.Lock()
							defer failedMu.Unlock()
							return failedSet[px.Address()]
						}

						isCIDR := strings.Contains(target, "/")
						if isCIDR {
							allIPs, cidrErr := scanner.ExpandTarget(target)
							if cidrErr != nil {
								appendLog(fmt.Sprintf("[-] CIDR error: %v\n", cidrErr))
								break
							}
							rand.Shuffle(len(allIPs), func(i, j int) { allIPs[i], allIPs[j] = allIPs[j], allIPs[i] })
							chunkSize := (len(allIPs) + n - 1) / n
							appendLog(fmt.Sprintf("[*] nmap rotate  %s  %d hosts / %d proxies  ~%d hosts each  [parallel]\n",
								target, len(allIPs), n, chunkSize))
							for i := range snap {
								if i*chunkSize >= len(allIPs) {
									break
								}
								chunksLaunched++
							}

							for i, proxyX := range snap {
								start := i * chunkSize
								if start >= len(allIPs) {
									break
								}
								end := start + chunkSize
								if end > len(allIPs) {
									end = len(allIPs)
								}
								ipList := strings.Join(allIPs[start:end], " ")
								appendLog(fmt.Sprintf("[*] Chunk %d/%d  %d hosts  via %s\n", i+1, n, end-start, proxyX.URI()))
								chunkWg.Add(1)
								go runChunk(i+1, proxyX, ipList, portSpec)
							}
						} else {
							ports, parseErr := scanner.ParsePorts(portSpec)
							if parseErr != nil || len(ports) == 0 {
								appendLog(fmt.Sprintf("[-] Port spec error: %v\n", parseErr))
								break
							}
							// Both rotation paths use Go-native SOCKS5/SOCKS4 dial,
							// not nmap --proxies, which silently falls back to direct
							// on macOS when the proxy rejects or times out.
							if len(ports) <= n {
								// More proxies than ports: one goroutine per port, each
								// trying proxies in shuffled order until enough agree.
								shuffled := make([]*proxy.Proxy, len(snap))
								copy(shuffled, snap)
								rand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
								chunksLaunched = len(ports)

								// Quorum: how many proxies must independently agree a port
								// is open before we report it (guards against lying proxies).
								quorum := 1
								switch verifySelect.Selected {
								case "Confirmed (2 proxies)":
									quorum = 2
								case "Paranoid (3 proxies)":
									quorum = 3
								}
								if quorum > n {
									quorum = n
								}
								appendLog(fmt.Sprintf("[*] TCP rotate  %s  %d port(s) / %d proxies  1 port each  (need %d to agree open)  [parallel]\n",
									target, len(ports), n, quorum))

								// Optional proxy burn protection: skip any proxy used
								// within the configured gap so the pool isn't hammered.
								var throttle *scanner.ProxyThrottle
								if burnCheck.Checked {
									secs, _ := strconv.ParseFloat(strings.TrimSpace(burnIntervalEntry.Text), 64)
									if secs <= 0 {
										secs = 2
									}
									throttle = scanner.NewProxyThrottle(time.Duration(secs * float64(time.Second)))
									appendLog(fmt.Sprintf("[*] Burn protection on, each proxy rested %.0fs between uses\n", secs))
								}

								// Shared dial-concurrency cap across all ports and their
								// parallel confirmation batches.
								dialSem := make(chan struct{}, conc)

								for i, port := range ports {
									startIdx := i % len(shuffled)
									chunkWg.Add(1)
									go func(startIdx, port int) {
										defer chunkWg.Done()
										defer func() {
											done := chunksDone.Add(1)
											if chunksLaunched > 0 {
												scanProgressBind.Set(float64(done) / float64(chunksLaunched))
											}
										}()
										poolSize := len(shuffled)
										// Cap proxy-error retries so a flaky/filtered target
										// can't churn the entire pool.
										maxProxyRetries := 10
										if poolSize < maxProxyRetries {
											maxProxyRetries = poolSize
										}

										confirmations := 0 // distinct proxies that voted open
										proxyErrors := 0
										refuted := false
										var refutedBy string
										var openLabels []string // every proxy that voted open
										var openBanner string
										consumed := 0 // proxies tried

										// Probe proxies in PARALLEL batches: each round fires
										// (still-needed + 2) dials at once, so quorum is reached
										// in ~one round-trip instead of N sequential ones.
										for confirmations < quorum && !refuted &&
											proxyErrors < maxProxyRetries && consumed < poolSize {
											if ctx.Err() != nil {
												return
											}
											need := quorum - confirmations
											batchN := need + 2
											var batch []*proxy.Proxy
											for len(batch) < batchN && consumed < poolSize {
												p := shuffled[(startIdx+consumed)%poolSize]
												consumed++
												if isFailed(p) {
													continue
												}
												// Burn protection: skip a proxy used too recently.
												if !throttle.Ready(p.Address()) {
													continue
												}
												batch = append(batch, p)
											}
											if len(batch) == 0 {
												break
											}

											type voteResult struct {
												vote   int // 1 open, -1 refused, 0 proxy-error
												banner string
												label  string
												addr   string
											}
											results := make([]voteResult, len(batch))
											var bwg sync.WaitGroup
											for bi, p := range batch {
												bwg.Add(1)
												go func(bi int, p *proxy.Proxy) {
													defer bwg.Done()
													dialSem <- struct{}{}
													defer func() { <-dialSem }()
													if ctx.Err() != nil {
														return
													}
													conn, err := dialThroughProxyCtx(ctx, p, target, port, to)
													if ctx.Err() != nil {
														if conn != nil {
															conn.Close()
														}
														return
													}
													if err != nil {
														if proxy.IsProxyError(p.Address(), err) {
															markFailed(p)
															results[bi] = voteResult{vote: 0, addr: p.Address()}
														} else {
															results[bi] = voteResult{vote: -1, addr: p.Address()}
														}
														return
													}
													var banner string
													conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
													bbuf := make([]byte, 256)
													bn, _ := conn.Read(bbuf)
													if bn > 0 {
														banner = scanner.CleanBanner(bbuf[:bn])
													}
													conn.Close()
													results[bi] = voteResult{vote: 1, banner: banner, label: proxyViaLabel(p), addr: p.Address()}
												}(bi, p)
											}
											bwg.Wait()
											if ctx.Err() != nil {
												return
											}

											for _, r := range results {
												switch r.vote {
												case 1:
													confirmations++
													openLabels = append(openLabels, r.label)
													if openBanner == "" {
														openBanner = r.banner
													}
												case -1:
													refuted = true
													refutedBy = r.addr
												case 0:
													proxyErrors++
												}
											}
										}

										// Decide (pure verdict logic lives in scanner.DecideQuorum,
										// which is unit-tested; here we just render each outcome).
										switch scanner.DecideQuorum(confirmations, quorum, refuted) {
										case scanner.QuorumRefuted:
											if confirmations > 0 {
												appendLog(fmt.Sprintf("[!] Port %d refuted: %s reports closed after %d open vote(s), treating as closed\n", port, refutedBy, confirmations))
											} else {
												appendLog(fmt.Sprintf("[!] Port %d closed/filtered (refused by %s)\n", port, refutedBy))
											}
										case scanner.QuorumOpen:
											svc := scanner.PortService(port)
											if svc == "" {
												svc = "unknown"
											}
											portLine := fmt.Sprintf("%d/tcp   open  %s", port, svc)
											totalOpenAtomic.Add(1)
											appendLog(fmt.Sprintf("  ► OPEN  %s:%d  [%s]  (%d/%d agreed)\n", target, port, svc, confirmations, quorum))
											if openBanner != "" {
												appendLog("      │  " + openBanner + "\n")
											}
											for vi, lbl := range openLabels {
												branch := "├─"
												if vi == len(openLabels)-1 {
													branch = "└─"
												}
												appendLog("      " + branch + " via " + lbl + "\n")
											}
											primary := ""
											if len(openLabels) > 0 {
												primary = openLabels[0]
											}
											findingsMu.Lock()
											targetFindings = append(targetFindings, Finding{Host: target, Line: portLine, ProxyURI: primary, Proxies: openLabels, Banner: openBanner})
											findingsMu.Unlock()
										case scanner.QuorumUnconfirmed:
											appendLog(fmt.Sprintf("[!] Port %d unconfirmed (%d/%d agreed), treating as closed/filtered\n", port, confirmations, quorum))
										default: // scanner.QuorumUnreachable
											appendLog(fmt.Sprintf("[!] Port %d: no proxy could reach it (target may be filtered)\n", port))
										}
									}(startIdx, port)
								}
							} else {
								// More ports than proxies: chunk ports across proxies.
								chunkSize := (len(ports) + n - 1) / n
								appendLog(fmt.Sprintf("[*] TCP rotate  %s  %d ports / %d proxies  ~%d ports each  [parallel]\n",
									target, len(ports), n, chunkSize))
								for i := range snap {
									if i*chunkSize >= len(ports) {
										break
									}
									chunksLaunched++
								}
								for i, proxyX := range snap {
									start := i * chunkSize
									if start >= len(ports) {
										break
									}
									end := start + chunkSize
									if end > len(ports) {
										end = len(ports)
									}
									chunk := scanner.CompressPorts(ports[start:end])
									pxCopy := proxyX
									chunkLabel := proxyViaLabel(pxCopy)
									appendLog(fmt.Sprintf("[*] Chunk %d/%d  ports:%s  via %s\n", i+1, n, chunk, chunkLabel))
									chunkWg.Add(1)
									go func(pxCopy *proxy.Proxy, chunk, chunkLabel string, idx int) {
										defer chunkWg.Done()
										defer func() {
											done := chunksDone.Add(1)
											if chunksLaunched > 0 {
												scanProgressBind.Set(float64(done) / float64(chunksLaunched))
											}
										}()
										if ctx.Err() != nil {
											return
										}
										getP := func() *proxy.Proxy { return pxCopy }
										open, chunkF := guiBuiltinScan(ctx, getP, target, chunk, 50, to,
											binding.NewFloat(), appendLog, chunkLabel)
										totalOpenAtomic.Add(int64(open))
										findingsMu.Lock()
										targetFindings = append(targetFindings, chunkF...)
										findingsMu.Unlock()
										appendLog(fmt.Sprintf("[+] Chunk %d/%d: %d open\n", idx, n, open))
									}(pxCopy, chunk, chunkLabel, i+1)
								}
							}
						}

						chunkWg.Wait()
						scanProgressBind.Set(1.0)

						// Prune proxies that failed (proxy-side) during this scan.
						failedMu.Lock()
						numDead := len(failedSet)
						deadCopy := make(map[string]bool, numDead)
						for k, v := range failedSet {
							deadCopy[k] = v
						}
						failedMu.Unlock()
						if numDead > 0 {
							valid := st.pool.Valid()
							var survivors []*proxy.Proxy
							for _, p := range valid {
								if !deadCopy[p.Address()] {
									survivors = append(survivors, p)
								}
							}
							st.pool.SetValid(survivors)
							st.validMu.Lock()
							st.validRows = st.validRows[:0]
							for _, p := range survivors {
								st.validRows = append(st.validRows, p.DisplayValid())
							}
							st.validMu.Unlock()
							if st.refreshValidList != nil {
								st.refreshValidList()
							}
							if st.refreshCounts != nil {
								st.refreshCounts()
							}
							appendLog(fmt.Sprintf("[=] Pruned %d dead proxy/proxies from pool (%d remaining)\n",
								numDead, len(survivors)))
						}

						if ctx.Err() == nil {
							total := int(totalOpenAtomic.Load())
							if total == 0 {
								appendLog("[!] Still 0 open ports. Hosts may be down or all ports filtered.\n")
							}
							appendLog(fmt.Sprintf("[+] Total: %d open port(s) on %s\n", total, target))
						}

					}

				default: // custom
					runExternalTool(ctx, w, st, px, target,
						portSpec, extraEntry.Text,
						customEntry.Text, tool, appendLog)
				}

				st.pushFindings(targetFindings)
				scanResults = append(scanResults, hostResult{host: target, findings: targetFindings})
				completed++
				scanCountBind.Set(strconv.Itoa(completed))
				if rotate {
					st.pool.Advance()
				}
			}

			// ── Final open port summary ───────────────────────────────────
			appendLog("[=] ─────────────── OPEN PORT SUMMARY ───────────────\n")
			multiHost := len(scanResults) > 1
			anyOpen := false
			for _, hr := range scanResults {
				if len(hr.findings) > 0 {
					anyOpen = true
					break
				}
			}
			if !anyOpen {
				appendLog("    (no open ports found)\n")
			} else {
				for i, hr := range scanResults {
					if multiHost {
						if i > 0 {
							appendLog("\n")
						}
						appendLog("HOST: " + hr.host + "\n")
					}
					for _, f := range hr.findings {
						displayLine := f.Line
						if f.Host != "" {
							displayLine = f.Host + "  " + f.Line
						}
						appendLog("  ► OPEN  " + displayLine + "\n")
						if len(f.Proxies) > 0 {
							for vi, lbl := range f.Proxies {
								branch := "├─"
								if vi == len(f.Proxies)-1 {
									branch = "└─"
								}
								appendLog("      " + branch + " via " + lbl + "\n")
							}
						} else if f.ProxyURI != "" {
							appendLog("      └─ via " + f.ProxyURI + "\n")
						}
					}
					if multiHost && len(hr.findings) == 0 {
						appendLog("    (no open ports)\n")
					}
				}
			}
			appendLog("[=] ─────────────────────────────────────────────────\n")
			appendLog(fmt.Sprintf("[=] All scans complete, %d targets processed\n", completed))
		}()
	})

	controls := container.NewHBox(
		btnStart, btnStop,
		widget.NewSeparator(),
		widget.NewLabel("Active proxy:"), activeLabel,
		widget.NewSeparator(),
		widget.NewLabel("Completed:"), countLabel,
		layout.NewSpacer(),
		rotateCheck, wrapCheck,
	)

	logButtons := container.NewHBox(
		widget.NewButton("Clear Log", func() { clearLog() }),
		widget.NewButton("Save Log…", func() {
			dialog.ShowFileSave(func(f fyne.URIWriteCloser, err error) {
				if err != nil || f == nil {
					return
				}
				defer f.Close()
				cur, _ := logBind.Get()
				f.Write([]byte(cur))
			}, w)
		}),
	)

	outputSection := container.NewBorder(
		widget.NewLabelWithStyle("Output", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		logButtons, nil, nil,
		logScroll,
	)

	queueSection := container.NewBorder(
		widget.NewLabelWithStyle("Target Queue", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		nil, nil, nil,
		queueEntry,
	)

	splitLog := container.NewVSplit(queueSection, outputSection)
	splitLog.Offset = 0.25

	return container.NewBorder(
		container.NewVBox(configForm, controls, scanProgress),
		nil, nil, nil,
		splitLog,
	)
}

// runExternalTool handles the "custom" tool case only.
func runExternalTool(ctx context.Context, _ fyne.Window, _ *state,
	px *proxy.Proxy, target, ports, _, customTmpl, _ string,
	log func(string)) {

	rendered := strings.NewReplacer(
		"{proxy}", px.URI(),
		"{target}", target,
		"{ports}", ports,
	).Replace(customTmpl)
	cmd := strings.Fields(rendered)
	if len(cmd) == 0 {
		log("[-] Custom command template is empty\n")
		return
	}
	log("  CMD: " + strings.Join(cmd, " ") + "\n")
	execRun(ctx, cmd, log)
}

// ── Hosts tab ─────────────────────────────────────────────────────────────────

func buildHostsTab(st *state) fyne.CanvasObject {
	var selHost atomic.Int32
	var selPort atomic.Int32
	selHost.Store(-1)
	selPort.Store(-1)

	monoStyle := widget.RichTextStyle{TextStyle: fyne.TextStyle{Monospace: true}}
	headerStyle := widget.RichTextStyle{TextStyle: fyne.TextStyle{Bold: true, Monospace: true}}
	viaStyle := widget.RichTextStyle{
		TextStyle: fyne.TextStyle{Monospace: true},
		ColorName: theme.ColorNameSuccess,
	}

	// ── Port-detail pane (right): full proxy list for the selected port ──
	detailRich := widget.NewRichText()
	detailRich.Wrapping = fyne.TextWrapOff
	detailScroll := container.NewVScroll(detailRich)

	showPortDetail := func(hostIdx, portIdx int) {
		st.hostsMu.RLock()
		defer st.hostsMu.RUnlock()
		if hostIdx < 0 || hostIdx >= len(st.hostsSlice) {
			detailRich.Segments = []widget.RichTextSegment{
				&widget.TextSegment{Text: "← Select a host, then a port", Style: monoStyle},
			}
			detailRich.Refresh()
			return
		}
		h := st.hostsSlice[hostIdx]
		if portIdx < 0 || portIdx >= len(h.Ports) {
			detailRich.Segments = []widget.RichTextSegment{
				&widget.TextSegment{Text: "↑ Select a port to see every proxy that validated it", Style: monoStyle},
			}
			detailRich.Refresh()
			return
		}
		pe := h.Ports[portIdx]
		var segs []widget.RichTextSegment
		segs = append(segs, &widget.TextSegment{
			Text:  fmt.Sprintf("%d/%s   %s\n", pe.Port, pe.Proto, pe.Service),
			Style: headerStyle,
		})
		if pe.Version != "" {
			segs = append(segs, &widget.TextSegment{Text: "version: " + pe.Version + "\n", Style: monoStyle})
		}
		if pe.Banner != "" {
			segs = append(segs, &widget.TextSegment{Text: "banner:  " + pe.Banner + "\n", Style: monoStyle})
		}
		segs = append(segs, &widget.TextSegment{Text: strings.Repeat("─", 60) + "\n", Style: monoStyle})
		segs = append(segs, &widget.TextSegment{
			Text:  fmt.Sprintf("validated by %d proxy/proxies:\n", len(pe.Proxies)),
			Style: headerStyle,
		})
		for _, p := range pe.Proxies {
			segs = append(segs, &widget.TextSegment{Text: "  " + p + "\n", Style: viaStyle})
		}
		detailRich.Segments = segs
		detailRich.Refresh()
	}

	// ── Port list (middle): one row per open port, deduped ──
	var portList *widget.List
	portList = widget.NewList(
		func() int {
			st.hostsMu.RLock()
			defer st.hostsMu.RUnlock()
			hi := int(selHost.Load())
			if hi < 0 || hi >= len(st.hostsSlice) {
				return 0
			}
			return len(st.hostsSlice[hi].Ports)
		},
		func() fyne.CanvasObject {
			l := widget.NewLabel("")
			l.TextStyle = fyne.TextStyle{Monospace: true}
			return l
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			st.hostsMu.RLock()
			defer st.hostsMu.RUnlock()
			hi := int(selHost.Load())
			if hi < 0 || hi >= len(st.hostsSlice) {
				return
			}
			ports := st.hostsSlice[hi].Ports
			if int(id) >= len(ports) {
				return
			}
			pe := ports[id]
			detail := pe.Version
			if detail == "" {
				detail = pe.Banner
			}
			if len(detail) > 24 {
				detail = detail[:24] + "…"
			}
			obj.(*widget.Label).SetText(fmt.Sprintf("%-10s %-14s %-26s (%d proxies)",
				fmt.Sprintf("%d/%s", pe.Port, pe.Proto), pe.Service, detail, len(pe.Proxies)))
		},
	)
	portList.OnSelected = func(id widget.ListItemID) {
		selPort.Store(int32(id))
		showPortDetail(int(selHost.Load()), int(id))
	}

	// ── Host list (left) ──
	var hostList *widget.List
	hostList = widget.NewList(
		func() int {
			st.hostsMu.RLock()
			defer st.hostsMu.RUnlock()
			return len(st.hostsSlice)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			st.hostsMu.RLock()
			defer st.hostsMu.RUnlock()
			if int(id) < len(st.hostsSlice) {
				h := st.hostsSlice[id]
				obj.(*widget.Label).SetText(fmt.Sprintf("%s   (%d open)", h.IP, len(h.Ports)))
			}
		},
	)
	hostList.OnSelected = func(id widget.ListItemID) {
		selHost.Store(int32(id))
		selPort.Store(-1)
		portList.UnselectAll()
		portList.Refresh()
		showPortDetail(int(id), -1)
	}

	// hostsRefresh is invoked from scan worker goroutines (via pushFindings),
	// so all widget updates run on the main thread via fyne.Do.
	st.hostsRefresh = func() {
		fyne.Do(func() {
			hostList.Refresh()
			portList.Refresh()
			if hi := int(selHost.Load()); hi >= 0 {
				showPortDetail(hi, int(selPort.Load()))
			}
		})
	}
	showPortDetail(-1, -1)

	btnClear := widget.NewButton("Clear All", func() {
		st.clearHosts()
		selHost.Store(-1)
		selPort.Store(-1)
		hostList.UnselectAll()
		portList.UnselectAll()
		hostList.Refresh()
		portList.Refresh()
		showPortDetail(-1, -1)
	})

	leftPanel := container.NewBorder(
		container.NewHBox(
			widget.NewLabelWithStyle("Discovered Hosts", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			layout.NewSpacer(),
			btnClear,
		),
		nil, nil, nil,
		hostList,
	)

	midPanel := container.NewBorder(
		widget.NewLabelWithStyle("Open Ports", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		nil, nil, nil,
		portList,
	)

	rightPanel := container.NewBorder(
		widget.NewLabelWithStyle("Validating Proxies", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		nil, nil, nil,
		detailScroll,
	)

	// hosts | ports | proxies
	inner := container.NewHSplit(midPanel, rightPanel)
	inner.Offset = 0.5
	split := container.NewHSplit(leftPanel, inner)
	split.Offset = 0.2
	return split
}

// ── Settings tab ──────────────────────────────────────────────────────────────

func buildSettingsTab(st *state) fyne.CanvasObject {
	threadsEntry := widget.NewEntry()
	threadsEntry.SetText(strconv.Itoa(st.threads))

	timeoutEntry := widget.NewEntry()
	timeoutEntry.SetText(fmt.Sprintf("%.1f", st.timeout))

	testHostEntry := widget.NewEntry()
	testHostEntry.SetText(st.testHost)

	testPortEntry := widget.NewEntry()
	testPortEntry.SetText(strconv.Itoa(st.testPort))

	wrapCheck := widget.NewCheck("Wrap proxy pool when exhausted", nil)
	wrapCheck.SetChecked(st.wrap)

	// Handler is assigned below, after the auto-revalidation widgets exist.
	saveBtn := widget.NewButton("Save Settings", nil)

	// ── nmap detection section ──────────────────────────────────────────────
	nmapStatusBind := binding.NewString()
	updateNmapStatus := func() {
		p, found := cli.FindNmap("")
		if found {
			nmapStatusBind.Set("✓  Found: " + p)
		} else {
			nmapStatusBind.Set("✗  Not found. Install nmap or set path below")
		}
	}
	updateNmapStatus()

	nmapStatusLabel := widget.NewLabelWithData(nmapStatusBind)
	nmapStatusLabel.Wrapping = fyne.TextWrapWord

	nmapPathEntry := widget.NewEntry()
	nmapPathEntry.SetPlaceHolder("/usr/local/bin/nmap  (leave empty to auto-detect)")
	if p := cli.LoadConfig()["nmap_path"]; p != "" {
		nmapPathEntry.SetText(p)
	}

	nmapSaveBtn := widget.NewButton("Save Path", func() {
		p := strings.TrimSpace(nmapPathEntry.Text)
		if p == "" {
			_ = cli.SetConfigKey("nmap_path", "")
		} else {
			_ = cli.SetConfigKey("nmap_path", p)
		}
		updateNmapStatus()
	})
	nmapDetectBtn := widget.NewButton("Re-detect", func() {
		updateNmapStatus()
	})

	installNote := widget.NewLabel(
		"macOS:    brew install nmap\n" +
			"Debian:   apt install nmap\n" +
			"Fedora:   dnf install nmap\n" +
			"Windows:  winget install nmap")
	installNote.Wrapping = fyne.TextWrapWord

	nmapForm := container.New(layout.NewFormLayout(),
		widget.NewLabel("Status:"), nmapStatusLabel,
		widget.NewLabel("Custom path:"), nmapPathEntry,
		widget.NewLabel(""), container.NewHBox(nmapSaveBtn, nmapDetectBtn),
		widget.NewLabel("Install:"), installNote,
	)

	// ── validation settings form ────────────────────────────────────────────
	valForm := container.New(layout.NewFormLayout(),
		widget.NewLabel("Validation threads:"), threadsEntry,
		widget.NewLabel("Validation timeout (s):"), timeoutEntry,
		widget.NewLabel("Test hostname:"), testHostEntry,
		widget.NewLabel("Test port:"), testPortEntry,
		widget.NewLabel(""), wrapCheck,
	)

	// ── auto-revalidation ────────────────────────────────────────────────────
	autoRevalCheck := widget.NewCheck("Auto-revalidate pool on interval", nil)
	autoRevalMinsEntry := widget.NewEntry()
	autoRevalMinsEntry.SetText("30")
	autoRevalMinsEntry.SetPlaceHolder("minutes")

	revalStatusLabel := widget.NewLabelWithData(st.revalStatus)
	revalStatusLabel.Wrapping = fyne.TextWrapWord

	autoRevalForm := container.New(layout.NewFormLayout(),
		widget.NewLabel("Enabled:"), autoRevalCheck,
		widget.NewLabel("Interval (minutes):"), autoRevalMinsEntry,
		widget.NewLabel("Status:"), revalStatusLabel,
	)

	saveBtn.OnTapped = func() {
		if n, err := strconv.Atoi(threadsEntry.Text); err == nil && n > 0 {
			st.threads = n
		}
		if f, err := strconv.ParseFloat(timeoutEntry.Text, 64); err == nil && f > 0 {
			st.timeout = f
		}
		if h := strings.TrimSpace(testHostEntry.Text); h != "" {
			st.testHost = h
		}
		if n, err := strconv.Atoi(testPortEntry.Text); err == nil && n > 0 {
			st.testPort = n
		}
		st.wrap = wrapCheck.Checked

		if autoRevalCheck.Checked {
			mins, _ := strconv.Atoi(autoRevalMinsEntry.Text)
			if mins <= 0 {
				mins = 30
			}
			st.startAutoReval(time.Duration(mins) * time.Minute)
			st.revalStatus.Set(fmt.Sprintf("Revalidation scheduled every %d min", mins))
		} else {
			st.stopAutoReval()
			st.revalStatus.Set("Disabled")
		}
	}

	return container.NewVBox(
		widget.NewCard("nmap", "Required for nmap scanning mode", nmapForm),
		widget.NewCard("Validation & Pool", "", valForm),
		widget.NewCard("Auto-Revalidation", "Periodically re-check the pool and drop dead proxies", autoRevalForm),
		saveBtn,
	)
}
