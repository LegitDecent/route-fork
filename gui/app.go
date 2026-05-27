package gui

import (
	"context"
	"fmt"
	"math/rand"
	"os"
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

	"proxymgr/cli"
	"proxymgr/pool"
	"proxymgr/proxy"
	"proxymgr/relay"
	"proxymgr/scanner"
)

// ── State ─────────────────────────────────────────────────────────────────────

// HostRecord accumulates open-port findings for a single discovered host.
type HostRecord struct {
	IP       string
	Findings []Finding
}

type state struct {
	pool *pool.Pool

	validMu  sync.RWMutex
	validRows []string // formatted display rows

	failedMu   sync.RWMutex
	failedRows []string

	valCancel  context.CancelFunc
	scanCancel context.CancelFunc
	valRunning atomic.Bool
	scanRunning atomic.Bool

	// discovered hosts (Hosts tab)
	hostsMu     sync.RWMutex
	hostsMap    map[string]int // IP → index in hostsSlice
	hostsSlice  []*HostRecord
	hostsRefresh func() // set by buildHostsTab

	// settings
	threads  int
	timeout  float64
	testHost string
	testPort int
	wrap     bool
}

func newState() *state {
	return &state{
		pool:     pool.New(),
		hostsMap: make(map[string]int),
		threads:  100,
		timeout:  10,
		testHost: "www.google.com",
		testPort: 80,
		wrap:     true,
	}
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
			st.hostsSlice = append(st.hostsSlice, &HostRecord{IP: f.Host})
		}
		st.hostsSlice[idx].Findings = append(st.hostsSlice[idx].Findings, f)
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

// ── Entry point ───────────────────────────────────────────────────────────────

func Run() {
	a := app.NewWithID("com.proxymgr.app")
	a.Settings().SetTheme(theme.DarkTheme())

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
	inputEntry.SetPlaceHolder("Paste proxies here — one per line\n\nFormats:\n  host:port\n  socks5://host:port\n  socks4://host:port\n  socks5://user:pass@host:port\n  host:port:user:pass")
	inputEntry.Wrapping = fyne.TextWrapOff

	// ── Progress / status bindings ──
	progressBind := binding.NewFloat()
	statusBind   := binding.NewString()
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

	validCountBind  := binding.NewString()
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
				btnValidate.SetText("▶  Validate All")
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
					statusBind.Set(fmt.Sprintf("Stopped — Valid: %d  Failed: %d",
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
					n := done.Add(1)
					pct := float64(n) / float64(total)
					progressBind.Set(pct)
					statusBind.Set(fmt.Sprintf("Validating %d / %d  (%.0f%%)", n, total, pct*100))

					if ok {
						p.Status = proxy.StatusValid
						p.LatencyMs = ms
						st.pool.AddValid(p)
						st.validMu.Lock()
						st.validRows = append(st.validRows, p.DisplayValid())
						st.validMu.Unlock()
						validList.Refresh()
					} else {
						p.Status = proxy.StatusInvalid
						p.FailReason = errStr
						st.pool.AddFailed(p)
						st.failedMu.Lock()
						st.failedRows = append(st.failedRows, p.DisplayFailed())
						st.failedMu.Unlock()
						failedList.Refresh()
					}
					refreshCounts()
				}(p)
			}
			wg.Wait()
			progressBind.Set(1.0)
			statusBind.Set(fmt.Sprintf("Done — Valid: %d  Failed: %d  Total: %d",
				st.pool.ValidCount(), st.pool.FailedCount(), total))
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
			log(fmt.Sprintf("  ► OPEN  %s:%d\n", r.Host, r.Port))
			if proxyLabel != "" {
				log("      └─ via " + proxyLabel + "\n")
			}
			findings = append(findings, Finding{
				Host:     r.Host,
				Line:     fmt.Sprintf("%d/tcp   open", r.Port),
				ProxyURI: proxyLabel,
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

	configForm := container.New(layout.NewFormLayout(),
		widget.NewLabel("Tool:"), toolSelect,
		widget.NewLabel("Target:"), targetEntry,
		widget.NewLabel("Ports:"), portsEntry,
		widget.NewLabel("Timing:"), timingSelect,
		widget.NewLabel("Min-rate:"), minRateEntry,
		widget.NewLabel("Max-retries:"), maxRetriesEntry,
		widget.NewLabel("Concurrency:"), concEntry,
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
	rotatePerPortCheck := widget.NewCheck("Rotate proxy per port", nil)
	// rotatePerPortCheck starts enabled — both nmap (chunk-rotation) and Built-in support it
	wrapCheck := widget.NewCheck("Wrap pool when exhausted", nil)
	commonPortsCheck := widget.NewCheck("Add common ports on retry", nil)

	toolSelect.OnChanged = func(s string) {
		switch s {
		case "custom":
			customEntry.Enable()
			extraEntry.Enable()
			rotatePerPortCheck.Disable()
			timingSelect.Disable()
			minRateEntry.Disable()
			maxRetriesEntry.Disable()
		case "nmap":
			customEntry.Disable()
			extraEntry.Enable()
			rotatePerPortCheck.Enable()
			timingSelect.Enable()
			minRateEntry.Enable()
			maxRetriesEntry.Enable()
		default: // Built-in
			customEntry.Disable()
			extraEntry.Disable()
			rotatePerPortCheck.Enable()
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
	appendLog := func(line string) {
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
	}
	clearLog := func() {
		logMu.Lock()
		defer logMu.Unlock()
		logBind.Set("")
		logRich.Segments = nil
		logRich.Refresh()
	}

	// buildNmapExtras assembles timing + user extra flags for nmap commands.
	buildNmapExtras := func() string {
		var parts []string
		switch timingSelect.Selected {
		case "Aggressive (T4)":
			parts = append(parts, "-T4")
		case "Insane (T5)":
			parts = append(parts, "-T5")
		// Default (T3) needs no flag — it's nmap's built-in default
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
				btnStart.Enable()
				btnStop.Disable()
				activeProxyBind.Set("—")
				cancel()
			}()

			// Resolve nmap binary once per scan session
			nmapBin, nmapOK := cli.FindNmap("")
			if !nmapOK && toolSelect.Selected == "nmap" {
				appendLog("[!] nmap not found — check Settings tab to configure path\n")
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
					appendLog("[-] Proxy pool exhausted — stopping\n")
					return
				}
				activeProxyBind.Set(px.Address())

				to := time.Duration(float64(time.Second) * st.timeout)
				portSpec := portsEntry.Text

				// Build getProxy: random proxy per connection from pool snapshot
				var getProxy func() *proxy.Proxy
				var proxyLabel string
				if rotatePerPortCheck.Checked {
					snap := st.pool.Valid()
					if len(snap) == 0 {
						appendLog("[-] No proxies in pool\n")
						continue
					}
					getProxy = func() *proxy.Proxy {
						return snap[rand.Intn(len(snap))]
					}
					proxyLabel = fmt.Sprintf("[random from %d proxies]", len(snap))
				} else {
					getProxy = func() *proxy.Proxy { return px }
					proxyLabel = px.URI()
				}

				var targetFindings []Finding
				tool := toolSelect.Selected
				switch tool {

				case "Built-in (TCP connect)":
					if rotatePerPortCheck.Checked {
						appendLog(fmt.Sprintf("[*] Built-in scan  %s  ports:%s  rotating through %d proxies\n",
							target, portSpec, len(st.pool.Valid())))
					} else {
						appendLog(fmt.Sprintf("[*] Built-in scan  %s  ports:%s  via %s\n",
							target, portSpec, proxyLabel))
					}
					scanProgressBind.Set(0)
					openCount, f1 := guiBuiltinScan(ctx, getProxy, target, portSpec,
						conc, to, scanProgressBind, appendLog, proxyLabel)
					targetFindings = append(targetFindings, f1...)
					scanProgressBind.Set(1.0)
					appendLog(fmt.Sprintf("[+] %d open port(s) on %s\n", openCount, target))

					if openCount == 0 {
						retry := portSpec
						if commonPortsCheck.Checked {
							retry = mergeCommonPorts(portSpec)
							appendLog("[!] No open ports — retrying with -Pn + common ports...\n")
						} else {
							appendLog("[!] No open ports — retrying with -Pn on same ports...\n")
						}
						scanProgressBind.Set(0)
						openCount2, f2 := guiBuiltinScan(ctx, getProxy, target, retry,
							conc, to, scanProgressBind, appendLog, proxyLabel)
						targetFindings = append(targetFindings, f2...)
						scanProgressBind.Set(1.0)
						appendLog(fmt.Sprintf("[+] Retry: %d open port(s) on %s\n", openCount2, target))
						if openCount2 == 0 {
							appendLog("[!] Still 0 open ports. Host may be down or all ports filtered.\n")
						}
					}

				case "nmap":
					if rotatePerPortCheck.Checked {
						snap := st.pool.Valid()
						n := len(snap)
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
							pArg, pStop, pErr := relay.NmapProxyArg(proxyX, to)
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
									appendLog(fmt.Sprintf("[!] Chunk %d/%d: hosts seem down — retrying with -Pn\n", idx, n))
								} else {
									appendLog(fmt.Sprintf("[!] Chunk %d/%d: 0 open — retrying with -Pn\n", idx, n))
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
							chunkSize := (len(ports) + n - 1) / n
							appendLog(fmt.Sprintf("[*] nmap rotate  %s  %d ports / %d proxies  ~%d ports each  [parallel]\n",
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
								appendLog(fmt.Sprintf("[*] Chunk %d/%d  ports:%s  via %s\n", i+1, n, chunk, proxyX.URI()))
								chunkWg.Add(1)
								go runChunk(i+1, proxyX, target, chunk)
							}
						}

						chunkWg.Wait()
						scanProgressBind.Set(1.0)
						if ctx.Err() == nil {
							total := int(totalOpenAtomic.Load())
							if total == 0 {
								appendLog("[!] Still 0 open ports. Hosts may be down or all ports filtered.\n")
							}
							appendLog(fmt.Sprintf("[+] Total: %d open port(s) on %s\n", total, target))
						}

					} else {
						// Single proxy nmap with auto-retry
						proxyArg, stop, err := relay.NmapProxyArg(px, to)
						if err != nil {
							appendLog(fmt.Sprintf("[-] relay: %v\n", err))
							break
						}
						extras := buildNmapExtras()
						scanProgressBind.Set(0)

						cmd1 := nmapCmd(nmapBin, portSpec, extras, proxyArg, target, false)
						appendLog("  CMD: " + strings.Join(cmd1, " ") + "\n")
						open, hostDown, f1 := execNmapParsed(ctx, cmd1, px.URI(), appendLog)
						targetFindings = append(targetFindings, f1...)
						appendLog(fmt.Sprintf("[+] %d open port(s) on %s\n", open, target))

						if open == 0 {
							scanProgressBind.Set(0.5)
							if hostDown {
								appendLog("[!] nmap says host seems down (blocking ping probes).\n")
							} else {
								appendLog("[!] 0 open ports found on initial scan.\n")
							}
							retryPorts := portSpec
							if commonPortsCheck.Checked {
								retryPorts = mergeCommonPorts(portSpec)
								appendLog("[*] Retrying with -Pn + common ports...\n")
							} else {
								appendLog("[*] Retrying with -Pn on same ports...\n")
							}
							cmd2 := nmapCmd(nmapBin, retryPorts, extras, proxyArg, target, true)
							appendLog("  CMD: " + strings.Join(cmd2, " ") + "\n")
							open2, _, f2 := execNmapParsed(ctx, cmd2, px.URI(), appendLog)
							targetFindings = append(targetFindings, f2...)
							appendLog(fmt.Sprintf("[+] Retry: %d open port(s) on %s\n", open2, target))
							if open2 == 0 {
								appendLog("[!] Still 0 open ports. Host may be down or all ports filtered.\n")
							}
						}
						scanProgressBind.Set(1.0)
						stop()
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
						if f.ProxyURI != "" {
							appendLog("      └─ via " + f.ProxyURI + "\n")
						}
					}
					if multiHost && len(hr.findings) == 0 {
						appendLog("    (no open ports)\n")
					}
				}
			}
			appendLog("[=] ─────────────────────────────────────────────────\n")
			appendLog(fmt.Sprintf("[=] All scans complete — %d targets processed\n", completed))
		}()
	})

	controls := container.NewHBox(
		btnStart, btnStop,
		widget.NewSeparator(),
		widget.NewLabel("Active proxy:"), activeLabel,
		widget.NewSeparator(),
		widget.NewLabel("Completed:"), countLabel,
		layout.NewSpacer(),
		rotateCheck, rotatePerPortCheck, wrapCheck, commonPortsCheck,
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
	var selectedIdx atomic.Int32
	selectedIdx.Store(-1)

	monoStyle := widget.RichTextStyle{TextStyle: fyne.TextStyle{Monospace: true}}
	headerStyle := widget.RichTextStyle{TextStyle: fyne.TextStyle{Bold: true, Monospace: true}}
	openStyle := widget.RichTextStyle{
		TextStyle: fyne.TextStyle{Monospace: true},
		ColorName: theme.ColorNameSuccess,
	}

	detailRich := widget.NewRichText()
	detailRich.Wrapping = fyne.TextWrapOff
	detailScroll := container.NewVScroll(detailRich)

	showDetail := func(idx int) {
		st.hostsMu.RLock()
		defer st.hostsMu.RUnlock()
		if idx < 0 || idx >= len(st.hostsSlice) {
			detailRich.Segments = []widget.RichTextSegment{
				&widget.TextSegment{
					Text:  "← Select a host from the list to view port details",
					Style: monoStyle,
				},
			}
			detailRich.Refresh()
			return
		}
		h := st.hostsSlice[idx]
		var segs []widget.RichTextSegment

		segs = append(segs, &widget.TextSegment{
			Text:  fmt.Sprintf("Host: %s   —   %d open port(s)\n", h.IP, len(h.Findings)),
			Style: headerStyle,
		})
		segs = append(segs, &widget.TextSegment{Text: strings.Repeat("─", 76) + "\n", Style: monoStyle})
		segs = append(segs, &widget.TextSegment{
			Text:  fmt.Sprintf("%-12s %-22s %-32s %s\n", "PORT", "SERVICE", "VERSION", "VIA"),
			Style: headerStyle,
		})
		segs = append(segs, &widget.TextSegment{Text: strings.Repeat("─", 76) + "\n", Style: monoStyle})

		for _, f := range h.Findings {
			pd := parsePortLine(f.Line)
			portProto := pd.Port + "/" + pd.Proto
			segs = append(segs, &widget.TextSegment{
				Text: fmt.Sprintf("%-12s %-22s %-32s %s\n",
					portProto, pd.Service, pd.Version, f.ProxyURI),
				Style: openStyle,
			})
		}

		detailRich.Segments = segs
		detailRich.Refresh()
	}
	showDetail(-1)

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
				obj.(*widget.Label).SetText(fmt.Sprintf("%s   (%d open)", h.IP, len(h.Findings)))
			}
		},
	)
	hostList.OnSelected = func(id widget.ListItemID) {
		selectedIdx.Store(int32(id))
		showDetail(int(id))
	}

	st.hostsRefresh = func() {
		hostList.Refresh()
		if idx := int(selectedIdx.Load()); idx >= 0 {
			showDetail(idx)
		}
	}

	btnClear := widget.NewButton("Clear All", func() {
		st.clearHosts()
		selectedIdx.Store(-1)
		hostList.Refresh()
		showDetail(-1)
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

	rightPanel := container.NewBorder(
		widget.NewLabelWithStyle("Port Details", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		nil, nil, nil,
		detailScroll,
	)

	split := container.NewHSplit(leftPanel, rightPanel)
	split.Offset = 0.22
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

	saveBtn := widget.NewButton("Save Settings", func() {
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
	})

	// ── nmap detection section ──────────────────────────────────────────────
	nmapStatusBind := binding.NewString()
	updateNmapStatus := func() {
		p, found := cli.FindNmap("")
		if found {
			nmapStatusBind.Set("✓  Found: " + p)
		} else {
			nmapStatusBind.Set("✗  Not found — install nmap or set path below")
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

	return container.NewVBox(
		widget.NewCard("nmap", "Required for nmap scanning mode", nmapForm),
		widget.NewCard("Validation & Pool", "", valForm),
		saveBtn,
	)
}
