package main

import (
	"dhcplane/arp"
	"dhcplane/config"
	"dhcplane/console"
	"dhcplane/dhcpserver"
	"dhcplane/statistics"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/logrusorgru/aurora"
	"github.com/spf13/cobra"
	"gopkg.in/natefinch/lumberjack.v2"
)

var appVersion = "0.1.43"

func buildConsoleConfig(maxLines int) console.Config {
	if maxLines <= 0 {
		maxLines = console.DefaultMaxLines
	}
	return console.Config{
		MaxLines: maxLines,
		Counters: []console.CounterSpec{
			{Match: "REQUEST", CaseSensitive: false, Label: "RPM", WindowSeconds: 60},
			{Match: "ACK", CaseSensitive: false, Label: "APM", WindowSeconds: 60},
		},
		Highlights: []console.HighlightSpec{
			{Match: "BANNED-MAC", CaseSensitive: true, Style: &console.Style{FG: "red", Attrs: "b"}},
			{Match: "NAK", CaseSensitive: true, Style: &console.Style{FG: "red", Attrs: "b"}},
			{Match: "ACK", CaseSensitive: true, Style: &console.Style{FG: "green", Attrs: "b"}},
			{Match: "OFFER", CaseSensitive: true, Style: &console.Style{FG: "green", Attrs: "b"}},
			{Match: "REQUEST", CaseSensitive: true, Style: &console.Style{FG: "yellow", Attrs: "b"}},
			{Match: "DISCOVER", CaseSensitive: true, Style: &console.Style{FG: "yellow", Attrs: "b"}},
			{Match: "RELEASE", CaseSensitive: true, Style: &console.Style{FG: "yellow", Attrs: "b"}},
			{Match: "DECLINE", CaseSensitive: true, Style: &console.Style{FG: "yellow", Attrs: "b"}},
			{Match: "DETECT", CaseSensitive: true, Style: &console.Style{FG: "green", Attrs: "b"}},
			{Match: "FOREIGN-DHCP", CaseSensitive: true, Style: &console.Style{FG: "red", Attrs: "b"}},
			{Match: "ARP-ANOMALY", CaseSensitive: true, Style: &console.Style{FG: "red", Attrs: "b"}},
		},
	}
}

func consoleSocketCandidates() []string {
	candidates := []string{
		"/run/dhcplane/consoleui.sock",
		"/tmp/consoleui.sock",
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		candidates = append(candidates, filepath.Join(xdg, "dhcplane.sock"))
	}
	return candidates
}

// buildConsoleBroker wires the generic console broker with our DHCP-specific counters and highlights.
func buildConsoleBroker(maxLines int) *console.Broker {
	return console.NewBroker(console.BrokerOptions{
		Config:           buildConsoleConfig(maxLines),
		SocketCandidates: consoleSocketCandidates(),
	})
}

/* ----------------- Logging ----------------- */

func setupLogger(cfg config.Config) (*log.Logger, io.Closer, error) {
	filename := cfg.Logging.Filename
	if filename == "" {
		filename = "dhcplane.log"
	}
	full := filename
	if cfg.Logging.Path != "" {
		full = filepath.Join(cfg.Logging.Path, filename)
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil && !os.IsExist(err) {
		return nil, nil, err
	}
	rot := &lumberjack.Logger{
		Filename:   full,
		MaxSize:    cfg.Logging.MaxSize,
		MaxBackups: cfg.Logging.MaxBackups,
		MaxAge:     cfg.Logging.MaxAge,
		Compress:   cfg.Logging.Compress,
	}
	lg := log.New(rot, "", log.LstdFlags|log.Lmicroseconds)
	return lg, rot, nil
}

func writePID(pidPath string) error {
	if pidPath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(pidPath), 0o755); err != nil && !os.IsExist(err) {
		return err
	}
	return os.WriteFile(pidPath, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644)
}

func readPID(pidPath string) (int, error) {
	b, err := os.ReadFile(pidPath)
	if err != nil {
		return 0, err
	}
	var pid int
	_, err = fmt.Sscanf(string(b), "%d", &pid)
	if err != nil {
		return 0, err
	}
	return pid, nil
}

/* ----------------- Server bootstrap ----------------- */

// logDetect prints the detection mode line to logs and console via logSink.
func logDetect(cfg *config.Config, iface string, logSink func(string, ...any)) {
	if cfg.DetectDHCPServers.Enabled {
		logSink("DETECT start mode=%s interval=%ds rate_limit=%d/min iface=%s whitelist=%d",
			strings.ToLower(strings.TrimSpace(cfg.DetectDHCPServers.ActiveProbe)),
			cfg.DetectDHCPServers.ProbeInterval,
			cfg.DetectDHCPServers.RateLimit,
			iface,
			len(cfg.DetectDHCPServers.WhitelistServers),
		)
	} else {
		logSink("DETECT disabled (config) iface=%s", iface)
	}
}

// buildServerAndRun starts the DHCP server and optional console broker, handles reloads and signals.
func buildServerAndRun(cfgPath string, enableConsole bool) error {
	// Load + validate/normalize initial config
	raw, jerr := config.ParseStrict(cfgPath)
	if jerr != nil {
		return fmt.Errorf("config error: %w", jerr)
	}
	cfg, warns, verr := config.ValidateAndNormalizeConfig(raw)
	if verr != nil {
		return fmt.Errorf("config validation: %w", verr)
	}

	leasePath := cfg.LeaseDBPath
	db := dhcpserver.NewLeaseDB(leasePath)
	if err := db.Load(); err != nil {
		log.Printf("lease db load: %v (continuing with empty)", err)
	}

	// Logger (file or rotating)
	lg, closer, err := setupLogger(cfg)
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	defer func() {
		if closer != nil {
			_ = closer.Close()
		}
	}()

	// Optional console broker (exports console over UNIX socket)
	var consoleBroker *console.Broker
	if enableConsole {
		maxLines := cfg.ConsoleMaxLines
		if maxLines <= 0 {
			maxLines = console.DefaultMaxLines
		}
		consoleBroker = buildConsoleBroker(maxLines)
		if err := consoleBroker.Start(); err != nil {
			return fmt.Errorf("console broker: %w", err)
		}
		defer consoleBroker.Stop()
	}

	// Sinks
	logSink := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if lg != nil {
			lg.Printf("%s", msg)
		}

		ts := time.Now().Format("2006/01/02 15:04:05.000000")

		if consoleBroker != nil {
			consoleBroker.Append(ts + " " + msg)
		}

		fmt.Fprintln(os.Stdout, msg)
	}
	errorSink := func(format string, args ...any) {
		msg := fmt.Sprintf("ERROR: "+format, args...)
		if lg != nil {
			lg.Printf("%s", msg)
		}
		ts := time.Now().Format("2006/01/02 15:04:05.000000")
		if consoleBroker != nil {
			consoleBroker.Append(ts + " " + msg)
		}
		fmt.Fprintln(os.Stderr, msg)
	}

	// Log initial warnings
	for _, w := range warns {
		logSink("%s", w)
	}

	// Atomic config snapshot
	var cfgAtomic atomic.Value
	cfgAtomic.Store(&cfg)
	cfgGet := func() *config.Config { return cfgAtomic.Load().(*config.Config) }

	// Authoritative getter from config (default: true when unset)
	effectiveAuthoritative := func(c *config.Config) bool {
		if c == nil || c.Authoritative == nil {
			return true
		}
		return *c.Authoritative
	}
	authorGet := func() bool { return effectiveAuthoritative(cfgGet()) }

	// One-shot compaction on initial load ONLY if enabled
	if cfg.CompactOnLoad {
		sticky := time.Duration(cfg.LeaseStickySeconds) * time.Second
		if n := db.CompactNow(sticky); n > 0 {
			logSink("LEASE-COMPACT removed=%d (on initial load)", n)
		}
	}

	// Enforce reservations immediately
	dhcpserver.EnforceReservationLeaseConsistency(db, &cfg)

	// PID
	if err := writePID(cfg.PIDFile); err != nil {
		return fmt.Errorf("write pid: %w", err)
	}

	// Decoupled DHCP server
	s := dhcpserver.NewServer(db, cfgGet, authorGet, logSink, errorSink)

	// Bind + Serve, with rebind support when Interface changes
	laddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 67}
	var closerUDP ioCloser
	var currentIface = cfg.Interface

	bind := func(newIface string) error {
		if closerUDP != nil {
			_ = closerUDP.Close()
			closerUDP = nil
		}
		c, err := s.BindAndServe(newIface, laddr)
		if err != nil {
			return err
		}
		closerUDP = c
		currentIface = newIface
		return nil
	}
	if err := bind(currentIface); err != nil {
		return fmt.Errorf("bind: %w (need root/CAP_NET_BIND_SERVICE)", err)
	}

	logSink("START iface=%q bind=%s server_ip=%s subnet=%s gateway=%s lease=%s sticky=%s authoritative=%v",
		currentIface, laddr.String(), cfg.ServerIP, cfg.SubnetCIDR, cfg.Gateway,
		time.Duration(cfg.LeaseSeconds)*time.Second, time.Duration(cfg.LeaseStickySeconds)*time.Second, effectiveAuthoritative(&cfg))
	if cfg.AutoReload {
		logSink("START auto_reload=true (watching %s)", cfgPath)
	}

	// DETECT announcement on startup
	logDetect(&cfg, currentIface, logSink)

	// ARP anomaly scheduler (goroutine-based)
	if cfg.ARPAnomalyDetection.Enabled {
		first := time.Duration(cfg.ARPAnomalyDetection.FirstScan) * time.Second
		ival := time.Duration(cfg.ARPAnomalyDetection.ProbeInterval) * time.Second

		stopARP := make(chan struct{})
		go func() {
			timer := time.NewTimer(first)
			defer timer.Stop()
			select {
			case <-timer.C:
				triggerARPScan(cfgGet, db, currentIface, logSink, errorSink, false)
			case <-stopARP:
				return
			}
			tk := time.NewTicker(ival)
			defer tk.Stop()
			for {
				select {
				case <-tk.C:
					triggerARPScan(cfgGet, db, currentIface, logSink, errorSink, false)
				case <-stopARP:
					return
				}
			}
		}()
		defer close(stopARP)
	}

	// Optional auto-reload watcher
	var watcher *fsnotify.Watcher
	var watcherErr error
	if cfg.AutoReload {
		watcher, watcherErr = startConfigWatcher(cfgPath, func(newCfg config.Config, newWarns []string) {
			// Compare authoritative before swapping
			oldAuth := effectiveAuthoritative(cfgGet())
			newAuth := effectiveAuthoritative(&newCfg)

			cfgAtomic.Store(&newCfg)
			for _, w := range newWarns {
				logSink("%s", w)
			}
			dhcpserver.EnforceReservationLeaseConsistency(db, &newCfg)
			if newCfg.CompactOnLoad {
				if n := db.CompactNow(time.Duration(newCfg.LeaseStickySeconds) * time.Second); n > 0 {
					logSink("LEASE-COMPACT removed=%d (on auto-reload)", n)
				}
			}
			if newCfg.Interface != currentIface {
				if err := bind(newCfg.Interface); err != nil {
					logSink("AUTO-RELOAD: rebind failed for iface %q: %v (keeping %q)", newCfg.Interface, err, currentIface)
				} else {
					logSink("AUTO-RELOAD: rebound to iface=%q", newCfg.Interface)
				}
			}
			if oldAuth != newAuth {
				logSink("AUTO-RELOAD: authoritative %v -> %v", oldAuth, newAuth)
			} else {
				logSink("AUTO-RELOAD: authoritative=%v", newAuth)
			}
			logSink("AUTO-RELOAD: config applied")

			// DETECT announcement after auto-reload apply
			logDetect(&newCfg, currentIface, logSink)
		}, logSink)
		if watcherErr != nil {
			logSink("AUTO-RELOAD: watcher failed: %v", watcherErr)
		}
	}

	// Signals: INT/TERM stop; HUP reload
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for sig := range sigc {
		switch sig {
		case syscall.SIGHUP:
			rawNew, jerr := config.ParseStrict(cfgPath)
			if jerr != nil {
				logSink("RELOAD: config invalid, keeping old settings: %v", jerr)
				continue
			}
			nowEpoch := time.Now().Unix()
			changed := false
			for k, v := range rawNew.Reservations {
				if v.FirstSeen == 0 {
					v.FirstSeen = nowEpoch
					rawNew.Reservations[k] = v
					changed = true
				}
			}
			if rawNew.BannedMACs == nil {
				rawNew.BannedMACs = make(map[string]config.DeviceMeta)
			}
			for k, v := range rawNew.BannedMACs {
				if v.FirstSeen == 0 {
					v.FirstSeen = nowEpoch
					rawNew.BannedMACs[k] = v
					changed = true
				}
			}
			if changed {
				tmp := cfgPath + ".tmp"
				if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err == nil {
					if f2, err := os.Create(tmp); err == nil {
						enc := json.NewEncoder(f2)
						enc.SetIndent("", "  ")
						if err := enc.Encode(&rawNew); err == nil {
							_ = f2.Sync()
							_ = f2.Close()
							_ = os.Rename(tmp, cfgPath)
						} else {
							_ = f2.Close()
							_ = os.Remove(tmp)
							logSink("RELOAD: failed to persist first_seen update: %v", err)
						}
					}
				}
			}
			newCfg, newWarns, verr := config.ValidateAndNormalizeConfig(rawNew)
			if verr != nil {
				logSink("RELOAD: validation failed, keeping old settings: %v", verr)
				continue
			}
			for _, w := range newWarns {
				logSink("%s", w)
			}

			// Compare before swap
			oldAuth := effectiveAuthoritative(cfgGet())
			newAuth := effectiveAuthoritative(&newCfg)

			cfgAtomic.Store(&newCfg)
			dhcpserver.EnforceReservationLeaseConsistency(db, &newCfg)
			if newCfg.CompactOnLoad {
				if n := db.CompactNow(time.Duration(newCfg.LeaseStickySeconds) * time.Second); n > 0 {
					logSink("LEASE-COMPACT removed=%d (on config reload)", n)
				}
			}
			if newCfg.Interface != currentIface {
				if err := bind(newCfg.Interface); err != nil {
					logSink("RELOAD: rebind failed for iface %q: %v (keeping %q)", newCfg.Interface, err, currentIface)
				} else {
					logSink("RELOAD: rebound to iface=%q", newCfg.Interface)
				}
			}
			if oldAuth != newAuth {
				logSink("RELOAD: authoritative %v -> %v", oldAuth, newAuth)
			} else {
				logSink("RELOAD: authoritative=%v", newAuth)
			}
			logSink("RELOAD: config applied")

			// DETECT announcement after manual reload
			logDetect(&newCfg, currentIface, logSink)

		case syscall.SIGINT, syscall.SIGTERM:
			logSink("SIGNAL received, shutting down")
			_ = s.Close()
			_ = db.Save()
			if watcher != nil {
				_ = watcher.Close()
			}
			return nil
		}
	}
	return nil
}

/* ----------------- Watcher ----------------- */

// startConfigWatcher watches cfgPath and calls onApply(validatedCfg,warns) after successful parses.
// It also performs the first_seen stamping persist just like the HUP path.
func startConfigWatcher(
	cfgPath string,
	onApply func(config.Config, []string),
	logf func(string, ...any),
) (*fsnotify.Watcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(cfgPath)
	if err := w.Add(dir); err != nil {
		_ = w.Close()
		return nil, err
	}
	go func() {
		for {
			select {
			case ev, ok := <-w.Events:
				if !ok {
					return
				}
				if filepath.Clean(ev.Name) != filepath.Clean(cfgPath) {
					continue
				}
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Chmod) == 0 {
					continue
				}
				time.Sleep(150 * time.Millisecond)

				cfgNew, jerr := config.ParseStrict(cfgPath)
				if jerr != nil {
					logf("AUTO-RELOAD: config invalid, keeping old settings: %v", jerr)
					continue
				}

				now := time.Now().Unix()
				changed := false
				for k, v := range cfgNew.Reservations {
					if v.FirstSeen == 0 {
						v.FirstSeen = now
						cfgNew.Reservations[k] = v
						changed = true
					}
				}
				if cfgNew.BannedMACs == nil {
					cfgNew.BannedMACs = make(map[string]config.DeviceMeta)
				}
				for k, v := range cfgNew.BannedMACs {
					if v.FirstSeen == 0 {
						v.FirstSeen = now
						cfgNew.BannedMACs[k] = v
						changed = true
					}
				}
				if changed {
					tmp := cfgPath + ".tmp"
					if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err == nil {
						if f, err := os.Create(tmp); err == nil {
							enc := json.NewEncoder(f)
							enc.SetIndent("", "  ")
							if err := enc.Encode(&cfgNew); err == nil {
								_ = f.Sync()
								_ = f.Close()
								_ = os.Rename(tmp, cfgPath)
							} else {
								_ = f.Close()
								_ = os.Remove(tmp)
								logf("AUTO-RELOAD: failed to persist first_seen: %v", err)
							}
						}
					}
				}

				norm, warns, verr := config.ValidateAndNormalizeConfig(cfgNew)
				if verr != nil {
					logf("AUTO-RELOAD: validation failed, keeping old settings: %v", verr)
					continue
				}

				onApply(norm, warns)

			case err := <-w.Errors:
				logf("watcher error: %v", err)
			}
		}
	}()
	return w, nil
}

/* ----------------- Stats helpers ----------------- */

func loadDBAndConfig(cfgPath string) (*dhcpserver.LeaseDB, config.Config, error) {
	raw, jerr := config.ParseStrict(cfgPath)
	if jerr != nil {
		return nil, config.Config{}, jerr
	}
	cfg, _, verr := config.ValidateAndNormalizeConfig(raw)
	if verr != nil {
		return nil, config.Config{}, verr
	}
	db := dhcpserver.NewLeaseDB(cfg.LeaseDBPath)
	if err := db.Load(); err != nil {
		return nil, config.Config{}, err
	}
	return db, cfg, nil
}

/* ----------------- Cobra CLI ----------------- */

func addConsoleCommands(root *cobra.Command) {
	var socket string
	var transparent bool

	consoleCmd := &cobra.Command{
		Use:   "console",
		Short: "Console-related commands",
	}

	attachCmd := &cobra.Command{
		Use:   "attach",
		Short: "Attach to the running console via UNIX socket",
		RunE: func(_ *cobra.Command, _ []string) error {
			return console.Attach(console.AttachOptions{
				Socket:            socket,
				SocketCandidates:  consoleSocketCandidates(),
				Transparent:       transparent,
				Title:             "DHCPlane Console (attached)",
				DisconnectMessage: "[notice] disconnected from server",
				OnExit: func(code int) {
					go func() {
						time.Sleep(25 * time.Millisecond)
						os.Exit(code)
					}()
				},
			})
		},
	}
	attachCmd.Flags().StringVar(&socket, "socket", "", "UNIX socket path override")
	attachCmd.Flags().BoolVar(&transparent, "transparent", false, "Use terminal background")

	consoleCmd.AddCommand(attachCmd)
	root.AddCommand(consoleCmd)
}

func main() {
	var (
		cfgPath     string
		console     bool
		showVersion bool
	)

	root := &cobra.Command{
		Use:   "dhcplane",
		Short: "DHCPv4 server (insomniacslk/dhcp) with JSON config, reservations (with notes), logging, sticky leases, stats, and live reload",
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			if showVersion {
				fmt.Println(appVersion)
				os.Exit(0)
			}
			return nil
		},
	}
	root.PersistentFlags().BoolVarP(&showVersion, "version", "", false, "Print version and exit")
	root.PersistentFlags().StringVarP(&cfgPath, "config", "", "dhcplane.json", "Path to JSON config")
	// authoritative is now config-driven; flag removed
	root.PersistentFlags().BoolVar(&console, "console", false, "Export console over UNIX socket in addition to stdout/stderr logging")

	// Inject the client-side attach command into this binary.
	addConsoleCommands(root)

	/* ---- serve ---- */
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the DHCP server",
		RunE: func(_ *cobra.Command, _ []string) error {
			// Create a default config if missing
			if err := ensureDefaultConfig(cfgPath); err != nil {
				return fmt.Errorf("default config: %w", err)
			}

			// Validate config before start
			if _, jerr := config.ParseStrict(cfgPath); jerr != nil {
				return fmt.Errorf("config error: %w", jerr)
			}

			return buildServerAndRun(cfgPath, console)
		},
	}

	/* ---- leases ---- */
	var jsonOut bool
	showCmd := &cobra.Command{
		Use:   "leases",
		Short: "Print current leases",
		RunE: func(_ *cobra.Command, _ []string) error {
			db, _, err := loadDBAndConfig(cfgPath)
			if err != nil {
				return err
			}

			type row struct {
				IP          string `json:"ip"`
				MAC         string `json:"mac"`
				Hostname    string `json:"hostname"`
				AllocatedAt string `json:"allocated_at"`
				Expiry      string `json:"expiry"`
				FirstSeen   string `json:"first_seen"`
			}
			var rows []row
			db.ForEach(func(l dhcpserver.Lease) {
				rows = append(rows, row{
					IP:          l.IP,
					MAC:         l.MAC,
					Hostname:    l.Hostname,
					AllocatedAt: dhcpserver.FormatEpoch(l.AllocatedAt),
					Expiry:      dhcpserver.FormatEpoch(l.Expiry),
					FirstSeen:   dhcpserver.FormatEpoch(l.FirstSeen),
				})
			})
			// Keep stable order by IP
			sort.Slice(rows, func(i, j int) bool {
				return ipKey(rows[i].IP) < ipKey(rows[j].IP)
			})

			if jsonOut {
				b, _ := json.MarshalIndent(rows, "", "  ")
				fmt.Println(string(b))
				return nil
			}

			// tabular default
			w := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)
			fmt.Fprintln(w, "IP\tMAC\tHostname\tAllocatedAt\tExpiry\tFirstSeen")
			for _, r := range rows {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
					r.IP, r.MAC, r.Hostname, r.AllocatedAt, r.Expiry, r.FirstSeen)
			}
			w.Flush()
			return nil
		},
	}
	showCmd.Flags().BoolVar(&jsonOut, "json", false, "Output leases in JSON")

	/* ---- stats ---- */
	var details bool
	var grid bool
	statsCmd := &cobra.Command{
		Use:   "stats",
		Short: "Show allocation rates and lease status (add --details for a full table, --grid for a colour grid)",
		RunE: func(_ *cobra.Command, _ []string) error {
			db, cfg, err := loadDBAndConfig(cfgPath)
			if err != nil {
				return err
			}
			assume := time.Duration(cfg.LeaseSeconds) * time.Second
			now := time.Now()

			// Build banned MAC set (merge config + env)
			bannedSet := make(map[string]struct{})
			for m := range cfg.BannedMACs {
				if nm, err := dhcpserver.CanonMAC(m); err == nil {
					bannedSet[nm] = struct{}{}
				} else {
					nm = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(m), "-", ":"), " ", ""))
					bannedSet[nm] = struct{}{}
				}
			}
			for nm := range dhcpserver.ParseBannedMACsEnv() {
				bannedSet[nm] = struct{}{}
			}
			isBanned := func(mac string) bool {
				if nm, err := dhcpserver.CanonMAC(mac); err == nil {
					_, ok := bannedSet[nm]
					return ok
				}
				nm := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(mac), "-", ":"), " ", ""))
				_, ok := bannedSet[nm]
				return ok
			}

			// Live iteration over leases without copying
			iter := func(yield func(statistics.LeaseLite)) {
				db.ForEach(func(l dhcpserver.Lease) {
					yield(statistics.LeaseLite{
						IP:          l.IP,
						MAC:         l.MAC,
						Hostname:    l.Hostname,
						AllocatedAt: l.AllocatedAt,
						Expiry:      l.Expiry,
					})
				})
			}
			isDeclined := func(ip string) bool { return db.IsDeclined(ip) }

			perMinute, perHour, perDay, perWeek, perMonth := statistics.CountAllocations(iter, assume, now)
			curr, expiring, expired := statistics.ClassifyLeases(iter, assume, now)

			fmt.Printf("Allocations: last 1m=%d  1h=%d  24h=%d  7d=%d  30d=%d\n",
				perMinute, perHour, perDay, perWeek, perMonth)
			fmt.Printf("Leases: current=%d  expiring=%d  expired=%d\n",
				len(curr), len(expiring), len(expired))

			if details {
				rows, err := statistics.BuildDetailRows(cfg, iter, isDeclined, isBanned, now)
				if err != nil {
					return err
				}
				statistics.PrintDetailsTable("DETAILS (entire subnet)", rows, assume, now)
			}

			if grid {
				if err := statistics.DrawSubnetGrid(cfg, iter, isDeclined, isBanned, 25, now); err != nil {
					return err
				}
			}
			return nil
		},
	}
	statsCmd.Flags().BoolVar(&details, "details", false, "Print a full table for the whole subnet including Type")
	statsCmd.Flags().BoolVar(&grid, "grid", false, "Render a full-subnet colour grid (green=free, red=leased, brown=reserved, light-gray=banned-mac, dark-gray=banned/excluded IPs)")

	/* ---- check ---- */
	checkCmd := &cobra.Command{
		Use:   "check",
		Short: "Validate the JSON config and exit (reports line/column on errors)",
		RunE: func(_ *cobra.Command, _ []string) error {
			_, jerr := config.ParseStrict(cfgPath)
			if jerr != nil {
				return jerr
			}
			fmt.Println("OK: config is valid")
			return nil
		},
	}

	/* ---- reload ---- */
	reloadCmd := &cobra.Command{
		Use:   "reload",
		Short: "Signal a running server to reload the config (SIGHUP via PID file)",
		RunE: func(_ *cobra.Command, _ []string) error {
			// Check file is valid before signaling
			raw, jerr := config.ParseStrict(cfgPath)
			if jerr != nil {
				return fmt.Errorf("refusing to reload: config invalid: %w", jerr)
			}
			cfg, _, verr := config.ValidateAndNormalizeConfig(raw)
			if verr != nil {
				return fmt.Errorf("refusing to reload: config invalid: %w", verr)
			}
			pid, err := readPID(cfg.PIDFile)
			if err != nil {
				return fmt.Errorf("read pid: %w", err)
			}
			if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
				return fmt.Errorf("signal: %w", err)
			}
			fmt.Printf("Sent SIGHUP to pid %d\n", pid)
			return nil
		},
	}

	/* ---- manage add/remove (with notes & conflict checks) ---- */
	manageCmd := &cobra.Command{
		Use:   "manage",
		Short: "Manage configuration (reservations, etc.)",
	}

	addCmd := &cobra.Command{
		Use:   "add <mac> <ip> [note...]",
		Short: "Add or update a MAC→IP reservation; optional note",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			norm, err := dhcpserver.CanonMAC(args[0])
			if err != nil {
				return errf("invalid mac: %v", err)
			}
			ip := net.ParseIP(args[1]).To4()
			if ip == nil {
				return errf("invalid IPv4: %s", args[1])
			}
			note := ""
			if len(args) > 2 {
				note = strings.TrimSpace(strings.Join(args[2:], " "))
			}

			rawCfg, jerr := config.ParseStrict(cfgPath)
			if jerr != nil {
				return jerr
			}
			cfg, _, verr := config.ValidateAndNormalizeConfig(rawCfg)
			if verr != nil {
				return verr
			}
			_, subnet := mustCIDR(cfg.SubnetCIDR)
			if !subnet.Contains(ip) {
				warnf("IP %s not in subnet %s", ip, cfg.SubnetCIDR)
			}

			// Conflict A: IP already reserved for someone else?
			for macKey, res := range cfg.Reservations {
				if macEqual(macKey, norm) {
					continue
				}
				if res.IP == ip.String() {
					return errf("IP %s is already reserved for %s", ip.String(), macKey)
				}
			}

			// Conflict B: IP currently leased to a different MAC? (warn)
			leasePath := cfg.LeaseDBPath
			db := dhcpserver.NewLeaseDB(leasePath)
			_ = db.Load()
			if l, ok := db.FindByIP(ip.String()); ok && !macEqual(l.MAC, norm) {
				warnf("IP %s currently leased to %s (hostname=%q) until %s",
					ip.String(), l.MAC, l.Hostname, dhcpserver.FormatEpoch(l.Expiry))
			}

			// Upsert reservation with first_seen epoch
			if cfg.Reservations == nil {
				cfg.Reservations = make(config.Reservations)
			}
			now := time.Now().Unix()
			prev, existed := cfg.Reservations[norm]
			if !existed {
				cfg.Reservations[norm] = config.Reservation{
					IP:        ip.String(),
					Note:      note,
					FirstSeen: now,
				}
				fmt.Printf("Added reservation: %s -> %s  note=%q  first_seen=%s\n",
					norm, ip.String(), note, dhcpserver.FormatEpoch(now))
			} else {
				fs := prev.FirstSeen
				if fs == 0 {
					fs = now
				}
				cfg.Reservations[norm] = config.Reservation{
					IP:                  ip.String(),
					Note:                note,
					FirstSeen:           fs,
					EquipmentType:       prev.EquipmentType,
					Manufacturer:        prev.Manufacturer,
					ManagementType:      prev.ManagementType,
					ManagementInterface: prev.ManagementInterface,
				}
				fmt.Printf("Updated reservation: %s  %s -> %s  note=%q (first_seen=%s)\n",
					norm, prev.IP, ip.String(), note, dhcpserver.FormatEpoch(fs))
			}

			// Write back (pretty)
			tmp := cfgPath + ".tmp"
			if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil && !os.IsExist(err) {
				return err
			}
			f, err := os.Create(tmp)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			if err := enc.Encode(&cfg); err != nil {
				f.Close()
				_ = os.Remove(tmp)
				return err
			}
			_ = f.Sync()
			_ = f.Close()
			if err := os.Rename(tmp, cfgPath); err != nil {
				return err
			}
			return nil
		},
	}

	removeCmd := &cobra.Command{
		Use:   "remove <mac>",
		Short: "Remove a MAC→IP reservation (and note) from the config",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			norm, err := dhcpserver.CanonMAC(args[0])
			if err != nil {
				return errf("invalid mac: %v", err)
			}
			rawCfg, jerr := config.ParseStrict(cfgPath)
			if jerr != nil {
				return jerr
			}
			cfg, _, verr := config.ValidateAndNormalizeConfig(rawCfg)
			if verr != nil {
				return verr
			}
			if cfg.Reservations == nil {
				fmt.Println("Nothing to remove: no reservations")
				return nil
			}
			if _, ok := cfg.Reservations[norm]; !ok {
				fmt.Printf("No reservation for %s\n", norm)
				return nil
			}
			delete(cfg.Reservations, norm)

			tmp := cfgPath + ".tmp"
			if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil && !os.IsExist(err) {
				return err
			}
			f, err := os.Create(tmp)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			if err := enc.Encode(&cfg); err != nil {
				f.Close()
				_ = os.Remove(tmp)
				return err
			}
			_ = f.Sync()
			_ = f.Close()
			if err := os.Rename(tmp, cfgPath); err != nil {
				return err
			}
			fmt.Printf("Reservation removed: %s in %s\n", norm, cfgPath)
			return nil
		},
	}

	manageCmd.AddCommand(addCmd, removeCmd)

	var arpAllIfaces bool
	var arpJSON bool
	var arpRefresh bool
	var arpIface string
	arpCmd := &cobra.Command{
		Use:   "arp",
		Short: "Scan/read ARP and print a table; Linux scans, macOS/Windows read cache",
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg := cfgGetForCLI(cfgPath) // keep your helper
			if !arpAllIfaces && cfg.Interface != "" && arpIface == "" {
				arpIface = cfg.Interface
			}

			entries, _, err := arp.ScanForCLI(cfg, cfg.LeaseDBPath, arpIface, arpAllIfaces, arpRefresh, time.Second*3)
			if err != nil {
				return err
			}

			// numeric IPv4 sort with iface tie-breaker
			sort.Slice(entries, func(i, j int) bool {
				ki, kj := ipKey(entries[i].IP), ipKey(entries[j].IP)
				if ki == kj {
					return entries[i].Iface < entries[j].Iface
				}
				return ki < kj
			})

			if arpJSON {
				b, _ := json.MarshalIndent(entries, "", "  ")
				fmt.Println(string(b))
				return nil
			}
			arp.PrintTable(entries)
			return nil
		},
	}
	arpCmd.Flags().BoolVar(&arpAllIfaces, "all-ifaces", false, "Use all interfaces")
	arpCmd.Flags().BoolVar(&arpJSON, "json", false, "JSON output")
	arpCmd.Flags().BoolVar(&arpRefresh, "refresh", false, "Best-effort cache warm-up on macOS/Windows")
	arpCmd.Flags().StringVar(&arpIface, "iface", "", "Interface name override")

	root.AddCommand(serveCmd, showCmd, statsCmd, checkCmd, reloadCmd, manageCmd, arpCmd)
	if err := root.Execute(); err != nil {
		log.Fatal(err)
	}
}

func triggerARPScan(
	cfgGet func() *config.Config,
	db *dhcpserver.LeaseDB,
	iface string,
	logf, errf func(string, ...any),
	_ bool, // allIfaces currently unused here; keep for future
) {
	cfg := cfgGet()
	entries, findings, err := arp.Scan(cfg, db, iface, false, time.Second*3)
	if err != nil {
		errf("ARP scan error: %v", err)
		return
	}
	_ = entries // reserved for future use
	for _, f := range findings {
		logf("ARP-ANOMALY ip=%s mac=%s iface=%s reason=%s lease_mac=%s res_mac=%s",
			f.IP, f.MAC, f.Iface, f.Reason, f.LeaseMAC, f.ResMAC)
	}
}

func cfgGetForCLI(cfgPath string) config.Config {
	raw, _ := config.ParseStrict(cfgPath)
	cfg, _, _ := config.ValidateAndNormalizeConfig(raw)
	return cfg
}

/* ----------------- Small helpers kept in main ----------------- */

func errf(format string, a ...any) error {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stderr, aurora.Red(fmt.Sprintf("ERROR: %s", msg)))
	return fmt.Errorf("%s", msg)
}

func warnf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintln(os.Stderr, aurora.Yellow(fmt.Sprintf("WARNING: %s", msg)))
}

func mustCIDR(c string) (net.IP, *net.IPNet) {
	ip, n, err := net.ParseCIDR(c)
	if err != nil {
		log.Fatalf("bad subnet_cidr %q: %v", c, err)
	}
	return ip, n
}

// macEqual normalizes both sides and compares.
func macEqual(a, b string) bool {
	na, ea := dhcpserver.CanonMAC(a)
	nb, eb := dhcpserver.CanonMAC(b)
	if ea == nil && eb == nil {
		return na == nb
	}
	return strings.EqualFold(a, b)
}

// ensureDefaultConfig writes a sane default config if cfgPath does not exist.
func ensureDefaultConfig(cfgPath string) error {
	_, err := os.Stat(cfgPath)
	if err == nil {
		return nil // exists
	}
	if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil && !os.IsExist(err) {
		return err
	}

	// Default: 192.168.1.0/24
	def := map[string]any{
		"interface":                "",
		"server_ip":                "192.168.1.2",
		"subnet_cidr":              "192.168.1.0/24",
		"gateway":                  "192.168.1.1",
		"compact_on_load":          false,
		"dns":                      []string{"192.168.1.1", "1.1.1.1"},
		"domain":                   "lan",
		"lease_db_path":            "leases.json",
		"pid_file":                 "dhcplane.pid",
		"authoritative":            true, // default authoritative if unset
		"lease_seconds":            3600,
		"lease_sticky_seconds":     3600,
		"auto_reload":              true,
		"pools":                    []map[string]string{{"start": "192.168.1.100", "end": "192.168.1.200"}},
		"exclusions":               []string{"192.168.1.1", "192.168.1.2"},
		"reservations":             map[string]any{},
		"ntp":                      []string{},
		"mtu":                      0,
		"tftp_server_name":         "",
		"bootfile_name":            "",
		"wpad_url":                 "",
		"wins":                     []string{},
		"domain_search":            []string{},
		"static_routes":            []map[string]string{},
		"mirror_routes_to_249":     false,
		"vendor_specific_43_hex":   "",
		"device_overrides":         map[string]any{},
		"vendor_class_overrides":   map[string]any{}, // Vendor Class overrides (by option 60 string)
		"user_class_overrides_77":  map[string]any{},
		"enable_broadcast_28":      false,
		"use_classful_routes_33":   false,
		"routes_33":                []map[string]string{}, // {"destination":"a.b.c.0","gateway":"x.y.z.w"}
		"netbios_node_type_46":     0,                     // 0 omit, else {1,2,4,8}
		"netbios_scope_id_47":      "",
		"max_dhcp_message_size_57": 0,          // 0 omit, else >=576
		"tftp_servers_150":         []string{}, // list of IPv4s
		"echo_relay_agent_info_82": false,
		"banned_macs":              map[string]any{},
		"equipment_types":          []string{},
		"management_types":         []string{},
		"console_max_lines":        10000,
		"logging": map[string]any{
			"path":        "",
			"filename":    "dhcplane.log",
			"max_size":    20, // MB
			"max_backups": 5,
			"max_age":     0,    // days; 0 = no age-based purge
			"compress":    true, // gzip (lumberjack)
		},
		// New: default detection block
		"detect_dhcp_servers": map[string]any{
			"enabled":           true,
			"active_probe":      "off",   // off|safe|aggressive
			"probe_interval":    600,     // seconds
			"rate_limit":        6,       // events per minute per server
			"whitelist_servers": []any{}, // IPv4 or MAC entries
		},
	}

	b, _ := json.MarshalIndent(def, "", "  ")
	return os.WriteFile(cfgPath, b, 0o644)
}

/* ----------------- Local type needed for bind closer ----------------- */

type ioCloser interface {
	Close() error
}

func ipKey(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return ^uint32(0)
	}
	return dhcpserver.IPToU32(ip)
}
