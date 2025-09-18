package main

import (
	"dhcplane/config"
	"dhcplane/consoleui"
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
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gdamore/tcell/v2"
	"github.com/logrusorgru/aurora"
	"github.com/rivo/tview"
	"github.com/spf13/cobra"
	"gopkg.in/natefinch/lumberjack.v2"
)

var appVersion = "0.1.37"
var transparent bool

// buildConsoleUI wires the generic console with our DHCP-specific counters and highlights.
func buildConsoleUI(nocolour bool, maxLines int) *consoleui.UI {
	ui := consoleui.New(consoleui.Options{
		NoColour:     nocolour,
		MaxLines:     maxLines,
		MouseEnabled: true,
		OnExit:       nil,
	})
	ui.SetTitle(fmt.Sprintf("DHCPlane Console v%s", appVersion))

	ui.RegisterCounter("REQUEST", false, "RPM", 60)
	ui.RegisterCounter("ACK", false, "APM", 60)

	ui.HighlightMap("BANNED-MAC", true, consoleui.Style{FG: "red", Attrs: "b"})
	ui.HighlightMap("NAK", true, consoleui.Style{FG: "red", Attrs: "b"})
	ui.HighlightMap("ACK", true, consoleui.Style{FG: "green", Attrs: "b"})
	ui.HighlightMap("OFFER", true, consoleui.Style{FG: "green", Attrs: "b"})
	ui.HighlightMap("REQUEST", true, consoleui.Style{FG: "yellow", Attrs: "b"})
	ui.HighlightMap("DISCOVER", true, consoleui.Style{FG: "yellow", Attrs: "b"})
	ui.HighlightMap("RELEASE", true, consoleui.Style{FG: "yellow", Attrs: "b"})
	ui.HighlightMap("DECLINE", true, consoleui.Style{FG: "yellow", Attrs: "b"})

	return ui
}

/* ----------------- Logging ----------------- */

func setupLogger(flagPath string, cfg config.Config) (*log.Logger, io.Closer, error) {
	// Config-driven rotating file if logging is specified in config.
	if cfg.Logging.Path != "" || cfg.Logging.Filename != "" {
		full := cfg.Logging.Filename
		if cfg.Logging.Path != "" {
			full = filepath.Join(cfg.Logging.Path, cfg.Logging.Filename)
		}
		if full == "" {
			return nil, nil, fmt.Errorf("logging.filename is required when logging.path is set")
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil && !os.IsExist(err) {
			return nil, nil, err
		}
		rot := &lumberjack.Logger{
			Filename: full,
			MaxSize: func() int {
				if cfg.Logging.MaxSize > 0 {
					return cfg.Logging.MaxSize
				}
				return 20
			}(),
			MaxBackups: func() int {
				if cfg.Logging.MaxBackups > 0 {
					return cfg.Logging.MaxBackups
				}
				return 5
			}(),
			MaxAge:   cfg.Logging.MaxAge, // 0 means no age-based pruning
			Compress: true,               // gzip; lumberjack doesn't support zstd
		}
		lg := log.New(rot, "", log.LstdFlags|log.Lmicroseconds)
		return lg, rot, nil
	}

	// No logging section: keep old default path and rotate with defaults.
	if flagPath == "" {
		flagPath = "dhcplane.log"
	}
	if err := os.MkdirAll(filepath.Dir(flagPath), 0o755); err != nil && !os.IsExist(err) {
		return nil, nil, err
	}
	rot := &lumberjack.Logger{
		Filename:   flagPath,
		MaxSize:    20, // MB
		MaxBackups: 5,
		MaxAge:     0,
		Compress:   true, // gzip
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

func buildServerAndRun(cfgPath string, leasePath string, authoritative bool, logPath string, console bool, pidPath string, nocolour bool) error {
	// Load + validate/normalize initial config
	raw, jerr := config.ParseStrict(cfgPath)
	if jerr != nil {
		return fmt.Errorf("config error: %w", jerr)
	}
	cfg, warns, verr := config.ValidateAndNormalizeConfig(raw)
	if verr != nil {
		return fmt.Errorf("config validation: %w", verr)
	}

	// Lease DB
	db := dhcpserver.NewLeaseDB(leasePath)
	if err := db.Load(); err != nil {
		log.Printf("lease db load: %v (continuing with empty)", err)
	}

	// Logger (file or rotating)
	lg, closer, err := setupLogger(logPath, cfg)
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	defer func() {
		if closer != nil {
			_ = closer.Close()
		}
	}()

	// Optional console UI
	var ui *consoleui.UI
	if console {
		maxLines := cfg.ConsoleMaxLines
		if maxLines <= 0 {
			maxLines = 10000
		}
		ui = buildConsoleUI(nocolour, maxLines)
		go func() {
			if err := ui.Start(); err != nil {
				log.Fatalf("console UI failed: %v", err)
			}
		}()
		defer ui.Stop()
	}

	// Sinks
	logSink := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		if lg != nil {
			lg.Printf("%s", msg)
		}
		if ui != nil {
			ts := time.Now().Format("2006/01/02 15:04:05.000000")
			ui.Append(ts + " " + msg)
		}
	}
	errorSink := func(format string, args ...any) {
		msg := fmt.Sprintf("ERROR: "+format, args...)
		if lg != nil {
			lg.Printf("%s", msg)
		}
		if ui != nil {
			ts := time.Now().Format("2006/01/02 15:04:05.000000")
			ui.Append(ts + " " + msg)
		}
	}

	// Log initial warnings
	for _, w := range warns {
		logSink("%s", w)
	}

	// Atomic config snapshot
	var cfgAtomic atomic.Value
	cfgAtomic.Store(&cfg)
	cfgGet := func() *config.Config { return cfgAtomic.Load().(*config.Config) }

	// Authoritative getter
	authorGet := func() bool { return authoritative }

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
	if err := writePID(pidPath); err != nil {
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

	logSink("START iface=%q bind=%s server_ip=%s subnet=%s gateway=%s lease=%s sticky=%s",
		currentIface, laddr.String(), cfg.ServerIP, cfg.SubnetCIDR, cfg.Gateway,
		time.Duration(cfg.LeaseSeconds)*time.Second, time.Duration(cfg.LeaseStickySeconds)*time.Second)
	if cfg.AutoReload {
		logSink("START auto_reload=true (watching %s)", cfgPath)
	}

	// Optional auto-reload watcher
	var watcher *fsnotify.Watcher
	var watcherErr error
	if cfg.AutoReload {
		watcher, watcherErr = startConfigWatcher(cfgPath, func(newCfg config.Config, newWarns []string) {
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
			logSink("AUTO-RELOAD: config applied")
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
			logSink("RELOAD: config applied")
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

func loadDBAndConfig(leasePath, cfgPath string) (*dhcpserver.LeaseDB, config.Config, error) {
	db := dhcpserver.NewLeaseDB(leasePath)
	if err := db.Load(); err != nil {
		return nil, config.Config{}, err
	}
	cfg, jerr := config.ParseStrict(cfgPath)
	if jerr != nil {
		return nil, config.Config{}, jerr
	}
	return db, cfg, nil
}

/* ----------------- Cobra CLI ----------------- */

func main() {
	var (
		cfgPath       string
		leasePath     string
		authoritative bool
		logPath       string
		console       bool
		pidPath       string
		nocolour      bool
		showVersion   bool
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
	root.PersistentFlags().StringVar(&leasePath, "lease-db", "leases.json", "Path to leases JSON DB")
	root.PersistentFlags().BoolVar(&authoritative, "authoritative", true, "Send NAKs on invalid requests")
	root.PersistentFlags().StringVar(&logPath, "log", "dhcplane.log", "Log file path (empty to log only to console)")
	root.PersistentFlags().BoolVar(&console, "console", false, "Also print logs to stdout in addition to --log")
	root.PersistentFlags().StringVar(&pidPath, "pid-file", "dhcplane.pid", "PID file for reload control")
	root.PersistentFlags().BoolVar(&nocolour, "nocolour", false, "Disable ANSI colours in console output")
	root.PersistentFlags().BoolVar(&transparent, "transparent", false, "Use terminal background (no solid fill)")

	/* ---- serve ---- */
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the DHCP server",
		// serveCmd RunE (anonymous func) — with default config generation
		RunE: func(_ *cobra.Command, _ []string) error {
			// Create a default config if missing
			if err := ensureDefaultConfig(cfgPath); err != nil {
				return fmt.Errorf("default config: %w", err)
			}

			// Validate config before start
			if _, jerr := config.ParseStrict(cfgPath); jerr != nil {
				return fmt.Errorf("config error: %w", jerr)
			}

			if transparent {
				tview.Styles.PrimitiveBackgroundColor = tcell.ColorDefault
				tview.Styles.ContrastBackgroundColor = tcell.ColorDefault
				tview.Styles.MoreContrastBackgroundColor = tcell.ColorDefault
			}
			return buildServerAndRun(cfgPath, leasePath, authoritative, logPath, console, pidPath, nocolour)
		},
	}

	/* ---- leases ---- */
	showCmd := &cobra.Command{
		Use:   "leases",
		Short: "Print current leases",
		RunE: func(_ *cobra.Command, _ []string) error {
			db := dhcpserver.NewLeaseDB(leasePath)
			if err := db.Load(); err != nil {
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
			// Keep stable order by IP as before
			sort.Slice(rows, func(i, j int) bool { return rows[i].IP < rows[j].IP })

			b, _ := json.MarshalIndent(rows, "", "  ")
			fmt.Println(string(b))
			return nil
		},
	}

	/* ---- stats ---- */
	var details bool
	var grid bool
	statsCmd := &cobra.Command{
		Use:   "stats",
		Short: "Show allocation rates and lease status (add --details for a full table, --grid for a colour grid)",
		RunE: func(_ *cobra.Command, _ []string) error {
			db, cfg, err := loadDBAndConfig(leasePath, cfgPath)
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
			_, jerr := config.ParseStrict(cfgPath)
			if jerr != nil {
				return fmt.Errorf("refusing to reload: config invalid: %w", jerr)
			}
			pid, err := readPID(pidPath)
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

			cfg, jerr := config.ParseStrict(cfgPath)
			if jerr != nil {
				return jerr
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
			cfg, jerr := config.ParseStrict(cfgPath)
			if jerr != nil {
				return jerr
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

	root.AddCommand(serveCmd, showCmd, statsCmd, checkCmd, reloadCmd, manageCmd)
	if err := root.Execute(); err != nil {
		log.Fatal(err)
	}
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
	}

	b, _ := json.MarshalIndent(def, "", "  ")
	return os.WriteFile(cfgPath, b, 0o644)
}

/* ----------------- Local type needed for bind closer ----------------- */

type ioCloser interface {
	Close() error
}
