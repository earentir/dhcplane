package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gdamore/tcell/v2"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/insomniacslk/dhcp/rfc1035label"
	"github.com/logrusorgru/aurora"
	"github.com/rivo/tview"
	"github.com/spf13/cobra"
)

var appVersion = "0.1.29"

/* ----------------- Config & Types ----------------- */

// Pool represents a range of IP addresses.
type Pool struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

// StaticRoute represents a static route configuration.
type StaticRoute struct {
	CIDR    string `json:"cidr"`
	Gateway string `json:"gateway"`
}

// DeviceOverride represents per-device DHCP options.
type DeviceOverride struct {
	DNS            []string `json:"dns,omitempty"`              // opt 6
	TFTPServerName string   `json:"tftp_server_name,omitempty"` // opt 66
	BootFileName   string   `json:"bootfile_name,omitempty"`    // opt 67
}

// DeviceMeta contains metadata for a device.
type DeviceMeta struct {
	FirstSeen           int64  `json:"first_seen,omitempty"` // epoch seconds
	Note                string `json:"note,omitempty"`
	EquipmentType       string `json:"equipment_type,omitempty"`
	Manufacturer        string `json:"manufacturer,omitempty"`
	ManagementType      string `json:"management_type,omitempty"`
	ManagementInterface string `json:"management_interface,omitempty"`
}

// Reservation represents a DHCP reservation.
type Reservation struct {
	IP                  string `json:"ip"`
	Note                string `json:"note,omitempty"`
	FirstSeen           int64  `json:"first_seen,omitempty"` // epoch seconds
	EquipmentType       string `json:"equipment_type,omitempty"`
	Manufacturer        string `json:"manufacturer,omitempty"`
	ManagementType      string `json:"management_type,omitempty"`
	ManagementInterface string `json:"management_interface,omitempty"`
}

// Reservations is a map of MAC addresses to their DHCP reservations.
type Reservations map[string]Reservation

// UnmarshalJSON implements json.Unmarshaler.
func (r *Reservations) UnmarshalJSON(b []byte) error {
	// Try the new format first
	type newFormat map[string]Reservation
	var nf newFormat
	if err := json.Unmarshal(b, &nf); err == nil {
		*r = Reservations(nf)
		return nil
	}
	// Fallback to old format
	type oldFormat map[string]string
	var of oldFormat
	if err := json.Unmarshal(b, &of); err != nil {
		return err
	}
	out := make(Reservations, len(of))
	for k, v := range of {
		out[k] = Reservation{IP: v}
	}
	*r = out
	return nil
}

// Config represents the DHCP server configuration.
type Config struct {
	Interface     string   `json:"interface,omitempty"`
	ServerIP      string   `json:"server_ip"`
	SubnetCIDR    string   `json:"subnet_cidr"`
	Gateway       string   `json:"gateway"`
	CompactOnLoad bool     `json:"compact_on_load"`
	DNS           []string `json:"dns"`
	Domain        string   `json:"domain,omitempty"`

	LeaseSeconds       int  `json:"lease_seconds"`
	LeaseStickySeconds int  `json:"lease_sticky_seconds,omitempty"`
	AutoReload         bool `json:"auto_reload,omitempty"`

	Pools        []Pool       `json:"pools"`
	Exclusions   []string     `json:"exclusions,omitempty"`
	Reservations Reservations `json:"reservations,omitempty"`

	NTP            []string `json:"ntp,omitempty"`
	MTU            int      `json:"mtu,omitempty"`
	TFTPServerName string   `json:"tftp_server_name,omitempty"`
	BootFileName   string   `json:"bootfile_name,omitempty"`
	WPADURL        string   `json:"wpad_url,omitempty"`
	WINS           []string `json:"wins,omitempty"`

	DomainSearch        []string                  `json:"domain_search,omitempty"`
	StaticRoutes        []StaticRoute             `json:"static_routes,omitempty"`
	MirrorRoutesTo249   bool                      `json:"mirror_routes_to_249,omitempty"`
	VendorSpecific43Hex string                    `json:"vendor_specific_43_hex,omitempty"`
	DeviceOverrides     map[string]DeviceOverride `json:"device_overrides,omitempty"`

	// Config-based banned MACs with metadata (optional feature)
	BannedMACs map[string]DeviceMeta `json:"banned_macs,omitempty"`

	// Allowed enumerations (user-extendable)
	EquipmentTypes  []string `json:"equipment_types,omitempty"`  // e.g., Switch, Router, AP, Modem, Gateway
	ManagementTypes []string `json:"management_types,omitempty"` // e.g., ssh, web, telnet, serial, console

	//Max console buffer
	ConsoleMaxLines int `json:"console_max_lines,omitempty"`
}

// Lease represents a DHCP lease.
type Lease struct {
	MAC         string `json:"mac"`
	IP          string `json:"ip"`
	Hostname    string `json:"hostname,omitempty"`
	AllocatedAt int64  `json:"allocated_at,omitempty"` // epoch seconds
	Expiry      int64  `json:"expiry"`                 // epoch seconds
	FirstSeen   int64  `json:"first_seen,omitempty"`   // epoch seconds
}

// LeaseDB represents a database of DHCP leases.
type LeaseDB struct {
	mu    sync.Mutex
	ByIP  map[string]Lease `json:"by_ip"`
	ByMAC map[string]Lease `json:"by_mac"`

	Path    string `json:"-"`
	dirty   bool   `json:"-"`
	decline map[string]time.Time
}

// NewLeaseDB creates a new LeaseDB instance.
func NewLeaseDB(path string) *LeaseDB {
	return &LeaseDB{
		ByIP:    make(map[string]Lease),
		ByMAC:   make(map[string]Lease),
		Path:    path,
		decline: make(map[string]time.Time),
	}
}

// Load reads the lease database from the specified file.
func (db *LeaseDB) Load() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	f, err := os.Open(db.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	// Try the direct struct first
	type fileShape struct {
		ByIP  map[string]Lease `json:"by_ip"`
		ByMAC map[string]Lease `json:"by_mac"`
	}
	var tmp fileShape
	dec := json.NewDecoder(f)
	if err := dec.Decode(&tmp); err == nil {
		// OK: already epoch-based
		if tmp.ByIP != nil {
			db.ByIP = tmp.ByIP
		}
		if tmp.ByMAC != nil {
			db.ByMAC = tmp.ByMAC
		}
		return nil
	}

	// If we reach here, attempt a tolerant load from old time.Time layout (best-effort).
	// We read raw JSON, coerce fields we care about into epoch.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	var raw map[string]any
	if err := json.NewDecoder(f).Decode(&raw); err != nil {
		return err
	}

	coerce := func(v any) (Lease, bool) {
		m, ok := v.(map[string]any)
		if !ok {
			return Lease{}, false
		}
		lease := Lease{}
		if mac, _ := m["mac"].(string); mac != "" {
			lease.MAC = mac
		}
		if ip, _ := m["ip"].(string); ip != "" {
			lease.IP = ip
		}
		if hn, _ := m["hostname"].(string); hn != "" {
			lease.Hostname = hn
		}
		// allocated_at
		if a, ok := m["allocated_at"].(string); ok && a != "" {
			if t, err := time.Parse(time.RFC3339, a); err == nil {
				lease.AllocatedAt = t.Unix()
			}
		} else if f64, ok := m["allocated_at"].(float64); ok {
			lease.AllocatedAt = int64(f64)
		}
		// expiry
		if e, ok := m["expiry"].(string); ok && e != "" {
			if t, err := time.Parse(time.RFC3339, e); err == nil {
				lease.Expiry = t.Unix()
			}
		} else if f64, ok := m["expiry"].(float64); ok {
			lease.Expiry = int64(f64)
		}
		// first_seen (if existed)
		if fs, ok := m["first_seen"].(float64); ok {
			lease.FirstSeen = int64(fs)
		}
		return lease, true
	}

	byIP := map[string]Lease{}
	byMAC := map[string]Lease{}
	if bip, ok := raw["by_ip"].(map[string]any); ok {
		for ip, v := range bip {
			if lease, ok := coerce(v); ok {
				byIP[ip] = lease
			}
		}
	}
	if bmac, ok := raw["by_mac"].(map[string]any); ok {
		for mac, v := range bmac {
			if lease, ok := coerce(v); ok {
				byMAC[mac] = lease
			}
		}
	}
	if len(byIP) > 0 {
		db.ByIP = byIP
	}
	if len(byMAC) > 0 {
		db.ByMAC = byMAC
	}
	return nil
}

// Save writes the lease database to the specified file.
func (db *LeaseDB) Save() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if !db.dirty {
		return nil
	}

	tmpPath := db.Path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(db.Path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(struct {
		ByIP  map[string]Lease `json:"by_ip"`
		ByMAC map[string]Lease `json:"by_mac"`
	}{
		ByIP: db.ByIP, ByMAC: db.ByMAC,
	}); err != nil {
		f.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	_ = f.Sync()
	_ = f.Close()
	if err := os.Rename(tmpPath, db.Path); err != nil {
		return err
	}
	db.dirty = false
	return nil
}

func (db *LeaseDB) set(lease Lease) {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Always store canonical, lower-case with colons
	normMac := strings.ToLower(lease.MAC)
	if nm, err := normalizeMACFlexible(normMac); err == nil {
		normMac = nm
	}
	lease.MAC = normMac

	// If this MAC has an old IP, remove its by_ip entry when IP changes.
	if old, ok := db.ByMAC[normMac]; ok && !macEqual(old.MAC, lease.MAC) || (ok && old.IP != lease.IP) {
		delete(db.ByIP, old.IP)
		// Preserve original first_seen if it exists.
		if old.FirstSeen > 0 && lease.FirstSeen == 0 {
			lease.FirstSeen = old.FirstSeen
		}
	}
	// If the target IP is held by a different MAC, remove that from ByMAC.
	if old, ok := db.ByIP[lease.IP]; ok && !macEqual(old.MAC, lease.MAC) {
		delete(db.ByMAC, strings.ToLower(old.MAC))
	}

	// If FirstSeen is still zero here, this is a brand-new MAC to us.
	if lease.FirstSeen == 0 {
		lease.FirstSeen = time.Now().Unix()
	}

	db.ByIP[lease.IP] = lease
	db.ByMAC[normMac] = lease
	db.dirty = true
}

func (db *LeaseDB) removeByIP(ip string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if l, ok := db.ByIP[ip]; ok {
		delete(db.ByIP, ip)
		delete(db.ByMAC, strings.ToLower(l.MAC))
		db.dirty = true
	}
}

func (db *LeaseDB) findByMAC(mac string) (Lease, bool) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if nm, err := normalizeMACFlexible(mac); err == nil {
		mac = nm
	}
	l, ok := db.ByMAC[strings.ToLower(mac)]
	return l, ok
}

func (db *LeaseDB) findByIP(ip string) (Lease, bool) {
	db.mu.Lock()
	defer db.mu.Unlock()
	l, ok := db.ByIP[ip]
	return l, ok
}

func (db *LeaseDB) markDeclined(ip string, d time.Duration) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.decline[ip] = time.Now().Add(d)
}

func (db *LeaseDB) isDeclined(ip string) bool {
	db.mu.Lock()
	defer db.mu.Unlock()
	t, ok := db.decline[ip]
	if !ok {
		return false
	}
	if time.Now().After(t) {
		delete(db.decline, ip)
		return false
	}
	return true
}

// removeExpiredOlderThan removes leases whose Expiry + grace < now.
func (db *LeaseDB) removeExpiredOlderThan(grace time.Duration) int {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().Unix()
	graceSecs := int64(grace.Seconds())
	removed := 0

	for ip, l := range db.ByIP {
		if l.Expiry > 0 && now > (l.Expiry+graceSecs) {
			delete(db.ByIP, ip)
			delete(db.ByMAC, strings.ToLower(l.MAC))
			removed++
		}
	}
	if removed > 0 {
		db.dirty = true
	}
	return removed
}

func (db *LeaseDB) compactNow(grace time.Duration) int {
	n := db.removeExpiredOlderThan(grace)
	if n > 0 {
		_ = db.Save()
	}
	return n
}

/* ----------------- Console ----------------- */

// ConsoleUI represents the interactive console UI using tview.
type ConsoleUI struct {
	app        *tview.Application
	logView    *tview.TextView
	inputField *tview.InputField
	topSep     *tview.TextView
	bottomSep  *tview.TextView
	statusText *tview.TextView
	bottomBox  *tview.Flex
	reqTimes   []time.Time
	ackTimes   []time.Time

	mu                  sync.Mutex
	lines               []string // ring buffer content
	maxLines            int      // buffer cap
	filter              string
	filterActive        bool
	filterCaseSensitive bool
	paused              bool
	nocolour            bool
	mouseOn             bool

	lastFocus string // "log" or "input"
}

// NewConsoleUI builds the interactive console using tview.
func NewConsoleUI(nocolour bool, maxLines int) *ConsoleUI {
	if maxLines <= 0 {
		maxLines = 10000
	}
	app := tview.NewApplication()
	ui := &ConsoleUI{
		app:      app,
		nocolour: nocolour,
		maxLines: maxLines,
		mouseOn:  false, // start with terminal-native drag-to-copy
	}

	// Main log view
	logView := tview.NewTextView().
		SetDynamicColors(!nocolour).
		SetScrollable(true).
		SetWrap(false)
	ui.logView = logView

	// Separators (top/bottom lines around the log view)
	ui.topSep = tview.NewTextView().SetWrap(false)
	ui.bottomSep = tview.NewTextView().SetWrap(false)

	// Input field (single line at the bottom)
	input := tview.NewInputField().
		SetLabel("> ").
		SetFieldWidth(0)
	ui.inputField = input

	// Bottom container (just the input; no borders)
	bottom := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(input, 1, 0, true)
	ui.bottomBox = bottom

	// Root layout: top sep, log, bottom sep, then input
	root := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(ui.topSep, 1, 0, false).
		AddItem(logView, 0, 1, false).
		AddItem(ui.bottomSep, 1, 0, false).
		AddItem(bottom, 1, 0, true)

	// Key bindings
	ui.bindKeys()

	// Initial focus: input line active
	ui.lastFocus = "input"
	ui.app.EnableMouse(false)
	ui.app.SetRoot(root, true)
	ui.app.SetFocus(input)

	// Set initial separators (single for unfocused log)
	ui.setLogSeparators(false)

	return ui
}

// Do schedules a UI update on tview's UI goroutine.
func (ui *ConsoleUI) Do(fn func()) { ui.app.QueueUpdateDraw(fn) }

// bindKeys wires all key handling. Global keys act only when the log view is focused.
// Input-line keys are handled via the input field callbacks.
// bindKeys wires global and input-specific key handling.
func (ui *ConsoleUI) bindKeys() {
	// Input behaviors — runs on tview's UI goroutine
	ui.inputField.SetDoneFunc(func(key tcell.Key) {
		switch key {
		case tcell.KeyEnter:
			// Toggle filter state; DO NOT clear the text when disabling
			ui.mu.Lock()
			txt := ui.inputField.GetText()
			if ui.filterActive {
				ui.filterActive = false
				// keep ui.filter and input text intact so user can re-enable quickly
			} else {
				ui.filterActive = true
				ui.filter = txt
			}
			ui.mu.Unlock()

			// repaint
			ui.refreshDirect()

		case tcell.KeyEsc:
			ui.mu.Lock()
			ui.filterActive = false
			ui.filter = ""
			ui.inputField.SetText("") // explicit clear via Esc
			ui.mu.Unlock()

			// repaint
			ui.refreshDirect()
		}
	})

	// Global keymap — runs on the UI goroutine
	ui.app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyTab: // cycle focus: log <-> input
			if ui.app.GetFocus() == ui.logView {
				ui.app.SetFocus(ui.inputField)
				// log loses focus → single line separators
				ui.setLogSeparators(false)
			} else {
				ui.app.SetFocus(ui.logView)
				// log gains focus → double line separators
				ui.setLogSeparators(true)
			}
			return nil

		case tcell.KeyBacktab: // Shift+Tab reverse
			if ui.app.GetFocus() == ui.inputField {
				ui.app.SetFocus(ui.logView)
				ui.setLogSeparators(true)
			} else {
				ui.app.SetFocus(ui.inputField)
				ui.setLogSeparators(false)
			}
			return nil

		case tcell.KeyCtrlC:
			// Hard exit: stop UI and signal INT to self so the server loop exits too.
			ui.app.EnableMouse(false)
			ui.app.Stop()
			_ = syscall.Kill(syscall.Getpid(), syscall.SIGINT)
			return nil

		case tcell.KeyRune:
			// NOTE: global runes (q, m, space, ?, etc.) should only act when log view is focused.
			switch ev.Rune() {
			case 'q', 'Q':
				if ui.app.GetFocus() == ui.logView {
					ui.app.EnableMouse(false)
					ui.app.Stop()
					_ = syscall.Kill(syscall.Getpid(), syscall.SIGINT)
					return nil
				}
			case 'm':
				if ui.app.GetFocus() == ui.logView {
					ui.mu.Lock()
					ui.mouseOn = !ui.mouseOn
					on := ui.mouseOn
					ui.mu.Unlock()
					ui.app.EnableMouse(on)
					return nil
				}
			case '?':
				if ui.app.GetFocus() == ui.logView {
					// (Your modal toggling code goes here; omitted since not related to the crash)
					return nil
				}
			case ' ':
				// Pause/resume only when NOT in the input field
				if ui.app.GetFocus() != ui.inputField {
					ui.mu.Lock()
					ui.paused = !ui.paused
					ui.mu.Unlock()
					return nil
				}
			case 'c':
				// Toggle case only when NOT in the input field (so 'c' can be typed in the filter)
				if ui.app.GetFocus() != ui.inputField {
					ui.mu.Lock()
					ui.filterCaseSensitive = !ui.filterCaseSensitive
					ui.mu.Unlock()
					ui.refreshDirect()
					return nil
				}
			}
		case tcell.KeyUp:
			if ui.app.GetFocus() == ui.logView {
				row, col := ui.logView.GetScrollOffset()
				if row > 0 {
					ui.logView.ScrollTo(row-1, col)
				}
				return nil
			}
		case tcell.KeyDown:
			if ui.app.GetFocus() == ui.logView {
				row, col := ui.logView.GetScrollOffset()
				ui.logView.ScrollTo(row+1, col)
				return nil
			}
		case tcell.KeyPgUp:
			if ui.app.GetFocus() == ui.logView {
				_, _, _, h := ui.logView.GetInnerRect()
				if h < 1 {
					h = 1
				}
				row, col := ui.logView.GetScrollOffset()
				nr := row - (h - 1)
				if nr < 0 {
					nr = 0
				}
				ui.logView.ScrollTo(nr, col)
				return nil
			}
		case tcell.KeyPgDn:
			if ui.app.GetFocus() == ui.logView {
				_, _, _, h := ui.logView.GetInnerRect()
				if h < 1 {
					h = 1
				}
				row, col := ui.logView.GetScrollOffset()
				ui.logView.ScrollTo(row+(h-1), col)
				return nil
			}
		case tcell.KeyHome:
			if ui.app.GetFocus() == ui.logView {
				ui.logView.ScrollToBeginning()
				return nil
			}
		case tcell.KeyEnd:
			if ui.app.GetFocus() == ui.logView {
				ui.logView.ScrollToEnd()
				return nil
			}
		}
		return ev
	})
}

// visualLen returns an approximate printable length by stripping simple tview [tag] blocks.
func visualLen(s string) int {
	inTag := false
	n := 0
	for _, r := range s {
		switch r {
		case '[':
			inTag = true
		case ']':
			if inTag {
				inTag = false
			} else {
				n++ // stray ']' counts
			}
		default:
			if !inTag {
				n++
			}
		}
	}
	return n
}

func (ui *ConsoleUI) updateTitlesDirect(focus string) {
	if focus == ui.lastFocus {
		return
	}
	// Update “borders” based on focus: double lines when log is focused
	ui.setLogSeparators(focus == "log")
	ui.lastFocus = focus
}

// refreshDirect repaints the log view directly.
// Call this ONLY from the UI goroutine (e.g., inside widget callbacks).
func (ui *ConsoleUI) refreshDirect() {
	ui.logView.Clear()
	for _, l := range ui.filteredLines() {
		fmt.Fprintln(ui.logView, l)
	}
	// Keep separators width/form when we repaint
	ui.setLogSeparators(ui.app.GetFocus() == ui.logView)
	// Bottom bar may need an update (e.g., case toggle)
	ui.updateBottomBarDirect()
}

// Start starts the console UI.
func (ui *ConsoleUI) Start() {
	go func() {
		if err := ui.app.Run(); err != nil {
			log.Fatalf("console UI failed: %v", err)
		}
	}()
}

// Stop stops the console UI.
func (ui *ConsoleUI) Stop() {
	ui.app.EnableMouse(false)
	ui.app.Stop()
}

// setLogSeparators draws single ('─') or double ('═') lines to simulate top/bottom borders.
func (ui *ConsoleUI) setLogSeparators(focused bool) {
	// Be nil-safe: if these aren't ready yet, just return.
	if ui.logView == nil || ui.topSep == nil || ui.bottomSep == nil {
		return
	}

	// Use the log view width; GetScreen() isn't available on recent tview.
	_, _, w, _ := ui.logView.GetInnerRect()
	if w <= 0 {
		w = 1
	}

	ch := '─'
	if focused {
		ch = '═'
	}
	line := strings.Repeat(string(ch), w)

	ui.topSep.SetText(line)
	ui.bottomSep.SetText(line)
}

// updateBottomBarDirect updates the 2nd line under the input with help + live RPM/APM.
func (ui *ConsoleUI) updateBottomBarDirect() {
	ui.mu.Lock()
	rpm := len(ui.reqTimes)
	apm := len(ui.ackTimes)
	mouseOn := ui.mouseOn
	filterOn := ui.filterActive
	caseOn := ui.filterCaseSensitive
	paused := ui.paused
	nc := ui.nocolour
	ui.mu.Unlock()

	// Left segment (keys), with blue for keys
	key := func(s string) string {
		if nc {
			return s
		}
		return "[blue::b]" + s + "[-:-:-]"
	}
	left := fmt.Sprintf("%s help | %s switch focus | %s quit | RPM: %d | APM: %d",
		key("?"), key("Tab"), key("Ctrl+C"), rpm, apm)

	// Right segment (statuses): green when "active", yellow when not
	col := func(active bool, label string) string {
		if nc {
			return label
		}
		if active {
			return "[green::b]" + label + "[-:-:-]"
		}
		return "[yellow]" + label + "[-]"
	}
	// Running is "active" when not paused
	right := fmt.Sprintf("%s | %s | %s | %s",
		col(filterOn, "Filter"),
		col(caseOn, "Case Sensitive"),
		col(mouseOn, "Mouse"),
		col(!paused, "Running"),
	)

	// Align right: pad spaces between left and right to fit width
	_, _, w, _ := ui.statusText.GetInnerRect()
	if w <= 0 {
		// Fallback: just concatenate
		ui.statusText.SetText(left + "  " + right)
		return
	}
	pad := w - visualLen(left) - visualLen(right)
	if pad < 1 {
		pad = 1
	}
	ui.statusText.SetText(left + strings.Repeat(" ", pad) + right)
}

// Append appends one line, respecting pause and autoscroll, with bounded ring buffer.
func (ui *ConsoleUI) Append(line string) {
	now := time.Now()

	// Track rates (REQUESTS per minute, ACKS per minute) from incoming lines
	isReq := strings.Contains(line, "REQUEST")
	isAck := strings.Contains(line, "ACK")
	ui.mu.Lock()
	ui.lines = append(ui.lines, line)
	if len(ui.lines) > ui.maxLines {
		excess := len(ui.lines) - ui.maxLines
		ui.lines = ui.lines[excess:]
	}
	// Sliding 60s windows
	cut := now.Add(-60 * time.Second)
	if isReq {
		ui.reqTimes = append(ui.reqTimes, now)
	}
	if isAck {
		ui.ackTimes = append(ui.ackTimes, now)
	}
	// prune
	i := 0
	for _, t := range ui.reqTimes {
		if t.After(cut) {
			break
		}
		i++
	}
	if i > 0 && i <= len(ui.reqTimes) {
		ui.reqTimes = ui.reqTimes[i:]
	}
	j := 0
	for _, t := range ui.ackTimes {
		if t.After(cut) {
			break
		}
		j++
	}
	if j > 0 && j <= len(ui.ackTimes) {
		ui.ackTimes = ui.ackTimes[j:]
	}
	paused := ui.paused
	ui.mu.Unlock()

	// Update UI
	ui.Do(func() {
		if !paused {
			atBottom := ui.atBottom()
			ui.logView.Clear()
			for _, l := range ui.filteredLines() {
				fmt.Fprintln(ui.logView, l)
			}
			if atBottom {
				ui.logView.ScrollToEnd()
			}
		}
		ui.updateBottomBarDirect()
	})
}

func (ui *ConsoleUI) filteredLines() []string {
	ui.mu.Lock()
	defer ui.mu.Unlock()

	flt := ui.filter
	active := ui.filterActive
	caseSens := ui.filterCaseSensitive

	if !active || strings.TrimSpace(flt) == "" {
		out := make([]string, len(ui.lines))
		copy(out, ui.lines)
		return out
	}

	out := make([]string, 0, len(ui.lines))
	if caseSens {
		for _, l := range ui.lines {
			if strings.Contains(l, flt) {
				out = append(out, l)
			}
		}
	} else {
		want := strings.ToLower(flt)
		for _, l := range ui.lines {
			if strings.Contains(strings.ToLower(l), want) {
				out = append(out, l)
			}
		}
	}
	return out
}

func (ui *ConsoleUI) atBottom() bool {
	// Must be called on UI thread via ui.Do.
	filtered := ui.filteredLines()
	total := len(filtered)
	row, _ := ui.logView.GetScrollOffset()
	_, _, _, h := ui.logView.GetInnerRect()
	if h <= 0 {
		h = 1
	}
	if total == 0 {
		return true
	}
	threshold := total - h
	if threshold < 0 {
		threshold = 0
	}
	return row >= threshold
}

/* ----------------- Config parsing & validation ----------------- */

type jsonErr struct {
	Err    error
	Line   int
	Column int
}

func (e *jsonErr) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("%v (line %d, column %d)", e.Err, e.Line, e.Column)
	}
	return e.Err.Error()
}

func locateJSONError(data []byte, off int64) (line, col int) {
	if off <= 0 {
		return 0, 0
	}
	if off > int64(len(data)) {
		off = int64(len(data))
	}
	line, col = 1, 1
	for i := int64(0); i < off-1 && i < int64(len(data)); i++ {
		if data[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return
}

func parseConfigStrict(path string) (Config, *jsonErr) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, &jsonErr{Err: err}
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		if se, ok := err.(*json.SyntaxError); ok {
			line, col := locateJSONError(data, se.Offset)
			return cfg, &jsonErr{Err: err, Line: line, Column: col}
		}
		if ute, ok := err.(*json.UnmarshalTypeError); ok {
			line, col := locateJSONError(data, ute.Offset)
			return cfg, &jsonErr{Err: err, Line: line, Column: col}
		}
		return cfg, &jsonErr{Err: err}
	}
	// defaults
	if cfg.LeaseSeconds <= 0 {
		cfg.LeaseSeconds = 86400 // 24h
	}
	if cfg.LeaseStickySeconds <= 0 {
		cfg.LeaseStickySeconds = 86400 // default sticky window
	}
	if len(cfg.Pools) == 0 {
		return cfg, &jsonErr{Err: errors.New("config: at least one pool required")}
	}
	if cfg.Reservations == nil {
		cfg.Reservations = make(Reservations)
	}
	return cfg, nil
}

/* ----------------- Small helpers ----------------- */

func errf(format string, a ...any) error {
	msg := fmt.Sprintf(format, a...)
	// File logger stays clean. This helper is only for immediate stderr prints.
	// Use aurora for colour; respect the user’s preference elsewhere if needed.
	fmt.Fprintln(os.Stderr, aurora.Red(fmt.Sprintf("ERROR: %s", msg)))
	return errors.New(msg)
}

func warnf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	// Immediate stderr warning with aurora; file logs remain clean.
	fmt.Fprintln(os.Stderr, aurora.Yellow(fmt.Sprintf("WARNING: %s", msg)))
}

// Accepts with ":" "-" or no separators (12 hex chars)
func normalizeMACFlexible(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	// remove separators
	raw := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9':
			return r
		case r >= 'a' && r <= 'f':
			return r
		default:
			return -1
		}
	}, s)
	if len(raw) == 12 {
		var parts []string
		for i := 0; i < 12; i += 2 {
			parts = append(parts, raw[i:i+2])
		}
		s = strings.Join(parts, ":")
	} else {
		// keep original (maybe already colon/dash separated)
		s = strings.ReplaceAll(s, "-", ":")
	}
	m, err := net.ParseMAC(s)
	if err != nil {
		return "", err
	}
	return strings.ToLower(m.String()), nil
}

func mustCIDR(c string) (net.IP, *net.IPNet) {
	ip, n, err := net.ParseCIDR(c)
	if err != nil {
		log.Fatalf("bad subnet_cidr %q: %v", c, err)
	}
	return ip, n
}

func parseIP4(s string) net.IP {
	ip := net.ParseIP(strings.TrimSpace(s)).To4()
	if ip == nil {
		log.Fatalf("bad IPv4 %q", s)
	}
	return ip
}

func toIPs(list []string) []net.IP {
	out := make([]net.IP, 0, len(list))
	for _, s := range list {
		ip := net.ParseIP(strings.TrimSpace(s)).To4()
		if ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

func ipToU32(ip net.IP) uint32 { return binary.BigEndian.Uint32(ip.To4()) }
func u32ToIP(v uint32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return net.IP(b)
}
func incIP(ip net.IP) net.IP                  { return u32ToIP(ipToU32(ip) + 1) }
func ipInSubnet(ip net.IP, n *net.IPNet) bool { return n.Contains(ip) }

// parseHexPayload: accepts "01 02", "0x01,0x02", "hex:01:02", etc.
func parseHexPayload(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "hex:")
	s = strings.ReplaceAll(s, "0x", "")
	s = strings.NewReplacer(" ", "", ":", "", ",", "", "-", "").Replace(s)
	if s == "" {
		return nil, nil
	}
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("hex length must be even")
	}
	return hex.DecodeString(s)
}

func broadcastAddr(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	mask := net.IP(n.Mask).To4()
	var b [4]byte
	for i := 0; i < 4; i++ {
		b[i] = ip[i] | ^mask[i]
	}
	return net.IP(b[:])
}

/* ----------------- Logging ----------------- */

func setupLogger(path string) (*log.Logger, *os.File, error) {
	// We keep the file logger always clean (no ANSI), and handle console printing ourselves
	// so we can colourize the console only without polluting the file.
	if path == "" {
		// No file; still return a logger that writes to stdout (uncoloured),
		// we'll add a separate coloured console echo elsewhere.
		lg := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
		return lg, nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && !os.IsExist(err) {
		return nil, nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, nil, err
	}
	// IMPORTANT: file logger only — no MultiWriter — to avoid ANSI in files.
	lg := log.New(f, "", log.LstdFlags|log.Lmicroseconds)
	return lg, f, nil
}

// colourizeConsoleLine highlights key DHCP tokens (REQUEST, DISCOVER, OFFER, ACK, NAK, RELEASE, DECLINE, BANNED-MAC).
// Green = success-ish, Yellow = info/normal verbs, Red = errors/NAKs/banned.
func colourizeConsoleLine(line string, nocolour bool) string {
	if nocolour {
		return line
	}
	// Map important tokens to tview color tags.
	repls := [][2]string{
		{" BANNED-MAC", " [red::b]BANNED-MAC[-:-:-]"},
		{" NAK", " [red::b]NAK[-:-:-]"},
		{" ACK", " [green::b]ACK[-:-:-]"},
		{" OFFER", " [green::b]OFFER[-:-:-]"},
		{" REQUEST", " [yellow::b]REQUEST[-:-:-]"},
		{" DISCOVER", " [yellow::b]DISCOVER[-:-:-]"},
		{" RELEASE", " [yellow::b]RELEASE[-:-:-]"},
		{" DECLINE", " [yellow::b]DECLINE[-:-:-]"},

		{"-> NAK", "-> [red::b]NAK[-:-:-]"},
		{"BANNED-MAC", "[red::b]BANNED-MAC[-:-:-]"},
		{"NAK", "[red::b]NAK[-:-:-]"},
		{"ACK", "[green::b]ACK[-:-:-]"},
		{"OFFER", "[green::b]OFFER[-:-:-]"},
		{"REQUEST", "[yellow::b]REQUEST[-:-:-]"},
		{"DISCOVER", "[yellow::b]DISCOVER[-:-:-]"},
		{"RELEASE", "[yellow::b]RELEASE[-:-:-]"},
		{"DECLINE", "[yellow::b]DECLINE[-:-:-]"},
	}
	out := line
	for _, rp := range repls {
		out = strings.ReplaceAll(out, rp[0], rp[1])
	}
	return out
}

func (s *Server) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)

	if s.logger != nil {
		s.logger.Printf("%s", msg)
	}

	if s.consoleUI != nil {
		ts := time.Now().Format("2006/01/02 15:04:05.000000")
		line := colourizeConsoleLine(ts+" "+msg, s.nocolour)
		s.consoleUI.Append(line)
	}
}

// errorf logs to file and (if console enabled) prints red-tagged highlights to stderr too.
func (s *Server) errorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)

	if s.logger != nil {
		s.logger.Printf("ERROR: %s", msg)
	}

	if s.consoleUI != nil {
		ts := time.Now().Format("2006/01/02 15:04:05.000000")
		line := aurora.Red("ERROR").String() + ": " + msg
		s.consoleUI.Append(ts + " " + line)
	}
}

// xidString logs the 4-byte transaction ID consistently.
func xidString(req *dhcpv4.DHCPv4) string {
	b := req.TransactionID
	if len(b) >= 4 {
		return fmt.Sprintf("0x%08x", binary.BigEndian.Uint32(b[:4]))
	}
	return fmt.Sprintf("0x%x", b)
}

// macDisplay returns a user-friendly, zero-padded MAC for logs.
func macDisplay(b []byte) string {
	return net.HardwareAddr(b).String() // "aa:bb:cc:dd:ee:ff"
}

/* ----------------- Server ----------------- */

// Server represents a DHCP server instance.
type Server struct {
	mu sync.RWMutex

	cfg          Config
	iface        string
	serverIP     net.IP
	subnet       *net.IPNet
	gatewayIP    net.IP
	dnsIPs       []net.IP
	leaseDur     time.Duration
	stickyDur    time.Duration
	exclusions   map[string]struct{}
	reservations map[string]string
	deviceOv     map[string]DeviceOverride

	ntpIPs   []net.IP
	mtu      int
	tftpName string
	bootfile string
	wpadURL  string
	winsIPs  []net.IP

	domainSearch []string
	staticRoutes []StaticRoute
	mirror249    bool
	vend43       []byte

	db            *LeaseDB
	authoritative bool

	// logging
	logger  *log.Logger
	logFile *os.File
	console bool

	// banned MACs (from config) as meta + set
	bannedMeta map[string]DeviceMeta
	bannedSet  map[string]struct{}

	// disable console colours when true (set by --nocolour)
	nocolour bool

	// used for console UI
	consoleUI *ConsoleUI
}

func buildServerFromConfig(cfg Config, leasePath string, authoritative bool, old *Server) *Server {
	_, subnet := mustCIDR(cfg.SubnetCIDR)
	serverIP := parseIP4(cfg.ServerIP)
	gatewayIP := parseIP4(cfg.Gateway)

	// Default enumerations if missing
	if len(cfg.EquipmentTypes) == 0 {
		cfg.EquipmentTypes = []string{"Switch", "Router", "AP", "Modem", "Gateway"}
	}
	if len(cfg.ManagementTypes) == 0 {
		cfg.ManagementTypes = []string{"ssh", "web", "telnet", "serial", "console"}
	}

	dnsIPs := toIPs(cfg.DNS)
	ntpIPs := toIPs(cfg.NTP)
	winsIPs := toIPs(cfg.WINS)

	mtu := 0
	if cfg.MTU > 0 {
		mtu = cfg.MTU
	}
	tftpName := strings.TrimSpace(cfg.TFTPServerName)
	bootfile := strings.TrimSpace(cfg.BootFileName)
	wpad := strings.TrimSpace(cfg.WPADURL)

	exc := map[string]struct{}{}
	for _, e := range cfg.Exclusions {
		ip := parseIP4(e)
		exc[ip.String()] = struct{}{}
	}

	// Normalize reservations and validate enums
	res := map[string]string{}
	for m, rv := range cfg.Reservations {
		nm, err := normalizeMACFlexible(m) // <— flexible, lower-case, colonized
		if err != nil {
			log.Fatalf("bad reservation MAC %q: %v", m, err)
		}
		rip := parseIP4(rv.IP)
		res[nm] = rip.String()

		// validate equipment_type and management_type if present
		if rv.EquipmentType != "" && !stringInSlice(rv.EquipmentType, cfg.EquipmentTypes) {
			log.Printf("warning: reservation %s has unknown equipment_type %q; allowed: %v", nm, rv.EquipmentType, cfg.EquipmentTypes)
		}
		if rv.ManagementType != "" && !stringInSlice(rv.ManagementType, cfg.ManagementTypes) {
			log.Printf("warning: reservation %s has unknown management_type %q; allowed: %v", nm, rv.ManagementType, cfg.ManagementTypes)
		}
	}

	// Per-device overrides
	devOv := map[string]DeviceOverride{}
	for m, ov := range cfg.DeviceOverrides {
		nm, err := normalizeMACFlexible(m) // <— flexible
		if err != nil {
			log.Fatalf("bad device_overrides MAC %q: %v", m, err)
		}
		devOv[nm] = ov
	}

	// Vendor specific 43
	var vend43 []byte
	if cfg.VendorSpecific43Hex != "" {
		v43, err := parseHexPayload(cfg.VendorSpecific43Hex)
		if err != nil {
			log.Fatalf("vendor_specific_43_hex: %v", err)
		}
		vend43 = v43
	}

	// Leasedb
	var db *LeaseDB
	if old != nil && old.db != nil {
		db = old.db
	} else {
		db = NewLeaseDB(leasePath)
		if err := db.Load(); err != nil {
			log.Printf("lease db load: %v (continuing with empty)", err)
		}
	}

	// Normalize Banned MACs to a set and keep meta
	bannedMeta := make(map[string]DeviceMeta)
	bannedSet := make(map[string]struct{})
	for m, meta := range cfg.BannedMACs {
		nm, err := normalizeMACFlexible(m) // <— flexible
		if err != nil {
			log.Fatalf("bad banned_macs MAC %q: %v", m, err)
		}
		// enum validation
		if meta.EquipmentType != "" && !stringInSlice(meta.EquipmentType, cfg.EquipmentTypes) {
			log.Printf("warning: banned %s has unknown equipment_type %q; allowed: %v", nm, meta.EquipmentType, cfg.EquipmentTypes)
		}
		if meta.ManagementType != "" && !stringInSlice(meta.ManagementType, cfg.ManagementTypes) {
			log.Printf("warning: banned %s has unknown management_type %q; allowed: %v", nm, meta.ManagementType, cfg.ManagementTypes)
		}
		bannedMeta[nm] = meta
		bannedSet[nm] = struct{}{}
	}

	s := &Server{
		cfg:           cfg,
		iface:         cfg.Interface,
		serverIP:      serverIP,
		subnet:        subnet,
		gatewayIP:     gatewayIP,
		dnsIPs:        dnsIPs,
		leaseDur:      time.Duration(cfg.LeaseSeconds) * time.Second,
		stickyDur:     time.Duration(cfg.LeaseStickySeconds) * time.Second,
		exclusions:    exc,
		reservations:  res,
		deviceOv:      devOv,
		ntpIPs:        ntpIPs,
		mtu:           mtu,
		tftpName:      tftpName,
		bootfile:      bootfile,
		wpadURL:       wpad,
		winsIPs:       winsIPs,
		domainSearch:  cfg.DomainSearch,
		staticRoutes:  cfg.StaticRoutes,
		mirror249:     cfg.MirrorRoutesTo249,
		vend43:        vend43,
		db:            db,
		authoritative: authoritative,

		// NEW:
		bannedMeta: bannedMeta,
		bannedSet:  bannedSet,
	}
	// inherit logger/console if old provided
	if old != nil {
		s.logger = old.logger
		s.logFile = old.logFile
		s.console = old.console
	}

	// Ensure reservations are authoritative over leases
	s.enforceReservationLeaseConsistency()

	return s
}

// reservations win over leases
func (s *Server) enforceReservationLeaseConsistency() {
	// 1) Do all mutations under the DB lock, but DO NOT Save() while locked.
	s.db.mu.Lock()
	changed := false
	for mac, r := range s.cfg.Reservations {
		norm := strings.ToLower(mac)
		// Reserved IP must not be leased to someone else
		if l, ok := s.db.ByIP[r.IP]; ok && !macEqual(l.MAC, norm) {
			delete(s.db.ByMAC, strings.ToLower(l.MAC))
			delete(s.db.ByIP, r.IP)
			changed = true
		}
		// Reserved MAC must not have a lease on a different IP
		if l, ok := s.db.ByMAC[norm]; ok && l.IP != r.IP {
			delete(s.db.ByIP, l.IP)
			delete(s.db.ByMAC, norm)
			changed = true
		}
	}
	if changed {
		s.db.dirty = true
	}
	s.db.mu.Unlock()

	// 2) Save outside the lock to avoid deadlock.
	if changed {
		_ = s.db.Save()
	}
}

func buildServer(cfgPath string, leasePath string, authoritative bool) *Server {
	cfg, jerr := parseConfigStrict(cfgPath)
	if jerr != nil {
		log.Fatalf("config error: %v", jerr)
	}

	if len(cfg.EquipmentTypes) == 0 {
		cfg.EquipmentTypes = []string{"Switch", "Router", "AP", "Modem", "Gateway"}
	}
	if len(cfg.ManagementTypes) == 0 {
		cfg.ManagementTypes = []string{"ssh", "web", "telnet", "serial", "console"}
	}

	now := time.Now().Unix()
	changed := false
	for k, v := range cfg.Reservations {
		if v.FirstSeen == 0 {
			v.FirstSeen = now
			cfg.Reservations[k] = v
			changed = true
		}
	}
	if cfg.BannedMACs == nil {
		cfg.BannedMACs = make(map[string]DeviceMeta)
	}
	for k, v := range cfg.BannedMACs {
		if v.FirstSeen == 0 {
			v.FirstSeen = now
			cfg.BannedMACs[k] = v
			changed = true
		}
	}
	if changed {
		tmp := cfgPath + ".tmp"
		if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err == nil {
			if f, err := os.Create(tmp); err == nil {
				enc := json.NewEncoder(f)
				enc.SetIndent("", "  ")
				if err := enc.Encode(&cfg); err == nil {
					_ = f.Sync()
					_ = f.Close()
					_ = os.Rename(tmp, cfgPath)
				} else {
					_ = f.Close()
					_ = os.Remove(tmp)
					log.Printf("warning: failed to persist first_seen: %v", err)
				}
			}
		}
	}

	return buildServerFromConfig(cfg, leasePath, authoritative, nil)
}

/* --------------- DHCP handler --------------- */

// Handler handles incoming DHCP requests.
func (s *Server) Handler(conn net.PacketConn, peer net.Addr, req *dhcpv4.DHCPv4) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	mt := req.MessageType()
	dispMAC := macDisplay(req.ClientHWAddr)

	// Canonicalize to lower-case "aa:bb:.." and use that everywhere internally.
	var mac string
	if nm, err := normalizeMACFlexible(dispMAC); err == nil {
		mac = nm
	} else {
		// very unlikely; keep a lower-cased best-effort so we don't crash
		mac = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(dispMAC), "-", ":"), " ", ""))
	}

	hostname := strings.TrimRight(string(req.Options.Get(dhcpv4.OptionHostName)), "\x00")

	// BANNED MAC check (config/env-driven)
	banned := parseBannedMACsEnv() // or s.bannedSet if you prefer config-only
	if _, isBanned := banned[mac]; isBanned {
		s.logf("BANNED-MAC %s (%q) sent %s xid=%s — denying", dispMAC, hostname, mt.String(), xidString(req))
		warnf("BANNED-MAC %s (%q) sent %s xid=%s — denying", dispMAC, hostname, mt.String(), xidString(req))
		if mt == dhcpv4.MessageTypeRequest && s.authoritative {
			nak, _ := dhcpv4.NewReplyFromRequest(req)
			nak.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
			nak.UpdateOption(dhcpv4.OptServerIdentifier(s.serverIP))
			_, _ = conn.WriteTo(nak.ToBytes(), peer)
		}
		return
	}

	switch mt {
	case dhcpv4.MessageTypeDiscover:
		s.logf("DISCOVER from %s hostname=%q xid=%s", dispMAC, hostname, xidString(req))
		ip, ok := s.chooseIPForMAC(mac)
		if !ok {
			s.errorf("POOL EXHAUSTED for %s: no address available in configured pools", dispMAC)
			if s.authoritative {
				nak, _ := dhcpv4.NewReplyFromRequest(req)
				nak.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
				nak.UpdateOption(dhcpv4.OptServerIdentifier(s.serverIP))
				_, _ = conn.WriteTo(nak.ToBytes(), peer)
			}
			return
		}
		offer, err := s.buildReply(req, dhcpv4.MessageTypeOffer, ip, mac)
		if err != nil {
			s.logf("offer build error for %s: %v", dispMAC, err)
			return
		}
		s.logf("OFFER %s -> %s", dispMAC, ip.String())
		_, _ = conn.WriteTo(offer.ToBytes(), peer)

	case dhcpv4.MessageTypeRequest:
		var reqIP net.IP
		if rip := req.Options.Get(dhcpv4.OptionRequestedIPAddress); len(rip) == 4 {
			reqIP = net.IP(rip)
		} else if !req.ClientIPAddr.Equal(net.IPv4zero) {
			reqIP = req.ClientIPAddr
		}
		s.logf("REQUEST from %s requested_ip=%v ciaddr=%v xid=%s", dispMAC, reqIP, req.ClientIPAddr, xidString(req))

		if reqIP == nil {
			ip, ok := s.chooseIPForMAC(mac)
			if !ok {
				s.errorf("POOL EXHAUSTED for %s: no address available in configured pools", dispMAC)
				if s.authoritative {
					nak, _ := dhcpv4.NewReplyFromRequest(req)
					nak.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
					nak.UpdateOption(dhcpv4.OptServerIdentifier(s.serverIP))
					_, _ = conn.WriteTo(nak.ToBytes(), peer)
				}
				return
			}
			reqIP = ip
		}
		if !ipInSubnet(reqIP, s.subnet) || s.isExcluded(reqIP) || s.db.isDeclined(reqIP.String()) {
			s.logf("REQUEST invalid ip=%s for %s (excluded/declined/out-of-subnet)", reqIP, dispMAC)
			if s.authoritative {
				nak, _ := dhcpv4.NewReplyFromRequest(req)
				nak.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
				nak.UpdateOption(dhcpv4.OptServerIdentifier(s.serverIP))
				_, _ = conn.WriteTo(nak.ToBytes(), peer)
			}
			return
		}
		if rmac := s.macForReservedIP(reqIP); rmac != "" && !macEqual(rmac, mac) { // <-- use macEqual here
			s.logf("REQUEST %s asked for reserved ip=%s owned by %s -> NAK", dispMAC, reqIP, rmac)
			if s.authoritative {
				nak, _ := dhcpv4.NewReplyFromRequest(req)
				nak.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
				nak.UpdateOption(dhcpv4.OptServerIdentifier(s.serverIP))
				_, _ = conn.WriteTo(nak.ToBytes(), peer)
			}
			return
		}
		if l, ok := s.db.findByIP(reqIP.String()); ok {
			now := time.Now().Unix()
			if now <= l.Expiry && !macEqual(l.MAC, mac) {
				s.logf("REQUEST ip=%s already leased to %s until %s -> NAK", reqIP, l.MAC, formatEpoch(l.Expiry))
				if s.authoritative {
					nak, _ := dhcpv4.NewReplyFromRequest(req)
					nak.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
					nak.UpdateOption(dhcpv4.OptServerIdentifier(s.serverIP))
					_, _ = conn.WriteTo(nak.ToBytes(), peer)
				}
				return
			}
		}

		// Determine first_seen
		firstSeen := int64(0)
		if prev, ok := s.db.findByMAC(mac); ok && prev.FirstSeen > 0 {
			firstSeen = prev.FirstSeen
		} else {
			firstSeen = time.Now().Unix()
			// Log to file and console only; DO NOT write to stdout
			msg := fmt.Sprintf("first_seen: %s here on %s", mac, formatEpoch(firstSeen))
			s.logf("%s", msg)
			// (removed) fmt.Fprintf(os.Stdout, "%s\n", msg)
		}

		now := time.Now().Unix()
		ack, err := s.buildReply(req, dhcpv4.MessageTypeAck, reqIP, mac)
		if err != nil {
			s.logf("ack build error for %s ip=%s: %v", dispMAC, reqIP, err)
			return
		}
		lease := Lease{
			MAC:         mac,
			IP:          reqIP.String(),
			Hostname:    hostname,
			AllocatedAt: now,
			Expiry:      now + int64(s.leaseDur.Seconds()),
			FirstSeen:   firstSeen,
		}
		s.db.set(lease)
		_ = s.db.Save()
		s.logf("ACK %s <- %s lease=%s (alloc=%s, exp=%s)", dispMAC, reqIP.String(), s.leaseDur, formatEpoch(lease.AllocatedAt), formatEpoch(lease.Expiry))
		_, _ = conn.WriteTo(ack.ToBytes(), peer)

	case dhcpv4.MessageTypeRelease:
		if !req.ClientIPAddr.Equal(net.IPv4zero) {
			s.db.removeByIP(req.ClientIPAddr.String())
			_ = s.db.Save()
			s.logf("RELEASE from %s ip=%s", dispMAC, req.ClientIPAddr.String())
		}

	case dhcpv4.MessageTypeDecline:
		if rip := req.Options.Get(dhcpv4.OptionRequestedIPAddress); len(rip) == 4 {
			ip := net.IP(rip).String()
			s.db.markDeclined(ip, 10*time.Minute)
			s.logf("DECLINE from %s ip=%s quarantined 10m", dispMAC, ip)
		}

	default:
		s.logf("Unhandled DHCP msg type %v from %s", mt, dispMAC)
	}
}

func (s *Server) isExcluded(ip net.IP) bool {
	_, ok := s.exclusions[ip.String()]
	return ok
}

func (s *Server) macForReservedIP(ip net.IP) string {
	for m, r := range s.cfg.Reservations {
		if r.IP == ip.String() {
			return m
		}
	}
	return ""
}

// chooseIPForMAC implements the new policy:
//
//  1. If there is a reservation for this MAC -> return it.
//  2. If this MAC had any previous lease -> try that same IP again (even if long expired),
//     provided it isn't excluded/declined/reserved for someone else/actively leased by another MAC.
//  3. Scan pools for a **brand-new** IP (never seen in the leases DB).
//  4. If none available, recycle an **expired** previously-used IP that is safe to reuse.
//  5. If still none, return false (pool exhausted).
func (s *Server) chooseIPForMAC(mac string) (net.IP, bool) {
	// 1) Reservation first
	if rip, ok := s.reservations[mac]; ok {
		ip := net.ParseIP(rip).To4()
		if ip == nil || !ipInSubnet(ip, s.subnet) || s.isExcluded(ip) || s.db.isDeclined(ip.String()) {
			return nil, false
		}
		// If someone else actively holds it, we cannot give it yet.
		if l, ok := s.db.findByIP(ip.String()); ok {
			now := time.Now().Unix()
			if now <= l.Expiry && !macEqual(l.MAC, mac) {
				return nil, false
			}
		}
		return ip, true
	}

	now := time.Now().Unix()

	// 2) Prefer same IP we gave this MAC before (if safe).
	if l, ok := s.db.findByMAC(mac); ok {
		ip := net.ParseIP(l.IP).To4()
		if ip != nil &&
			ipInSubnet(ip, s.subnet) &&
			!s.isExcluded(ip) &&
			!s.db.isDeclined(ip.String()) {

			// Proceed only if the IP is NOT reserved for a different MAC.
			rmac := s.macForReservedIP(ip)
			if rmac == "" || macEqual(rmac, mac) {
				if cur, ok := s.db.findByIP(ip.String()); !ok ||
					macEqual(cur.MAC, mac) || now > cur.Expiry {
					return ip, true
				}
			}
		}
	}

	// helper to filter unusable IPs
	isBad := func(ip net.IP) bool {
		if !ipInSubnet(ip, s.subnet) || s.isExcluded(ip) || s.db.isDeclined(ip.String()) {
			return true
		}
		if ip.Equal(s.serverIP) || ip.Equal(s.gatewayIP) {
			return true
		}
		network := s.subnet.IP.Mask(s.subnet.Mask)
		bcast := broadcastAddr(s.subnet)
		if ip.Equal(network) || ip.Equal(bcast) {
			return true
		}
		if rmac := s.macForReservedIP(ip); rmac != "" && !macEqual(rmac, mac) {
			return true
		}
		return false
	}

	// 3) Brand-new IPs (never in DB)
	for _, p := range s.cfg.Pools {
		start := parseIP4(p.Start)
		end := parseIP4(p.End)
		for ip := start; ipToU32(ip) <= ipToU32(end); ip = incIP(ip) {
			if isBad(ip) {
				continue
			}
			if _, ever := s.db.findByIP(ip.String()); !ever {
				return ip, true
			}
		}
	}

	// 4) Recycle expired, safe IPs
	for _, p := range s.cfg.Pools {
		start := parseIP4(p.Start)
		end := parseIP4(p.End)
		for ip := start; ipToU32(ip) <= ipToU32(end); ip = incIP(ip) {
			if isBad(ip) {
				continue
			}
			if l, ok := s.db.findByIP(ip.String()); ok {
				rmac := s.macForReservedIP(ip)
				if now > l.Expiry && (macEqual(l.MAC, mac) || rmac == "" || macEqual(rmac, mac)) {
					return ip, true
				}
				continue
			}
		}
	}

	return nil, false
}

func (s *Server) buildReply(req *dhcpv4.DHCPv4, typ dhcpv4.MessageType, yiaddr net.IP, mac string) (*dhcpv4.DHCPv4, error) {
	resp, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		return nil, err
	}
	resp.UpdateOption(dhcpv4.OptMessageType(typ))
	resp.YourIPAddr = yiaddr.To4()

	// Core identifiers and timers
	resp.UpdateOption(dhcpv4.OptServerIdentifier(s.serverIP))
	resp.UpdateOption(dhcpv4.OptSubnetMask(net.IPMask(s.subnet.Mask)))
	resp.UpdateOption(dhcpv4.OptRouter(s.gatewayIP))
	resp.UpdateOption(dhcpv4.OptIPAddressLeaseTime(s.leaseDur))
	resp.UpdateOption(dhcpv4.OptRenewTimeValue(s.leaseDur / 2))
	resp.UpdateOption(dhcpv4.OptRebindingTimeValue(s.leaseDur * 7 / 8))

	// Global DNS (can be overridden per-device)
	if len(s.dnsIPs) > 0 {
		resp.UpdateOption(dhcpv4.OptDNS(s.dnsIPs...))
	}
	if s.cfg.Domain != "" {
		resp.UpdateOption(dhcpv4.OptDomainName(s.cfg.Domain))
	}

	// Global extras
	if len(s.ntpIPs) > 0 {
		resp.UpdateOption(dhcpv4.OptNTPServers(s.ntpIPs...))
	}
	if s.mtu > 0 {
		mtu := make([]byte, 2)
		binary.BigEndian.PutUint16(mtu, uint16(s.mtu))
		resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(26), mtu)) // Interface MTU
	}
	// Global TFTP/Bootfile (overridable by device)
	if s.tftpName != "" {
		resp.UpdateOption(dhcpv4.OptTFTPServerName(s.tftpName)) // 66
	}
	if s.bootfile != "" {
		resp.BootFileName = s.bootfile
		resp.UpdateOption(dhcpv4.OptBootFileName(s.bootfile)) // 67
	}
	// WPAD (252)
	if s.wpadURL != "" {
		resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(252), []byte(s.wpadURL)))
	}
	// WINS (44)
	if len(s.winsIPs) > 0 {
		resp.UpdateOption(dhcpv4.OptNetBIOSNameServers(s.winsIPs...))
	}
	// Domain Search (119)
	if len(s.domainSearch) > 0 {
		lbls := &rfc1035label.Labels{Labels: append([]string(nil), s.domainSearch...)}
		resp.UpdateOption(dhcpv4.OptDomainSearch(lbls))
	}
	// Classless Routes (121) + optional mirror 249
	if len(s.staticRoutes) > 0 {
		var rs []*dhcpv4.Route
		for _, r := range s.staticRoutes {
			_, ipnet, err := net.ParseCIDR(strings.TrimSpace(r.CIDR))
			if err != nil {
				return nil, fmt.Errorf("bad CIDR %q: %w", r.CIDR, err)
			}
			gw := parseIP4(r.Gateway)
			rs = append(rs, &dhcpv4.Route{Dest: ipnet, Router: gw})
		}
		resp.UpdateOption(dhcpv4.OptClasslessStaticRoute(rs...)) // 121
		if s.mirror249 {
			b := dhcpv4.Routes(rs).ToBytes()
			resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(249), b))
		}
	}
	// Vendor Specific (43) raw payload
	if len(s.vend43) > 0 {
		resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionVendorSpecificInformation, s.vend43))
	}

	// Per-device overrides: ONLY DNS/TFTP/Bootfile
	if ov, has := s.deviceOv[mac]; has {
		if len(ov.DNS) > 0 {
			resp.UpdateOption(dhcpv4.OptDNS(toIPs(ov.DNS)...))
		}
		if ov.TFTPServerName != "" {
			resp.UpdateOption(dhcpv4.OptTFTPServerName(ov.TFTPServerName))
		}
		if ov.BootFileName != "" {
			resp.BootFileName = ov.BootFileName
			resp.UpdateOption(dhcpv4.OptBootFileName(ov.BootFileName))
		}
	}

	return resp, nil
}

/* ----------------- Reload & runtime ----------------- */

func (s *Server) applyNewConfig(cfg Config, leasePath string) {
	// Build a temp server from cfg, then copy fields under lock.
	newS := buildServerFromConfig(cfg, leasePath, s.authoritative, s)
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cfg = newS.cfg
	s.iface = newS.iface
	s.serverIP = newS.serverIP
	s.subnet = newS.subnet
	s.gatewayIP = newS.gatewayIP
	s.dnsIPs = newS.dnsIPs
	s.leaseDur = newS.leaseDur
	s.stickyDur = newS.stickyDur
	s.exclusions = newS.exclusions
	s.reservations = newS.reservations
	s.deviceOv = newS.deviceOv
	s.ntpIPs = newS.ntpIPs
	s.mtu = newS.mtu
	s.tftpName = newS.tftpName
	s.bootfile = newS.bootfile
	s.wpadURL = newS.wpadURL
	s.winsIPs = newS.winsIPs
	s.domainSearch = newS.domainSearch
	s.staticRoutes = newS.staticRoutes
	s.mirror249 = newS.mirror249
	s.vend43 = newS.vend43
	// db/logger/console unchanged
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

func (s *Server) startWatcher(cfgPath, leasePath string) (*fsnotify.Watcher, error) {
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
				if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Chmod) != 0 {
					time.Sleep(150 * time.Millisecond)
					cfg, jerr := parseConfigStrict(cfgPath)
					if jerr != nil {
						s.logf("AUTO-RELOAD: config invalid, keeping old settings: %v", jerr)
						continue
					}
					now := time.Now().Unix()
					changed := false
					for k, v := range cfg.Reservations {
						if v.FirstSeen == 0 {
							v.FirstSeen = now
							cfg.Reservations[k] = v
							changed = true
						}
					}
					if cfg.BannedMACs == nil {
						cfg.BannedMACs = make(map[string]DeviceMeta)
					}
					for k, v := range cfg.BannedMACs {
						if v.FirstSeen == 0 {
							v.FirstSeen = now
							cfg.BannedMACs[k] = v
							changed = true
						}
					}
					if changed {
						tmp := cfgPath + ".tmp"
						if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err == nil {
							if f, err := os.Create(tmp); err == nil {
								enc := json.NewEncoder(f)
								enc.SetIndent("", "  ")
								if err := enc.Encode(&cfg); err == nil {
									_ = f.Sync()
									_ = f.Close()
									_ = os.Rename(tmp, cfgPath)
								} else {
									_ = f.Close()
									_ = os.Remove(tmp)
									s.logf("AUTO-RELOAD: failed to persist first_seen: %v", err)
								}
							}
						}
					}
					s.applyNewConfig(cfg, leasePath)
					s.enforceReservationLeaseConsistency()
					if s.cfg.CompactOnLoad {
						if n := s.db.compactNow(s.stickyDur); n > 0 {
							s.logf("LEASE-COMPACT removed=%d (on auto-reload)", n)
						}
					}
					s.logf("AUTO-RELOAD: config applied")
				}
			case err := <-w.Errors:
				s.logf("watcher error: %v", err)
			}
		}
	}()
	return w, nil
}

func buildServerAndRun(cfgPath, leasePath string, authoritative bool, logPath string, console bool, pidPath string, nocolour bool) error {
	s := buildServer(cfgPath, leasePath, authoritative)

	lg, f, err := setupLogger(logPath)
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	s.logger = lg
	s.logFile = f
	s.console = console
	s.nocolour = nocolour

	if console {
		maxLines := s.cfg.ConsoleMaxLines
		if maxLines <= 0 {
			maxLines = 10000
		}
		s.consoleUI = NewConsoleUI(nocolour, maxLines)
		s.consoleUI.Start()
		defer s.consoleUI.Stop()
	}

	// PID
	if err := writePID(pidPath); err != nil {
		return fmt.Errorf("write pid: %w", err)
	}

	// One-shot compaction on initial load ONLY if enabled
	if s.cfg.CompactOnLoad {
		if n := s.db.compactNow(s.stickyDur); n > 0 {
			s.logf("LEASE-COMPACT removed=%d (on initial load)", n)
		}
	}

	// Optional auto-reload watcher
	var watcher *fsnotify.Watcher
	if s.cfg.AutoReload {
		watcher, err = s.startWatcher(cfgPath, leasePath)
		if err != nil {
			s.logf("AUTO-RELOAD: watcher failed: %v", err)
		} else {
			s.logf("AUTO-RELOAD: watching %s", cfgPath)
		}
	}

	// Bind: interface name ("" for all), local UDP addr :67
	laddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 67}
	srv, err := server4.NewServer(s.iface, laddr, s.Handler)
	if err != nil {
		if watcher != nil {
			_ = watcher.Close()
		}
		return fmt.Errorf("bind: %w (need root/CAP_NET_BIND_SERVICE)", err)
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve() }()

	s.logf("START iface=%q bind=%s server_ip=%s subnet=%s gateway=%s lease=%s sticky=%s",
		s.iface, laddr.String(), s.serverIP, s.cfg.SubnetCIDR, s.gatewayIP, s.leaseDur, s.stickyDur)
	if s.cfg.AutoReload {
		s.logf("START auto_reload=true (watching %s)", cfgPath)
	}

	// Signals: INT/TERM stop; HUP reload
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for {
		select {
		case sig := <-sigc:
			switch sig {
			case syscall.SIGHUP:
				cfg, jerr := parseConfigStrict(cfgPath)
				if jerr != nil {
					s.logf("RELOAD: config invalid, keeping old settings: %v", jerr)
					continue
				}

				// Stamp/persist first_seen (epoch) if missing on reservations and banned_macs
				nowEpoch := time.Now().Unix()
				changed := false

				for k, v := range cfg.Reservations {
					if v.FirstSeen == 0 {
						v.FirstSeen = nowEpoch
						cfg.Reservations[k] = v
						changed = true
					}
				}
				if cfg.BannedMACs == nil {
					cfg.BannedMACs = make(map[string]DeviceMeta)
				}
				for k, v := range cfg.BannedMACs {
					if v.FirstSeen == 0 {
						v.FirstSeen = nowEpoch
						cfg.BannedMACs[k] = v
						changed = true
					}
				}

				if changed {
					tmp := cfgPath + ".tmp"
					if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err == nil {
						if f, err := os.Create(tmp); err == nil {
							enc := json.NewEncoder(f)
							enc.SetIndent("", "  ")
							if err := enc.Encode(&cfg); err == nil {
								_ = f.Sync()
								_ = f.Close()
								_ = os.Rename(tmp, cfgPath)
							} else {
								_ = f.Close()
								_ = os.Remove(tmp)
								s.logf("RELOAD: failed to persist first_seen update: %v", err)
							}
						}
					}
				}

				// Apply and enforce
				s.applyNewConfig(cfg, leasePath)
				s.enforceReservationLeaseConsistency()

				// Optional compaction only when enabled
				if s.cfg.CompactOnLoad {
					if n := s.db.compactNow(s.stickyDur); n > 0 {
						s.logf("LEASE-COMPACT removed=%d (on config reload)", n)
					}
				}
				s.logf("RELOAD: config applied")

			case syscall.SIGINT, syscall.SIGTERM:
				s.logf("SIGNAL received, shutting down")
				_ = srv.Close()
				_ = s.db.Save()
				if watcher != nil {
					_ = watcher.Close()
				}
				if s.logFile != nil {
					_ = s.logFile.Sync()
					_ = s.logFile.Close()
				}
				return nil
			}

		case err := <-errc:
			s.logf("SERVER ERROR: %v", err)
			_ = s.db.Save()
			if watcher != nil {
				_ = watcher.Close()
			}
			if s.logFile != nil {
				_ = s.logFile.Sync()
				_ = s.logFile.Close()
			}
			return err
		}
	}
}

/* ----------------- Stats command helpers ----------------- */

type leaseView struct {
	IP          string
	MAC         string
	Hostname    string
	AllocatedAt int64 // epoch seconds
	Expiry      int64 // epoch seconds
}

func loadDBAndConfig(leasePath, cfgPath string) (*LeaseDB, Config, error) {
	db := NewLeaseDB(leasePath)
	if err := db.Load(); err != nil {
		return nil, Config{}, err
	}
	cfg, jerr := parseConfigStrict(cfgPath)
	if jerr != nil {
		return nil, Config{}, jerr
	}
	return db, cfg, nil
}

func classifyLeases(db *LeaseDB, assumeLeaseDur time.Duration) (curr, expiring, expired []leaseView) {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().Unix()
	thresholdExpiring := int64(assumeLeaseDur.Seconds() / 8)

	for _, l := range db.ByIP {
		alloc := deriveAllocEpoch(l, assumeLeaseDur, now)
		rem := l.Expiry - now
		v := leaseView{
			IP:          l.IP,
			MAC:         l.MAC,
			Hostname:    l.Hostname,
			AllocatedAt: alloc,
			Expiry:      l.Expiry,
		}
		if rem <= 0 {
			expired = append(expired, v)
			continue
		}
		if rem <= thresholdExpiring {
			expiring = append(expiring, v)
		} else {
			curr = append(curr, v)
		}
	}

	// Sort by time proximity
	sort.Slice(curr, func(i, j int) bool { return curr[i].Expiry < curr[j].Expiry })
	sort.Slice(expiring, func(i, j int) bool { return expiring[i].Expiry < expiring[j].Expiry })
	sort.Slice(expired, func(i, j int) bool { return expired[i].Expiry > expired[j].Expiry })
	return
}

func countAllocations(db *LeaseDB, assumeLeaseDur time.Duration) (perMinute, perHour, perDay, perWeek, perMonth int) {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now().Unix()
	w1 := now - 60
	w2 := now - 3600
	w3 := now - 24*3600
	w4 := now - 7*24*3600
	w5 := now - 30*24*3600

	for _, l := range db.ByIP {
		alloc := deriveAllocEpoch(l, assumeLeaseDur, now)
		if alloc > w1 {
			perMinute++
		}
		if alloc > w2 {
			perHour++
		}
		if alloc > w3 {
			perDay++
		}
		if alloc > w4 {
			perWeek++
		}
		if alloc > w5 {
			perMonth++
		}
	}
	return
}

func printLeaseTable(title string, rows []leaseView, assumeLeaseDur time.Duration) {
	if len(rows) == 0 {
		fmt.Printf("\n%s: (none)\n", title)
		return
	}
	fmt.Printf("\n%s:\n", title)
	fmt.Printf("%-16s  %-17s  %-19s  %-10s  %-10s  %s\n",
		"IP", "MAC", "AllocatedAt", "Elapsed", "Remaining", "Hostname")

	now := time.Now().Unix()
	for _, v := range rows {
		alloc := deriveAllocEpoch(Lease{AllocatedAt: v.AllocatedAt, Expiry: v.Expiry}, assumeLeaseDur, now)
		elapsedSecs := now - alloc
		if elapsedSecs < 0 {
			elapsedSecs = 0
		}
		remainingSecs := v.Expiry - now
		if remainingSecs < 0 {
			remainingSecs = 0
		}
		fmt.Printf("%-16s  %-17s  %-19s  %-10s  %-10s  %s\n",
			v.IP,
			v.MAC,
			formatEpoch(alloc),
			humanDurSecs(elapsedSecs),
			humanDurSecs(remainingSecs),
			v.Hostname,
		)
	}
}

/* ----------------- Grid rendering helpers ----------------- */

// drawSubnetGrid renders the entire IPv4 subnet (host range only) as a colour grid:
//
//	red       █ = leased (unexpired; from leases DB)
//	brown     █ = reserved/fixed (from config.reservations; only if not actively leased)
//	dark gray █ = banned/unusable IPs (exclusions, network/broadcast/server/gateway, declined)
//	light gray█ = banned MAC leases (active leases owned by banned MACs)
//	green     █ = free host IP inside the configured subnet
//
// Each row is prefixed with the last octet of the first IP in that row.
func drawSubnetGrid(db *LeaseDB, subnetCIDR string) error {
	// Aurora colours
	blkLeased := aurora.Red("█")
	blkReserved := aurora.Brown("█")
	blkBannedIP := aurora.Gray(8, "█")   // dark gray
	blkBannedMAC := aurora.Gray(14, "█") // light gray
	blkFree := aurora.Green("█")

	// Load config (exclusions/reservations/server/gateway/banned_macs)
	cfgPath := strings.TrimSpace(os.Getenv("dhcplane_CONFIG"))
	if cfgPath == "" {
		cfgPath = "config.json"
	}
	cfg, jerr := parseConfigStrict(cfgPath)
	if jerr != nil {
		return fmt.Errorf("load config: %v", jerr)
	}

	// Parse subnet
	_, ipnet := mustCIDR(subnetCIDR)
	network := ipnet.IP.Mask(ipnet.Mask).To4()
	if network == nil {
		return fmt.Errorf("subnet %s is not IPv4", subnetCIDR)
	}
	bcast := broadcastAddr(ipnet)
	first := incIP(network)
	last := u32ToIP(ipToU32(bcast) - 1)

	// Banned MACs: merge from config + env
	banned := make(map[string]struct{})
	for m := range cfg.BannedMACs {
		if nm, err := normalizeMACFlexible(m); err == nil {
			banned[nm] = struct{}{}
		}
	}
	if env := parseBannedMACsEnv(); len(env) > 0 {
		for nm := range env {
			banned[nm] = struct{}{}
		}
	}

	// Build activity maps (epoch-safe)
	now := time.Now()
	nowEpoch := now.Unix()

	active := make(map[string]bool)
	activeBanned := make(map[string]bool)
	declined := make(map[string]time.Time)

	db.mu.Lock()
	for ip, l := range db.ByIP {
		if nowEpoch <= l.Expiry {
			active[ip] = true
			if nm, err := normalizeMACFlexible(l.MAC); err == nil {
				if _, bad := banned[nm]; bad {
					activeBanned[ip] = true
				}
			}
		}
	}
	for ip, until := range db.decline {
		if now.Before(until) {
			declined[ip] = until
		}
	}
	db.mu.Unlock()

	// Exclusions
	excluded := make(map[string]struct{})
	for _, e := range cfg.Exclusions {
		if ip := net.ParseIP(strings.TrimSpace(e)).To4(); ip != nil {
			excluded[ip.String()] = struct{}{}
		}
	}

	// Reservations
	reservedIPs := make(map[string]struct{})
	for _, r := range cfg.Reservations {
		if ip := net.ParseIP(strings.TrimSpace(r.IP)).To4(); ip != nil {
			reservedIPs[ip.String()] = struct{}{}
		}
	}

	// Special addresses
	var serverIP, gatewayIP net.IP
	if cfg.ServerIP != "" {
		serverIP = net.ParseIP(cfg.ServerIP).To4()
	}
	if cfg.Gateway != "" {
		gatewayIP = net.ParseIP(cfg.Gateway).To4()
	}

	const cols = 25 // cells per row

	// Counters for legend
	var countLeased, countReserved, countBannedMAC, countBannedIP, countFree int

	fmt.Println()
	fmt.Printf("Subnet usage grid (%s):\n\n", subnetCIDR)

	printRowLabel := func(ip net.IP) {
		fmt.Printf("%3d ", int(ip.To4()[3]))
	}

	curU := ipToU32(first)
	endU := ipToU32(last)
	col := 0
	startOfRow := true

	for curU <= endU {
		ip := u32ToIP(curU).To4()
		if startOfRow {
			printRowLabel(ip)
			startOfRow = false
		}

		s := ip.String()
		_, isReserved := reservedIPs[s]
		_, isExcluded := excluded[s]
		_, isDeclined := declined[s]
		isActive := active[s]
		isActiveBanned := activeBanned[s]
		isSpecial := (serverIP != nil && ip.Equal(serverIP)) ||
			(gatewayIP != nil && ip.Equal(gatewayIP)) ||
			ip.Equal(network) || ip.Equal(bcast)

		// Priority: banned MAC leases → banned/excluded IPs → leased → reserved → free
		switch {
		case isActiveBanned:
			fmt.Print(blkBannedMAC, " ")
			countBannedMAC++
		case isSpecial || isExcluded || isDeclined:
			fmt.Print(blkBannedIP, " ")
			countBannedIP++
		case isActive:
			fmt.Print(blkLeased, " ")
			countLeased++
		case isReserved:
			fmt.Print(blkReserved, " ")
			countReserved++
		default:
			fmt.Print(blkFree, " ")
			countFree++
		}

		col++
		if col >= cols {
			fmt.Println()
			col = 0
			startOfRow = true
		}
		curU++
	}
	if col != 0 {
		fmt.Println()
	}

	// Legend with counts
	fmt.Println()
	fmt.Println(
		"Legend:",
		blkLeased, " = leased (", countLeased, ")  ",
		blkReserved, " = reserved/fixed (", countReserved, ")  ",
		blkBannedMAC, " = banned MAC leases (", countBannedMAC, ")  ",
		blkBannedIP, " = banned/excluded IPs (", countBannedIP, ")  ",
		blkFree, " = free (", countFree, ")",
	)
	fmt.Println()
	return nil
}

// parseBannedMACsEnv reads dhcplane_BANNED_MACS and returns a set of normalized MACs.
// Accepts separators: comma, space, newline. MACs can be "aa:bb:cc:dd:ee:ff", "aabbccddeeff", or "aa-bb-...".
func parseBannedMACsEnv() map[string]struct{} {
	raw := os.Getenv("dhcplane_BANNED_MACS")
	banned := make(map[string]struct{})
	if strings.TrimSpace(raw) == "" {
		return banned
	}
	split := func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r'
	}
	for _, tok := range strings.FieldsFunc(raw, split) {
		if tok == "" {
			continue
		}
		if nm, err := normalizeMACFlexible(tok); err == nil {
			banned[nm] = struct{}{}
		}
	}
	return banned
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
		showVersion   bool // <— ADD
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
	root.PersistentFlags().BoolVarP(&showVersion, "version", "v", false, "Print version and exit")
	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", "config.json", "Path to JSON config")
	root.PersistentFlags().StringVar(&leasePath, "lease-db", "leases.json", "Path to leases JSON DB")
	root.PersistentFlags().BoolVar(&authoritative, "authoritative", true, "Send NAKs on invalid requests")
	root.PersistentFlags().StringVar(&logPath, "log", "dhcplane.log", "Log file path (empty to log only to console)")
	root.PersistentFlags().BoolVar(&console, "console", false, "Also print logs to stdout in addition to --log")
	root.PersistentFlags().StringVar(&pidPath, "pid-file", "dhcplane.pid", "PID file for reload control")
	// NEW: global flag to disable console colours
	root.PersistentFlags().BoolVar(&nocolour, "nocolour", false, "Disable ANSI colours in console output")

	/* ---- serve ---- */
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the DHCP server",
		RunE: func(_ *cobra.Command, _ []string) error {
			// Validate config before start
			if _, jerr := parseConfigStrict(cfgPath); jerr != nil {
				return fmt.Errorf("config error: %w", jerr)
			}
			return buildServerAndRun(cfgPath, leasePath, authoritative, logPath, console, pidPath, nocolour)
		},
	}

	/* ---- leases ---- */
	showCmd := &cobra.Command{
		Use:   "leases",
		Short: "Print current leases",
		RunE: func(_ *cobra.Command, _ []string) error {
			db := NewLeaseDB(leasePath)
			if err := db.Load(); err != nil {
				return err
			}
			db.mu.Lock()
			defer db.mu.Unlock()

			ips := make([]string, 0, len(db.ByIP))
			for ip := range db.ByIP {
				ips = append(ips, ip)
			}
			sort.Slice(ips, func(i, j int) bool { return ips[i] < ips[j] })

			type row struct {
				IP          string `json:"ip"`
				MAC         string `json:"mac"`
				Hostname    string `json:"hostname"`
				AllocatedAt string `json:"allocated_at"` // formatted as "YYYY/MM/DD HH:MM:SS"
				Expiry      string `json:"expiry"`       // formatted as "YYYY/MM/DD HH:MM:SS"
				FirstSeen   string `json:"first_seen"`   // formatted as "YYYY/MM/DD HH:MM:SS"
			}
			var rows []row
			for _, ip := range ips {
				l := db.ByIP[ip]
				rows = append(rows, row{
					IP:          ip,
					MAC:         l.MAC,
					Hostname:    l.Hostname,
					AllocatedAt: formatEpoch(l.AllocatedAt),
					Expiry:      formatEpoch(l.Expiry),
					FirstSeen:   formatEpoch(l.FirstSeen),
				})
			}
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

			minute, hour, day, week, month := countAllocations(db, assume)
			curr, expiring, expired := classifyLeases(db, assume)

			fmt.Printf("Allocations: last 1m=%d  1h=%d  24h=%d  7d=%d  30d=%d\n",
				minute, hour, day, week, month)
			fmt.Printf("Leases: current=%d  expiring=%d  expired=%d\n",
				len(curr), len(expiring), len(expired))

			if details {
				// Unified table with "Type" for ALL IPs (leased/reserved/banned-mac/banned-ip/free).
				rows, err := buildDetailRows(db, cfg)
				if err != nil {
					return err
				}
				printDetailsTable("DETAILS (entire subnet)", rows, assume)
			} else {
				printLeaseTable("CURRENT", curr, assume)
				printLeaseTable("EXPIRING (<= last 1/8 of lease)", expiring, assume)
				printLeaseTable("EXPIRED", expired, assume)
			}

			if grid {
				if err := drawSubnetGrid(db, cfg.SubnetCIDR); err != nil {
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
			_, jerr := parseConfigStrict(cfgPath)
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
			_, jerr := parseConfigStrict(cfgPath)
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
			norm, err := normalizeMACFlexible(args[0])
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

			cfg, jerr := parseConfigStrict(cfgPath)
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
			db := NewLeaseDB(leasePath)
			_ = db.Load()
			if l, ok := db.findByIP(ip.String()); ok && !macEqual(l.MAC, norm) {
				warnf("IP %s currently leased to %s (hostname=%q) until %s",
					ip.String(), l.MAC, l.Hostname, formatEpoch(l.Expiry))
			}

			// Upsert reservation with first_seen epoch
			if cfg.Reservations == nil {
				cfg.Reservations = make(Reservations)
			}
			now := time.Now().Unix()
			prev, existed := cfg.Reservations[norm]
			if !existed {
				cfg.Reservations[norm] = Reservation{
					IP:        ip.String(),
					Note:      note,
					FirstSeen: now,
				}
				fmt.Printf("Added reservation: %s -> %s  note=%q  first_seen=%s\n",
					norm, ip.String(), note, formatEpoch(now))
			} else {
				// Keep prior first_seen if set; otherwise stamp now.
				fs := prev.FirstSeen
				if fs == 0 {
					fs = now
				}
				cfg.Reservations[norm] = Reservation{
					IP:                  ip.String(),
					Note:                note,
					FirstSeen:           fs,
					EquipmentType:       prev.EquipmentType,
					Manufacturer:        prev.Manufacturer,
					ManagementType:      prev.ManagementType,
					ManagementInterface: prev.ManagementInterface,
				}
				fmt.Printf("Updated reservation: %s  %s -> %s  note=%q (first_seen=%s)\n",
					norm, prev.IP, ip.String(), note, formatEpoch(fs))
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
			norm, err := normalizeMACFlexible(args[0])
			if err != nil {
				return errf("invalid mac: %v", err)
			}
			cfg, jerr := parseConfigStrict(cfgPath)
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

// buildDetailRows walks the whole host range and classifies every IP into the
// same types used by the grid: "leased", "reserved", "banned-mac", "banned-ip",
// or "free". It also fills MAC/Hostname/AllocatedAt/Expiry when available.
// (For "reserved", the MAC column is the reserved MAC from config, if any.)
func buildDetailRows(db *LeaseDB, cfg Config) ([]struct {
	IP          string
	Type        string
	MAC         string
	Hostname    string
	AllocatedAt int64
	Expiry      int64
}, error) {
	_, ipnet := mustCIDR(cfg.SubnetCIDR)
	network := ipnet.IP.Mask(ipnet.Mask).To4()
	if network == nil {
		return nil, fmt.Errorf("subnet %s is not IPv4", cfg.SubnetCIDR)
	}
	bcast := broadcastAddr(ipnet)
	first := incIP(network)
	last := u32ToIP(ipToU32(bcast) - 1)

	// Banned set from config (keep your preferred source)
	banned := make(map[string]struct{})
	for m := range cfg.BannedMACs {
		if nm, err := normalizeMACFlexible(m); err == nil {
			banned[nm] = struct{}{}
		}
	}

	now := time.Now().Unix()
	active := make(map[string]Lease)
	activeBanned := make(map[string]bool)
	declined := make(map[string]time.Time)

	db.mu.Lock()
	for ip, l := range db.ByIP {
		if now <= l.Expiry {
			active[ip] = l
			if nm, err := normalizeMACFlexible(l.MAC); err == nil {
				if _, bad := banned[nm]; bad {
					activeBanned[ip] = true
				}
			}
		}
	}
	for ip, until := range db.decline {
		if time.Now().Before(until) {
			declined[ip] = until
		}
	}
	db.mu.Unlock()

	excluded := make(map[string]struct{})
	for _, e := range cfg.Exclusions {
		if ip := net.ParseIP(strings.TrimSpace(e)).To4(); ip != nil {
			excluded[ip.String()] = struct{}{}
		}
	}

	reservedIPs := make(map[string]struct{})
	reservedIPToMAC := make(map[string]string)
	for macKey, r := range cfg.Reservations {
		if ip := net.ParseIP(strings.TrimSpace(r.IP)).To4(); ip != nil {
			reservedIPs[ip.String()] = struct{}{}
			if nm, err := normalizeMACFlexible(macKey); err == nil {
				reservedIPToMAC[ip.String()] = nm
			}
		}
	}

	var serverIP, gatewayIP net.IP
	if cfg.ServerIP != "" {
		serverIP = net.ParseIP(cfg.ServerIP).To4()
	}
	if cfg.Gateway != "" {
		gatewayIP = net.ParseIP(cfg.Gateway).To4()
	}

	rows := make([]struct {
		IP          string
		Type        string
		MAC         string
		Hostname    string
		AllocatedAt int64
		Expiry      int64
	}, 0, ipToU32(last)-ipToU32(first)+1)

	for u := ipToU32(first); u <= ipToU32(last); u++ {
		ip := u32ToIP(u).To4()
		s := ip.String()
		_, isExcluded := excluded[s]
		_, isReserved := reservedIPs[s]
		resMAC := reservedIPToMAC[s]
		_, isDecl := declined[s]
		isSpecial := (serverIP != nil && ip.Equal(serverIP)) ||
			(gatewayIP != nil && ip.Equal(gatewayIP)) ||
			ip.Equal(network) || ip.Equal(bcast)

		if l, ok := active[s]; ok {
			if activeBanned[s] {
				rows = append(rows, struct {
					IP, Type, MAC, Hostname string
					AllocatedAt, Expiry     int64
				}{IP: s, Type: "banned-mac", MAC: l.MAC, Hostname: l.Hostname, AllocatedAt: l.AllocatedAt, Expiry: l.Expiry})
				continue
			}
			rows = append(rows, struct {
				IP, Type, MAC, Hostname string
				AllocatedAt, Expiry     int64
			}{IP: s, Type: "leased", MAC: l.MAC, Hostname: l.Hostname, AllocatedAt: l.AllocatedAt, Expiry: l.Expiry})
			continue
		}

		switch {
		case isSpecial || isExcluded || isDecl:
			rows = append(rows, struct {
				IP, Type, MAC, Hostname string
				AllocatedAt, Expiry     int64
			}{IP: s, Type: "banned-ip"})
		case isReserved:
			rows = append(rows, struct {
				IP, Type, MAC, Hostname string
				AllocatedAt, Expiry     int64
			}{IP: s, Type: "reserved", MAC: resMAC})
		default:
			rows = append(rows, struct {
				IP, Type, MAC, Hostname string
				AllocatedAt, Expiry     int64
			}{IP: s, Type: "free"})
		}
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].IP < rows[j].IP })
	return rows, nil
}

// printDetailsTable prints a single tabular view including Type.
// It hides "free" rows; for non-leased rows, timing columns are left blank.
func printDetailsTable(title string, rows []struct {
	IP          string
	Type        string
	MAC         string
	Hostname    string
	AllocatedAt int64
	Expiry      int64
}, assumeLeaseDur time.Duration) {
	// Filter out "free"
	filtered := make([]struct {
		IP          string
		Type        string
		MAC         string
		Hostname    string
		AllocatedAt int64
		Expiry      int64
	}, 0, len(rows))
	for _, r := range rows {
		if r.Type == "free" {
			continue
		}
		filtered = append(filtered, r)
	}

	if len(filtered) == 0 {
		fmt.Printf("\n%s: (none)\n", title)
		return
	}

	fmt.Printf("\n%s:\n", title)
	fmt.Printf("%-16s  %-12s  %-17s  %-19s  %-10s  %-10s  %s\n",
		"IP", "Type", "MAC", "AllocatedAt", "Elapsed", "Remaining", "Hostname")

	now := time.Now().Unix()
	for _, r := range filtered {
		var alloc, elapsed, remaining int64
		var allocStr, elapsedStr, remainStr string

		if r.AllocatedAt > 0 || r.Expiry > 0 {
			alloc = deriveAllocEpoch(Lease{AllocatedAt: r.AllocatedAt, Expiry: r.Expiry}, assumeLeaseDur, now)
			elapsed = now - alloc
			if elapsed < 0 {
				elapsed = 0
			}
			remaining = r.Expiry - now
			if remaining < 0 {
				remaining = 0
			}
			allocStr = formatEpoch(alloc)
			elapsedStr = humanDurSecs(elapsed)
			remainStr = humanDurSecs(remaining)
		}

		fmt.Printf("%-16s  %-12s  %-17s  %-19s  %-10s  %-10s  %s\n",
			r.IP, r.Type, r.MAC, allocStr, elapsedStr, remainStr, r.Hostname)
	}
}

func stringInSlice(s string, list []string) bool {
	for _, v := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

func formatEpoch(ts int64) string {
	if ts <= 0 {
		return ""
	}
	t := time.Unix(ts, 0).Local()
	return t.Format("2006/01/02 15:04:05")
}

func deriveAllocEpoch(l Lease, assumeLeaseDur time.Duration, now int64) int64 {
	alloc := l.AllocatedAt
	if alloc <= 0 || alloc > now {
		if l.Expiry > 0 {
			alloc = l.Expiry - int64(assumeLeaseDur.Seconds())
			if alloc > now {
				alloc = now
			}
		} else {
			alloc = now
		}
	}
	return alloc
}

func humanDurSecs(secs int64) string {
	neg := secs < 0
	if neg {
		secs = -secs
	}
	h := secs / 3600
	m := (secs % 3600) / 60
	s := secs % 60
	if neg {
		if h > 0 {
			return fmt.Sprintf("-%dh%dm%ds", h, m, s)
		}
		if m > 0 {
			return fmt.Sprintf("-%dm%ds", m, s)
		}
		return fmt.Sprintf("-%ds", s)
	}
	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// CanonMAC returns a canonical, lower-case "aa:bb:cc:dd:ee:ff".
func CanonMAC(s string) (string, error) {
	return normalizeMACFlexible(s)
}

// MustCanonMAC panics if s cannot be normalized.
func MustCanonMAC(s string) string {
	n, err := CanonMAC(s)
	if err != nil {
		panic(err)
	}
	return n
}

// macEqual normalizes both sides (accepts "aa:..", "aa-..", or "aabb..") and compares.
func macEqual(a, b string) bool {
	na, ea := CanonMAC(a)
	nb, eb := CanonMAC(b)
	if ea == nil && eb == nil {
		return na == nb
	}
	// Fallback: case-insensitive direct compare if one side failed normalization.
	return strings.EqualFold(a, b)
}
