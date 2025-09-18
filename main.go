package main

import (
	"dhcplane/config"
	"dhcplane/consoleui"
	"dhcplane/statistics"
	"encoding/binary"
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
	"sync/atomic"
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

var appVersion = "0.1.35"
var transparent bool

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

// buildConsoleUI wires the generic console with our DHCP-specific counters and highlights.
func buildConsoleUI(nocolour bool, maxLines int) *consoleui.UI {
	ui := consoleui.New(consoleui.Options{
		NoColour:     nocolour,
		MaxLines:     maxLines,
		MouseEnabled: true,
		OnExit:       nil, // default immediate exit
	})
	ui.SetTitle(fmt.Sprintf("DHCPlane Console v%s", appVersion))

	// Counters (data-driven; unlimited)
	ui.RegisterCounter("REQUEST", false, "RPM", 60)
	ui.RegisterCounter("ACK", false, "APM", 60)
	// Add more at will:
	// ui.RegisterCounter("DISCOVER", false, "DISC", 60)
	// ui.RegisterCounter("NAK",      false, "NAK",  60)

	// Highlights (case-sensitive where helpful)
	ui.HighlightMap("BANNED-MAC", true, consoleui.Style{FG: "red", Attrs: "b"})
	ui.HighlightMap("NAK", true, consoleui.Style{FG: "red", Attrs: "b"})
	ui.HighlightMap("ACK", true, consoleui.Style{FG: "green", Attrs: "b"})
	ui.HighlightMap("OFFER", true, consoleui.Style{FG: "green", Attrs: "b"})
	ui.HighlightMap("REQUEST", true, consoleui.Style{FG: "yellow", Attrs: "b"})
	ui.HighlightMap("DISCOVER", true, consoleui.Style{FG: "yellow", Attrs: "b"})
	ui.HighlightMap("RELEASE", true, consoleui.Style{FG: "yellow", Attrs: "b"})
	ui.HighlightMap("DECLINE", true, consoleui.Style{FG: "yellow", Attrs: "b"})

	// Example with background (optional):
	// ui.HighlightMap("MAINT", false, consoleui.Style{BG: "#1e293b", Attrs: ""})

	return ui
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

func (s *Server) logf(format string, args ...any) {
	if s.logSink != nil {
		s.logSink(format, args...)
	}
}

// errorf logs to file and (if console enabled) prints red-tagged highlights to stderr too.
func (s *Server) errorf(format string, args ...any) {
	if s.errorSink != nil {
		s.errorSink(format, args...)
	} else if s.logSink != nil {
		s.logSink("ERROR: "+format, args...)
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

// Server represents a DHCP server instance, decoupled from Config/Console.
// It never stores Config/Console values. When it needs them, it calls cfgGet().
type Server struct {
	mu sync.RWMutex

	// DHCP-runtime state (belongs to DHCP domain)
	db *LeaseDB

	// Providers/sinks (no structs from other domains stored here)
	cfgGet    func() *config.Config // returns the current Config (atomic/RW-safe outside)
	authorGet func() bool           // returns current authoritative flag
	logSink   func(string, ...any)  // info/debug sink
	errorSink func(string, ...any)  // error sink
	now       func() time.Time      // time source (for tests; defaults to time.Now)
}

// enforceReservationLeaseConsistency ensures reservations win over leases.
// Pure function over cfg+db; not tied to Server internals.
func enforceReservationLeaseConsistency(db *LeaseDB, cfg *config.Config) {
	db.mu.Lock()
	changed := false
	for mac, r := range cfg.Reservations {
		norm := strings.ToLower(mac)
		if l, ok := db.ByIP[r.IP]; ok && !macEqual(l.MAC, norm) {
			delete(db.ByMAC, strings.ToLower(l.MAC))
			delete(db.ByIP, r.IP)
			changed = true
		}
		if l, ok := db.ByMAC[norm]; ok && l.IP != r.IP {
			delete(db.ByIP, l.IP)
			delete(db.ByMAC, norm)
			changed = true
		}
	}
	if changed {
		db.dirty = true
	}
	db.mu.Unlock()
	if changed {
		_ = db.Save()
	}
}

/* --------------- DHCP handler --------------- */

// Handler handles incoming DHCP requests.
// All configuration used here is pulled via s.cfgGet() at the start of the call.
func (s *Server) Handler(conn net.PacketConn, peer net.Addr, req *dhcpv4.DHCPv4) {
	cfg := s.cfgGet()
	if cfg == nil {
		s.errorf("no config available")
		return
	}
	authoritative := s.authorGet()

	_, subnet := mustCIDR(cfg.SubnetCIDR)
	serverIP := parseIP4(cfg.ServerIP)

	mt := req.MessageType()
	dispMAC := macDisplay(req.ClientHWAddr)

	var mac string
	if nm, err := normalizeMACFlexible(dispMAC); err == nil {
		mac = nm
	} else {
		mac = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(dispMAC), "-", ":"), " ", ""))
	}

	hostname := strings.TrimRight(string(req.Options.Get(dhcpv4.OptionHostName)), "\x00")

	// build banned set from env + cfg
	banned := parseBannedMACsEnv()
	for m := range cfg.BannedMACs {
		if nm, err := normalizeMACFlexible(m); err == nil {
			banned[nm] = struct{}{}
		}
	}
	if _, isBanned := banned[mac]; isBanned {
		s.logf("BANNED-MAC %s (%q) sent %s xid=%s — denying", dispMAC, hostname, mt.String(), xidString(req))
		if mt == dhcpv4.MessageTypeRequest && authoritative {
			nak, _ := dhcpv4.NewReplyFromRequest(req)
			nak.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
			nak.UpdateOption(dhcpv4.OptServerIdentifier(serverIP))
			_, _ = conn.WriteTo(nak.ToBytes(), peer)
		}
		return
	}

	switch mt {
	case dhcpv4.MessageTypeDiscover:
		s.logf("DISCOVER from %s hostname=%q xid=%s", dispMAC, hostname, xidString(req))
		ip, ok := s.chooseIPForMAC(cfg, mac)
		if !ok {
			s.errorf("POOL EXHAUSTED for %s: no address available in configured pools", dispMAC)
			if authoritative {
				nak, _ := dhcpv4.NewReplyFromRequest(req)
				nak.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
				nak.UpdateOption(dhcpv4.OptServerIdentifier(serverIP))
				_, _ = conn.WriteTo(nak.ToBytes(), peer)
			}
			return
		}
		offer, err := s.buildReply(cfg, req, dhcpv4.MessageTypeOffer, ip, mac)
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
			ip, ok := s.chooseIPForMAC(cfg, mac)
			if !ok {
				s.errorf("POOL EXHAUSTED for %s: no address available in configured pools", dispMAC)
				if authoritative {
					nak, _ := dhcpv4.NewReplyFromRequest(req)
					nak.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
					nak.UpdateOption(dhcpv4.OptServerIdentifier(serverIP))
					_, _ = conn.WriteTo(nak.ToBytes(), peer)
				}
				return
			}
			reqIP = ip
		}
		if !ipInSubnet(reqIP, subnet) || s.isExcluded(cfg, reqIP) || s.db.isDeclined(reqIP.String()) {
			s.logf("REQUEST invalid ip=%s for %s (excluded/declined/out-of-subnet)", reqIP, dispMAC)
			if authoritative {
				nak, _ := dhcpv4.NewReplyFromRequest(req)
				nak.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
				nak.UpdateOption(dhcpv4.OptServerIdentifier(serverIP))
				_, _ = conn.WriteTo(nak.ToBytes(), peer)
			}
			return
		}
		if rmac := s.macForReservedIP(cfg, reqIP); rmac != "" && !macEqual(rmac, mac) {
			s.logf("REQUEST %s asked for reserved ip=%s owned by %s -> NAK", dispMAC, reqIP, rmac)
			if authoritative {
				nak, _ := dhcpv4.NewReplyFromRequest(req)
				nak.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
				nak.UpdateOption(dhcpv4.OptServerIdentifier(serverIP))
				_, _ = conn.WriteTo(nak.ToBytes(), peer)
			}
			return
		}
		if l, ok := s.db.findByIP(reqIP.String()); ok {
			now := s.now().Unix()
			if now <= l.Expiry && !macEqual(l.MAC, mac) {
				s.logf("REQUEST ip=%s already leased to %s until %s -> NAK", reqIP, l.MAC, formatEpoch(l.Expiry))
				if authoritative {
					nak, _ := dhcpv4.NewReplyFromRequest(req)
					nak.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
					nak.UpdateOption(dhcpv4.OptServerIdentifier(serverIP))
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
			firstSeen = s.now().Unix()
			s.logf("first_seen: %s here on %s", mac, formatEpoch(firstSeen))
		}

		now := s.now().Unix()
		ack, err := s.buildReply(cfg, req, dhcpv4.MessageTypeAck, reqIP, mac)
		if err != nil {
			s.logf("ack build error for %s ip=%s: %v", dispMAC, reqIP, err)
			return
		}
		lease := Lease{
			MAC:         mac,
			IP:          reqIP.String(),
			Hostname:    hostname,
			AllocatedAt: now,
			Expiry:      now + int64(cfg.LeaseSeconds),
			FirstSeen:   firstSeen,
		}
		s.db.set(lease)
		_ = s.db.Save()
		s.logf("ACK %s <- %s lease=%s (alloc=%s, exp=%s)",
			dispMAC, reqIP.String(),
			time.Duration(cfg.LeaseSeconds)*time.Second,
			formatEpoch(lease.AllocatedAt), formatEpoch(lease.Expiry))
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

func (s *Server) isExcluded(cfg *config.Config, ip net.IP) bool {
	for _, e := range cfg.Exclusions {
		if ip.Equal(parseIP4(e)) {
			return true
		}
	}
	return false
}

func (s *Server) macForReservedIP(cfg *config.Config, ip net.IP) string {
	for m, r := range cfg.Reservations {
		if r.IP == ip.String() {
			if nm, err := normalizeMACFlexible(m); err == nil {
				return nm
			}
			return m
		}
	}
	return ""
}

// chooseIPForMAC implements the policy:
//
//  1. If there is a reservation for this MAC -> return it.
//  2. If this MAC had any previous lease -> try that same IP again (even if long expired),
//     provided it isn't excluded/declined/reserved for someone else/actively leased by another MAC.
//  3. Scan pools for a **brand-new** IP (never seen in the leases DB).
//  4. If none available, recycle an **expired** previously-used IP that is safe to reuse.
//  5. If still none, return false (pool exhausted).
func (s *Server) chooseIPForMAC(cfg *config.Config, mac string) (net.IP, bool) {
	_, subnet := mustCIDR(cfg.SubnetCIDR)
	serverIP := parseIP4(cfg.ServerIP)
	gatewayIP := parseIP4(cfg.Gateway)

	isBad := func(ip net.IP) bool {
		if !ipInSubnet(ip, subnet) || s.isExcluded(cfg, ip) || s.db.isDeclined(ip.String()) {
			return true
		}
		if ip.Equal(serverIP) || ip.Equal(gatewayIP) {
			return true
		}
		network := subnet.IP.Mask(subnet.Mask)
		bcast := broadcastAddr(subnet)
		if ip.Equal(network) || ip.Equal(bcast) {
			return true
		}
		if rmac := s.macForReservedIP(cfg, ip); rmac != "" && !macEqual(rmac, mac) {
			return true
		}
		return false
	}

	// 1) Reservation first
	if rv, ok := cfg.Reservations[mac]; ok {
		ip := parseIP4(rv.IP)
		if ip == nil || isBad(ip) {
			return nil, false
		}
		if l, ok := s.db.findByIP(ip.String()); ok {
			now := s.now().Unix()
			if now <= l.Expiry && !macEqual(l.MAC, mac) {
				return nil, false
			}
		}
		return ip, true
	}

	now := s.now().Unix()

	// 2) Prefer same IP we gave this MAC before (if safe).
	if l, ok := s.db.findByMAC(mac); ok {
		ip := net.ParseIP(l.IP).To4()
		if ip != nil && !isBad(ip) {
			if cur, ok := s.db.findByIP(ip.String()); !ok ||
				macEqual(cur.MAC, mac) || now > cur.Expiry {
				return ip, true
			}
		}
	}

	// 3) Brand-new IPs (never in DB)
	for _, p := range cfg.Pools {
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
	for _, p := range cfg.Pools {
		start := parseIP4(p.Start)
		end := parseIP4(p.End)
		for ip := start; ipToU32(ip) <= ipToU32(end); ip = incIP(ip) {
			if isBad(ip) {
				continue
			}
			if l, ok := s.db.findByIP(ip.String()); ok {
				rmac := s.macForReservedIP(cfg, ip)
				if now > l.Expiry && (macEqual(l.MAC, mac) || rmac == "" || macEqual(rmac, mac)) {
					return ip, true
				}
			}
		}
	}

	return nil, false
}

func (s *Server) buildReply(cfg *config.Config, req *dhcpv4.DHCPv4, typ dhcpv4.MessageType, yiaddr net.IP, mac string) (*dhcpv4.DHCPv4, error) {
	resp, err := dhcpv4.NewReplyFromRequest(req)
	if err != nil {
		return nil, err
	}
	_, subnet := mustCIDR(cfg.SubnetCIDR)
	serverIP := parseIP4(cfg.ServerIP)
	gatewayIP := parseIP4(cfg.Gateway)

	resp.UpdateOption(dhcpv4.OptMessageType(typ))
	resp.YourIPAddr = yiaddr.To4()

	leaseDur := time.Duration(cfg.LeaseSeconds) * time.Second

	// Core identifiers and timers
	resp.UpdateOption(dhcpv4.OptServerIdentifier(serverIP))
	resp.UpdateOption(dhcpv4.OptSubnetMask(net.IPMask(subnet.Mask)))
	resp.UpdateOption(dhcpv4.OptRouter(gatewayIP))
	resp.UpdateOption(dhcpv4.OptIPAddressLeaseTime(leaseDur))
	resp.UpdateOption(dhcpv4.OptRenewTimeValue(leaseDur / 2))
	resp.UpdateOption(dhcpv4.OptRebindingTimeValue(leaseDur * 7 / 8))

	// DNS + Domain
	if len(cfg.DNS) > 0 {
		resp.UpdateOption(dhcpv4.OptDNS(toIPs(cfg.DNS)...))
	}
	if cfg.Domain != "" {
		resp.UpdateOption(dhcpv4.OptDomainName(cfg.Domain))
	}

	// Extras
	if len(cfg.NTP) > 0 {
		resp.UpdateOption(dhcpv4.OptNTPServers(toIPs(cfg.NTP)...))
	}
	if cfg.MTU > 0 {
		mtu := make([]byte, 2)
		binary.BigEndian.PutUint16(mtu, uint16(cfg.MTU))
		resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(26), mtu)) // Interface MTU
	}
	if cfg.TFTPServerName != "" {
		resp.UpdateOption(dhcpv4.OptTFTPServerName(cfg.TFTPServerName))
	}
	if cfg.BootFileName != "" {
		resp.BootFileName = cfg.BootFileName
		resp.UpdateOption(dhcpv4.OptBootFileName(cfg.BootFileName))
	}
	if cfg.WPADURL != "" {
		resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(252), []byte(cfg.WPADURL)))
	}
	if len(cfg.WINS) > 0 {
		resp.UpdateOption(dhcpv4.OptNetBIOSNameServers(toIPs(cfg.WINS)...))
	}
	if len(cfg.DomainSearch) > 0 {
		lbls := &rfc1035label.Labels{Labels: append([]string(nil), cfg.DomainSearch...)}
		resp.UpdateOption(dhcpv4.OptDomainSearch(lbls))
	}
	if len(cfg.StaticRoutes) > 0 {
		var rs []*dhcpv4.Route
		for _, r := range cfg.StaticRoutes {
			_, ipnet, err := net.ParseCIDR(strings.TrimSpace(r.CIDR))
			if err != nil {
				return nil, fmt.Errorf("bad CIDR %q: %w", r.CIDR, err)
			}
			gw := parseIP4(r.Gateway)
			rs = append(rs, &dhcpv4.Route{Dest: ipnet, Router: gw})
		}
		resp.UpdateOption(dhcpv4.OptClasslessStaticRoute(rs...)) // 121
		if cfg.MirrorRoutesTo249 {
			b := dhcpv4.Routes(rs).ToBytes()
			resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(249), b))
		}
	}
	if cfg.VendorSpecific43Hex != "" {
		if v43, err := config.ParseHexPayload(cfg.VendorSpecific43Hex); err == nil && len(v43) > 0 {
			resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionVendorSpecificInformation, v43))
		}
	}

	// Per-device overrides: ONLY DNS/TFTP/Bootfile
	if ov, has := cfg.DeviceOverrides[mac]; has {
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

// newServer wires a decoupled Server.
func newServer(
	db *LeaseDB,
	cfgGet func() *config.Config,
	authorGet func() bool,
	logSink func(string, ...any),
	errorSink func(string, ...any),
) *Server {
	if cfgGet == nil {
		cfgGet = func() *config.Config { return nil }
	}
	if authorGet == nil {
		authorGet = func() bool { return true }
	}
	return &Server{
		db:        db,
		cfgGet:    cfgGet,
		authorGet: authorGet,
		logSink:   logSink,
		errorSink: errorSink,
		now:       time.Now,
	}
}

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
	db := NewLeaseDB(leasePath)
	if err := db.Load(); err != nil {
		log.Printf("lease db load: %v (continuing with empty)", err)
	}

	// Logger (file only)
	lg, f, err := setupLogger(logPath)
	if err != nil {
		return fmt.Errorf("logger: %w", err)
	}
	defer func() {
		if f != nil {
			_ = f.Sync()
			_ = f.Close()
		}
	}()

	// Optional console UI (generic)
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

	// Sinks (no colour pushed here; UI applies highlight rules)
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

	// Log any initial warnings
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
		if n := db.compactNow(sticky); n > 0 {
			logSink("LEASE-COMPACT removed=%d (on initial load)", n)
		}
	}

	// Enforce reservations immediately
	enforceReservationLeaseConsistency(db, &cfg)

	// PID
	if err := writePID(pidPath); err != nil {
		return fmt.Errorf("write pid: %w", err)
	}

	// Decoupled server
	s := newServer(db, cfgGet, authorGet, logSink, errorSink)

	// Bind + Serve, with rebind support when Interface changes
	laddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 67}
	var srv *server4.Server
	var currentIface = cfg.Interface
	bind := func(newIface string) error {
		if srv != nil {
			_ = srv.Close()
			srv = nil
		}
		nsrv, err := server4.NewServer(newIface, laddr, s.Handler)
		if err != nil {
			return err
		}
		srv = nsrv
		go func() {
			if err := srv.Serve(); err != nil {
				logSink("SERVER ERROR: %v", err)
			}
		}()
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
			enforceReservationLeaseConsistency(db, &newCfg)
			if newCfg.CompactOnLoad {
				if n := db.compactNow(time.Duration(newCfg.LeaseStickySeconds) * time.Second); n > 0 {
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
			enforceReservationLeaseConsistency(db, &newCfg)
			if newCfg.CompactOnLoad {
				if n := db.compactNow(time.Duration(newCfg.LeaseStickySeconds) * time.Second); n > 0 {
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
			if srv != nil {
				_ = srv.Close()
			}
			_ = db.Save()
			if watcher != nil {
				_ = watcher.Close()
			}
			return nil
		}
	}
	return nil
}

// startConfigWatcher watches cfgPath and calls onApply(validatedCfg) after successful parses.
// It also performs the first_seen stamping persist just like your prior watcher.
func startConfigWatcher(
	cfgPath string,
	onApply func(config.Config, []string), // now also passes warnings
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

				// Parse
				cfg, jerr := config.ParseStrict(cfgPath)
				if jerr != nil {
					logf("AUTO-RELOAD: config invalid, keeping old settings: %v", jerr)
					continue
				}

				// Stamp/persist first_seen (unchanged behavior)
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
					cfg.BannedMACs = make(map[string]config.DeviceMeta)
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
								logf("AUTO-RELOAD: failed to persist first_seen: %v", err)
							}
						}
					}
				}

				// Validate + normalize (restores lost behavior)
				norm, warns, verr := config.ValidateAndNormalizeConfig(cfg)
				if verr != nil {
					logf("AUTO-RELOAD: validation failed, keeping old settings: %v", verr)
					continue
				}

				// Apply
				onApply(norm, warns)

			case err := <-w.Errors:
				logf("watcher error: %v", err)
			}
		}
	}()
	return w, nil
}

/* ----------------- Stats command helpers ----------------- */

func loadDBAndConfig(leasePath, cfgPath string) (*LeaseDB, config.Config, error) {
	db := NewLeaseDB(leasePath)
	if err := db.Load(); err != nil {
		return nil, config.Config{}, err
	}
	cfg, jerr := config.ParseStrict(cfgPath)
	if jerr != nil {
		return nil, config.Config{}, jerr
	}
	return db, cfg, nil
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
	root.PersistentFlags().BoolVar(&nocolour, "nocolour", false, "Disable ANSI colours in console output")
	root.PersistentFlags().BoolVar(&transparent, "transparent", false, "Use terminal background (no solid fill)")

	/* ---- serve ---- */
	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the DHCP server",
		RunE: func(_ *cobra.Command, _ []string) error {
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
			now := time.Now()

			// Build banned MAC set (merge config + env), using your existing CanonMAC and parseBannedMACsEnv.
			bannedSet := make(map[string]struct{})
			for m := range cfg.BannedMACs {
				if nm, err := CanonMAC(m); err == nil {
					bannedSet[nm] = struct{}{}
				} else {
					nm = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(m), "-", ":"), " ", ""))
					bannedSet[nm] = struct{}{}
				}
			}
			for nm := range parseBannedMACsEnv() {
				bannedSet[nm] = struct{}{}
			}
			isBanned := func(mac string) bool {
				if nm, err := CanonMAC(mac); err == nil {
					_, ok := bannedSet[nm]
					return ok
				}
				nm := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(mac), "-", ":"), " ", ""))
				_, ok := bannedSet[nm]
				return ok
			}

			// Live iteration over leases without copying; holds the DB lock while walking.
			iter := func(yield func(statistics.LeaseLite)) {
				db.mu.Lock()
				defer db.mu.Unlock()
				for _, l := range db.ByIP {
					yield(statistics.LeaseLite{
						IP:          l.IP,
						MAC:         l.MAC,
						Hostname:    l.Hostname,
						AllocatedAt: l.AllocatedAt,
						Expiry:      l.Expiry,
					})
				}
			}
			isDeclined := func(ip string) bool { return db.isDeclined(ip) }

			// Counters and classifications (we still classify to get the counts).
			perMinute, perHour, perDay, perWeek, perMonth := statistics.CountAllocations(iter, assume, now)
			curr, expiring, expired := statistics.ClassifyLeases(iter, assume, now)

			fmt.Printf("Allocations: last 1m=%d  1h=%d  24h=%d  7d=%d  30d=%d\n",
				perMinute, perHour, perDay, perWeek, perMonth)
			fmt.Printf("Leases: current=%d  expiring=%d  expired=%d\n",
				len(curr), len(expiring), len(expired))

			// Only print detailed rows when --details is set.
			if details {
				rows, err := statistics.BuildDetailRows(cfg, iter, isDeclined, isBanned, now)
				if err != nil {
					return err
				}
				statistics.PrintDetailsTable("DETAILS (entire subnet)", rows, assume, now)
			}

			// Render grid if requested (does not print per-IP tables).
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
			db := NewLeaseDB(leasePath)
			_ = db.Load()
			if l, ok := db.findByIP(ip.String()); ok && !macEqual(l.MAC, norm) {
				warnf("IP %s currently leased to %s (hostname=%q) until %s",
					ip.String(), l.MAC, l.Hostname, formatEpoch(l.Expiry))
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
					norm, ip.String(), note, formatEpoch(now))
			} else {
				// Keep prior first_seen if set; otherwise stamp now.
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

func formatEpoch(ts int64) string {
	if ts <= 0 {
		return ""
	}
	t := time.Unix(ts, 0).Local()
	return t.Format("2006/01/02 15:04:05")
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
	out := make([]string, 0, len(list))
	ips := make([]net.IP, 0, len(list))
	for _, s := range list {
		ip := net.ParseIP(strings.TrimSpace(s)).To4()
		if ip != nil {
			ips = append(ips, ip)
			out = append(out, ip.String())
		}
	}
	_ = out // kept for clarity; only ips is returned
	return ips
}

func ipToU32(ip net.IP) uint32 { return binary.BigEndian.Uint32(ip.To4()) }

func u32ToIP(v uint32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return net.IP(b)
}

func incIP(ip net.IP) net.IP { return u32ToIP(ipToU32(ip) + 1) }

func ipInSubnet(ip net.IP, n *net.IPNet) bool { return n.Contains(ip) }

func broadcastAddr(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	mask := net.IP(n.Mask).To4()
	var b [4]byte
	for i := 0; i < 4; i++ {
		b[i] = ip[i] | ^mask[i]
	}
	return net.IP(b[:])
}
