// Package dhcpserver implements a DHCPv4 server with lease management.
package dhcpserver

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"dhcplane/config"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/insomniacslk/dhcp/rfc1035label"
)

/* ----------------- Public types ----------------- */

// Lease represents a DHCP lease.
// JSON field names and semantics are unchanged.
// Times are epoch seconds.
type Lease struct {
	MAC         string `json:"mac"`
	IP          string `json:"ip"`
	Hostname    string `json:"hostname,omitempty"`
	AllocatedAt int64  `json:"allocated_at,omitempty"`
	Expiry      int64  `json:"expiry"`
	FirstSeen   int64  `json:"first_seen,omitempty"`
}

// LeaseDB stores leases indexed by IP and MAC with a lightweight decline cache.
// Concurrency: internal mutex protects maps; exported methods are safe for concurrent use.
type LeaseDB struct {
	mu      sync.Mutex
	ByIP    map[string]Lease `json:"by_ip"`
	ByMAC   map[string]Lease `json:"by_mac"`
	Path    string           `json:"-"`
	dirty   bool             `json:"-"`
	decline map[string]time.Time
}

// NewLeaseDB creates an empty DB bound to a file path.
func NewLeaseDB(path string) *LeaseDB {
	return &LeaseDB{
		ByIP:    make(map[string]Lease),
		ByMAC:   make(map[string]Lease),
		Path:    path,
		decline: make(map[string]time.Time),
	}
}

// Load reads the DB from disk. Tolerates old time formats by coercing to epoch seconds.
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

	// First try the canonical struct shape.
	type fileShape struct {
		ByIP  map[string]Lease `json:"ByIP"`
		ByMAC map[string]Lease `json:"ByMAC"`
	}
	var tmp fileShape
	dec := json.NewDecoder(f)
	if err := dec.Decode(&tmp); err == nil {
		if tmp.ByIP != nil {
			db.ByIP = tmp.ByIP
		}
		if tmp.ByMAC != nil {
			db.ByMAC = tmp.ByMAC
		}
		return nil
	}
	// Fallback: tolerant load from older layouts with RFC3339 strings.
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
		if a, ok := m["allocated_at"].(string); ok && a != "" {
			if t, err := time.Parse(time.RFC3339, a); err == nil {
				lease.AllocatedAt = t.Unix()
			}
		} else if f64, ok := m["allocated_at"].(float64); ok {
			lease.AllocatedAt = int64(f64)
		}
		if e, ok := m["expiry"].(string); ok && e != "" {
			if t, err := time.Parse(time.RFC3339, e); err == nil {
				lease.Expiry = t.Unix()
			}
		} else if f64, ok := m["expiry"].(float64); ok {
			lease.Expiry = int64(f64)
		}
		if fs, ok := m["first_seen"].(float64); ok {
			lease.FirstSeen = int64(fs)
		}
		return lease, true
	}
	byIP := map[string]Lease{}
	byMAC := map[string]Lease{}
	if bip, ok := raw["ByIP"].(map[string]any); ok {
		for ip, v := range bip {
			if lease, ok := coerce(v); ok {
				byIP[ip] = lease
			}
		}
	}
	if bmac, ok := raw["ByMAC"].(map[string]any); ok {
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

// Save writes the DB to disk atomically. No format change.
func (db *LeaseDB) Save() error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if !db.dirty {
		return nil
	}
	tmpPath := db.Path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(db.Path), 0o755); err != nil && !os.IsExist(err) {
		return err
	}
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(struct{ ByIP, ByMAC map[string]Lease }{db.ByIP, db.ByMAC}); err != nil {
		_ = f.Close()
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

// Set inserts or updates a lease while maintaining MAC/IP indexes and first_seen.
func (db *LeaseDB) Set(lease Lease) {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Canonical lower-case with colons.
	normMac := strings.ToLower(lease.MAC)
	if nm, err := normalizeMACFlexible(normMac); err == nil {
		normMac = nm
	}
	lease.MAC = normMac

	if old, ok := db.ByMAC[normMac]; ok && (old.IP != lease.IP || !macEqual(old.MAC, lease.MAC)) {
		delete(db.ByIP, old.IP)
		if old.FirstSeen > 0 && lease.FirstSeen == 0 {
			lease.FirstSeen = old.FirstSeen
		}
	}
	if old, ok := db.ByIP[lease.IP]; ok && !macEqual(old.MAC, lease.MAC) {
		delete(db.ByMAC, strings.ToLower(old.MAC))
	}
	if lease.FirstSeen == 0 {
		lease.FirstSeen = time.Now().Unix()
	}
	db.ByIP[lease.IP] = lease
	db.ByMAC[normMac] = lease
	db.dirty = true
}

// RemoveByIP deletes a lease by IP if present.
func (db *LeaseDB) RemoveByIP(ip string) {
	db.mu.Lock()
	if l, ok := db.ByIP[ip]; ok {
		delete(db.ByIP, ip)
		delete(db.ByMAC, strings.ToLower(l.MAC))
		db.dirty = true
	}
	db.mu.Unlock()
}

// FindByMAC returns the lease for a MAC, if any.
func (db *LeaseDB) FindByMAC(mac string) (Lease, bool) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if nm, err := normalizeMACFlexible(mac); err == nil {
		mac = nm
	}
	l, ok := db.ByMAC[strings.ToLower(mac)]
	return l, ok
}

// FindByIP returns the lease for an IP, if any.
func (db *LeaseDB) FindByIP(ip string) (Lease, bool) {
	db.mu.Lock()
	defer db.mu.Unlock()
	l, ok := db.ByIP[ip]
	return l, ok
}

// MarkDeclined quarantines an IP for duration d.
func (db *LeaseDB) MarkDeclined(ip string, d time.Duration) {
	db.mu.Lock()
	db.decline[ip] = time.Now().Add(d)
	db.mu.Unlock()
}

// IsDeclined reports whether ip is currently quarantined.
func (db *LeaseDB) IsDeclined(ip string) bool {
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

// CompactNow removes leases expired more than grace ago and persists if anything changed.
func (db *LeaseDB) CompactNow(grace time.Duration) int {
	n := db.removeExpiredOlderThan(grace)
	if n > 0 {
		_ = db.Save()
	}
	return n
}

// ForEach iterates current snapshot under lock without copying. Read-only use only.
func (db *LeaseDB) ForEach(yield func(Lease)) {
	db.mu.Lock()
	for _, l := range db.ByIP {
		yield(l)
	}
	db.mu.Unlock()
}

func (db *LeaseDB) removeExpiredOlderThan(grace time.Duration) int {
	db.mu.Lock()
	defer db.mu.Unlock()
	now := time.Now().Unix()
	g := int64(grace.Seconds())
	removed := 0
	for ip, l := range db.ByIP {
		if l.Expiry > 0 && now > (l.Expiry+g) {
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

/* ----------------- Server ----------------- */

// Server is the DHCP engine. It holds only DHCP-domain state and foreign providers.
// It never stores the Config itself; it calls cfgGet() per-request.
type Server struct {
	mu        sync.RWMutex
	db        *LeaseDB
	cfgGet    func() *config.Config
	authorGet func() bool
	logSink   func(string, ...any)
	errorSink func(string, ...any)
	now       func() time.Time
	closer    io.Closer // active listener from BindAndServe
}

// NewServer builds a decoupled server. Sinks may be nil.
func NewServer(db *LeaseDB, cfgGet func() *config.Config, authorGet func() bool, logSink func(string, ...any), errorSink func(string, ...any)) *Server {
	if cfgGet == nil {
		cfgGet = func() *config.Config { return nil }
	}
	if authorGet == nil {
		authorGet = func() bool { return true }
	}
	return &Server{db: db, cfgGet: cfgGet, authorGet: authorGet, logSink: logSink, errorSink: errorSink, now: time.Now}
}

// BindAndServe binds to iface on UDP/67 and serves in a goroutine. Returns an io.Closer for shutdown.
func (s *Server) BindAndServe(iface string, laddr *net.UDPAddr) (io.Closer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closer != nil {
		_ = s.closer.Close()
		s.closer = nil
	}
	nsrv, err := server4.NewServer(iface, laddr, s.Handler)
	if err != nil {
		return nil, err
	}
	go func() { _ = nsrv.Serve() }()
	s.closer = nsrv
	return nsrv, nil
}

// Close stops the active listener if any.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closer != nil {
		err := s.closer.Close()
		s.closer = nil
		return err
	}
	return nil
}

func (s *Server) logf(format string, args ...any) {
	if s.logSink != nil {
		s.logSink(format, args...)
	}
}
func (s *Server) errorf(format string, args ...any) {
	if s.errorSink != nil {
		s.errorSink(format, args...)
	} else if s.logSink != nil {
		s.logSink("ERROR: "+format, args...)
	}
}

// Handler processes a single DHCPv4 request.
func (s *Server) Handler(conn net.PacketConn, peer net.Addr, req *dhcpv4.DHCPv4) {
	cfg := s.cfgGet()
	if cfg == nil {
		s.errorf("no config available")
		return
	}
	authoritative := s.authorGet()
	_, subnet := mustCIDR(cfg.SubnetCIDR)
	serverIP := ParseIP4(cfg.ServerIP)

	mt := req.MessageType()
	dispMAC := macDisplay(req.ClientHWAddr)

	var mac string
	if nm, err := normalizeMACFlexible(dispMAC); err == nil {
		mac = nm
	} else {
		mac = strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(dispMAC), "-", ":"), " ", ""))
	}

	hostname := strings.TrimRight(string(req.Options.Get(dhcpv4.OptionHostName)), "\x00")

	// banned set = env + cfg
	banned := ParseBannedMACsEnv()
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
		// echo relay agent info if configured
		if cfg.EchoRelayAgentInfo82 {
			if ra := req.Options.Get(dhcpv4.OptionRelayAgentInformation); len(ra) > 0 {
				offer.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionRelayAgentInformation, ra))
			}
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
		if !ipInSubnet(reqIP, subnet) || s.isExcluded(cfg, reqIP) || s.db.IsDeclined(reqIP.String()) {
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
		if l, ok := s.db.FindByIP(reqIP.String()); ok {
			now := s.now().Unix()
			if now <= l.Expiry && !macEqual(l.MAC, mac) {
				s.logf("REQUEST ip=%s already leased to %s until %s -> NAK", reqIP, l.MAC, FormatEpoch(l.Expiry))
				if authoritative {
					nak, _ := dhcpv4.NewReplyFromRequest(req)
					nak.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeNak))
					nak.UpdateOption(dhcpv4.OptServerIdentifier(serverIP))
					_, _ = conn.WriteTo(nak.ToBytes(), peer)
				}
				return
			}
		}
		firstSeen := int64(0)
		if prev, ok := s.db.FindByMAC(mac); ok && prev.FirstSeen > 0 {
			firstSeen = prev.FirstSeen
		} else {
			firstSeen = s.now().Unix()
			s.logf("first_seen: %s here on %s", mac, FormatEpoch(firstSeen))
		}
		now := s.now().Unix()
		ack, err := s.buildReply(cfg, req, dhcpv4.MessageTypeAck, reqIP, mac)
		if err != nil {
			s.logf("ack build error for %s ip=%s: %v", dispMAC, reqIP, err)
			return
		}
		// echo relay agent info if configured
		if cfg.EchoRelayAgentInfo82 {
			if ra := req.Options.Get(dhcpv4.OptionRelayAgentInformation); len(ra) > 0 {
				ack.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionRelayAgentInformation, ra))
			}
		}
		lease := Lease{MAC: mac, IP: reqIP.String(), Hostname: hostname, AllocatedAt: now, Expiry: now + int64(cfg.LeaseSeconds), FirstSeen: firstSeen}
		s.db.Set(lease)
		_ = s.db.Save()
		s.logf("ACK %s <- %s lease=%s (alloc=%s, exp=%s)", dispMAC, reqIP.String(), time.Duration(cfg.LeaseSeconds)*time.Second, FormatEpoch(lease.AllocatedAt), FormatEpoch(lease.Expiry))
		_, _ = conn.WriteTo(ack.ToBytes(), peer)

	case dhcpv4.MessageTypeRelease:
		if !req.ClientIPAddr.Equal(net.IPv4zero) {
			s.db.RemoveByIP(req.ClientIPAddr.String())
			_ = s.db.Save()
			s.logf("RELEASE from %s ip=%s", dispMAC, req.ClientIPAddr.String())
		}

	case dhcpv4.MessageTypeDecline:
		if rip := req.Options.Get(dhcpv4.OptionRequestedIPAddress); len(rip) == 4 {
			ip := net.IP(rip).String()
			s.db.MarkDeclined(ip, 10*time.Minute)
			s.logf("DECLINE from %s ip=%s quarantined 10m", dispMAC, ip)
		}

	default:
		s.logf("Unhandled DHCP msg type %v from %s", mt, dispMAC)
	}
}

func (s *Server) isExcluded(cfg *config.Config, ip net.IP) bool {
	for _, e := range cfg.Exclusions {
		if ip.Equal(ParseIP4(e)) {
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

// chooseIPForMAC implements the same 5-step policy as before.
func (s *Server) chooseIPForMAC(cfg *config.Config, mac string) (net.IP, bool) {
	_, subnet := mustCIDR(cfg.SubnetCIDR)
	serverIP := ParseIP4(cfg.ServerIP)
	gatewayIP := ParseIP4(cfg.Gateway)
	isBad := func(ip net.IP) bool {
		if !ipInSubnet(ip, subnet) || s.isExcluded(cfg, ip) || s.db.IsDeclined(ip.String()) {
			return true
		}
		if ip.Equal(serverIP) || ip.Equal(gatewayIP) {
			return true
		}
		network := subnet.IP.Mask(subnet.Mask)
		bcast := BroadcastAddr(subnet)
		if ip.Equal(network) || ip.Equal(bcast) {
			return true
		}
		if rmac := s.macForReservedIP(cfg, ip); rmac != "" && !macEqual(rmac, mac) {
			return true
		}
		return false
	}
	// 1) Reservation
	if rv, ok := cfg.Reservations[mac]; ok {
		ip := ParseIP4(rv.IP)
		if ip == nil || isBad(ip) {
			return nil, false
		}
		if l, ok := s.db.FindByIP(ip.String()); ok {
			now := s.now().Unix()
			if now <= l.Expiry && !macEqual(l.MAC, mac) {
				return nil, false
			}
		}
		return ip, true
	}
	now := s.now().Unix()
	// 2) Prefer last IP for this MAC
	if l, ok := s.db.FindByMAC(mac); ok {
		ip := net.ParseIP(l.IP).To4()
		if ip != nil && !isBad(ip) {
			if cur, ok := s.db.FindByIP(ip.String()); !ok || macEqual(cur.MAC, mac) || now > cur.Expiry {
				return ip, true
			}
		}
	}
	// 3) Brand-new IPs
	for _, p := range cfg.Pools {
		start := ParseIP4(p.Start)
		end := ParseIP4(p.End)
		for ip := start; IPToU32(ip) <= IPToU32(end); ip = IncIP(ip) {
			if isBad(ip) {
				continue
			}
			if _, ever := s.db.FindByIP(ip.String()); !ever {
				return ip, true
			}
		}
	}
	// 4) Recycle expired safe IPs
	for _, p := range cfg.Pools {
		start := ParseIP4(p.Start)
		end := ParseIP4(p.End)
		for ip := start; IPToU32(ip) <= IPToU32(end); ip = IncIP(ip) {
			if isBad(ip) {
				continue
			}
			if l, ok := s.db.FindByIP(ip.String()); ok {
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
	serverIP := ParseIP4(cfg.ServerIP)
	gatewayIP := ParseIP4(cfg.Gateway)

	resp.UpdateOption(dhcpv4.OptMessageType(typ))
	resp.YourIPAddr = yiaddr.To4()
	leaseDur := time.Duration(cfg.LeaseSeconds) * time.Second
	resp.UpdateOption(dhcpv4.OptServerIdentifier(serverIP))
	resp.UpdateOption(dhcpv4.OptSubnetMask(net.IPMask(subnet.Mask)))
	resp.UpdateOption(dhcpv4.OptRouter(gatewayIP))
	resp.UpdateOption(dhcpv4.OptIPAddressLeaseTime(leaseDur))
	resp.UpdateOption(dhcpv4.OptRenewTimeValue(leaseDur / 2))
	resp.UpdateOption(dhcpv4.OptRebindingTimeValue(leaseDur * 7 / 8))
	if len(cfg.DNS) > 0 {
		resp.UpdateOption(dhcpv4.OptDNS(toIPs(cfg.DNS)...))
	}
	// 12 Host Name suggestion only if client did not send one
	if cfg.Hostname12 != "" && len(req.Options.Get(dhcpv4.OptionHostName)) == 0 {
		resp.UpdateOption(dhcpv4.OptHostName(cfg.Hostname12))
	}
	if cfg.Domain != "" {
		resp.UpdateOption(dhcpv4.OptDomainName(cfg.Domain))
	}
	if len(cfg.NTP) > 0 {
		resp.UpdateOption(dhcpv4.OptNTPServers(toIPs(cfg.NTP)...))
	}
	if cfg.MTU > 0 {
		mtu := make([]byte, 2)
		binary.BigEndian.PutUint16(mtu, uint16(cfg.MTU))
		resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(26), mtu))
	}
	if cfg.TFTPServerName != "" {
		resp.UpdateOption(dhcpv4.OptTFTPServerName(cfg.TFTPServerName)) // 66
	}
	if cfg.BootFileName != "" {
		resp.BootFileName = cfg.BootFileName
		resp.UpdateOption(dhcpv4.OptBootFileName(cfg.BootFileName)) // 67
	}
	if cfg.WPADURL != "" {
		resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(252), []byte(cfg.WPADURL)))
	}
	if len(cfg.WINS) > 0 {
		resp.UpdateOption(dhcpv4.OptNetBIOSNameServers(toIPs(cfg.WINS)...))
	}
	if len(cfg.DomainSearch) > 0 {
		lbls := &rfc1035label.Labels{Labels: append([]string(nil), cfg.DomainSearch...)}
		resp.UpdateOption(dhcpv4.OptDomainSearch(lbls)) // 119
	}
	if len(cfg.StaticRoutes) > 0 {
		var rs []*dhcpv4.Route
		for _, r := range cfg.StaticRoutes {
			_, ipnet, err := net.ParseCIDR(strings.TrimSpace(r.CIDR))
			if err != nil {
				return nil, fmt.Errorf("bad CIDR %q: %w", r.CIDR, err)
			}
			gw := ParseIP4(r.Gateway)
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
			resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionVendorSpecificInformation, v43)) // 43
		}
	}

	// 28 Broadcast Address
	if cfg.EnableBroadcast28 {
		if b := BroadcastAddr(subnet).To4(); b != nil {
			resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(28), []byte(b)))
		}
	}

	// 33 Classful Static Routes
	if cfg.UseClassfulRoutes33 && len(cfg.Routes33) > 0 {
		var buf []byte
		for _, r := range cfg.Routes33 {
			dst := net.ParseIP(strings.TrimSpace(r.Destination)).To4()
			gw := net.ParseIP(strings.TrimSpace(r.Gateway)).To4()
			if dst == nil || gw == nil {
				continue
			}
			buf = append(buf, dst...)
			buf = append(buf, gw...)
		}
		if len(buf) > 0 {
			resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(33), buf))
		}
	}

	// 46 NetBIOS node type
	if cfg.NetBIOSNodeType46 != 0 {
		resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(46), []byte{byte(cfg.NetBIOSNodeType46)}))
	}

	// 47 NetBIOS scope ID
	if cfg.NetBIOSScopeID47 != "" {
		resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(47), []byte(cfg.NetBIOSScopeID47)))
	}

	// 57 Maximum DHCP Message Size
	if cfg.MaxDHCPMessageSize57 != 0 {
		msz := make([]byte, 2)
		binary.BigEndian.PutUint16(msz, cfg.MaxDHCPMessageSize57)
		resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(57), msz))
	}

	// 150 TFTP server addresses
	if len(cfg.TFTPServers150) > 0 {
		var buf []byte
		for _, s := range cfg.TFTPServers150 {
			if ip := net.ParseIP(strings.TrimSpace(s)).To4(); ip != nil {
				buf = append(buf, ip...)
			}
		}
		if len(buf) > 0 {
			resp.UpdateOption(dhcpv4.OptGeneric(dhcpv4.GenericOptionCode(150), buf))
		}
	}

	// MAC-based overrides
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

	// 60 Vendor Class Identifier based overrides
	if vci := strings.TrimRight(string(req.Options.Get(dhcpv4.OptionClassIdentifier)), "\x00"); vci != "" {
		if ov, ok := cfg.VendorClassOverrides[vci]; ok {
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
	}

	// 77 User Class based overrides (multiple classes possible)
	if raw := req.Options.Get(dhcpv4.GenericOptionCode(77)); len(raw) > 0 {
		for _, cls := range parseUserClass77(raw) {
			if ov, ok := cfg.UserClassOverrides77[cls]; ok {
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
		}
	}

	return resp, nil
}

// parseUserClass77 parses RFC 3004 user-class data into a slice of strings.
func parseUserClass77(b []byte) []string {
	var out []string
	for i := 0; i < len(b); {
		l := int(b[i])
		i++
		if l == 0 || i+l > len(b) {
			break
		}
		out = append(out, string(b[i:i+l]))
		i += l
	}
	// Fallback: if TLV parse failed, treat as single opaque string
	if len(out) == 0 && len(b) > 0 {
		out = append(out, string(b))
	}
	return out
}

/* ----------------- Cross-package helpers (exported) ----------------- */

// EnforceReservationLeaseConsistency ensures reservations win over leases.
func EnforceReservationLeaseConsistency(db *LeaseDB, cfg *config.Config) {
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

// FormatEpoch returns local time formatted as "YYYY/MM/DD HH:MM:SS" or empty if ts<=0.
func FormatEpoch(ts int64) string {
	if ts <= 0 {
		return ""
	}
	return time.Unix(ts, 0).Local().Format("2006/01/02 15:04:05")
}

// CanonMAC normalizes to lower-case "aa:bb:cc:dd:ee:ff".
func CanonMAC(s string) (string, error) { return normalizeMACFlexible(s) }

// MustCanonMAC panics if s cannot be normalized.
func MustCanonMAC(s string) string {
	n, err := CanonMAC(s)
	if err != nil {
		panic(err)
	}
	return n
}

// MacEqual normalizes both sides and compares.
func MacEqual(a, b string) bool {
	na, ea := CanonMAC(a)
	nb, eb := CanonMAC(b)
	if ea == nil && eb == nil {
		return na == nb
	}
	return strings.EqualFold(a, b)
}

// ParseBannedMACsEnv reads dhcplane_BANNED_MACS and returns a set of normalized MACs.
func ParseBannedMACsEnv() map[string]struct{} {
	raw := os.Getenv("dhcplane_BANNED_MACS")
	banned := make(map[string]struct{})
	if strings.TrimSpace(raw) == "" {
		return banned
	}
	split := func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' }
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

/* ----------------- Internal helpers (unchanged behavior) ----------------- */

func xidString(req *dhcpv4.DHCPv4) string {
	b := req.TransactionID
	if len(b) >= 4 {
		return fmt.Sprintf("0x%08x", binary.BigEndian.Uint32(b[:4]))
	}
	return fmt.Sprintf("0x%x", b)
}

func macDisplay(b []byte) string { return net.HardwareAddr(b).String() }

func mustCIDR(c string) (net.IP, *net.IPNet) {
	ip, n, err := net.ParseCIDR(c)
	if err != nil {
		panic(fmt.Errorf("bad subnet_cidr %q: %v", c, err))
	}
	return ip, n
}

// ParseIP4 parses and panics if invalid or not IPv4.
func ParseIP4(s string) net.IP {
	ip := net.ParseIP(strings.TrimSpace(s)).To4()
	if ip == nil {
		panic(fmt.Errorf("bad IPv4 %q", s))
	}
	return ip
}

func toIPs(list []string) []net.IP {
	ips := make([]net.IP, 0, len(list))
	for _, s := range list {
		if ip := net.ParseIP(strings.TrimSpace(s)).To4(); ip != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

// IPToU32 panics if ip is not 4 bytes.
func IPToU32(ip net.IP) uint32 { return binary.BigEndian.Uint32(ip.To4()) }

func u32ToIP(v uint32) net.IP {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return net.IP(b)
}

// IncIP returns ip+1. Panics if ip is not 4 bytes.
func IncIP(ip net.IP) net.IP { return u32ToIP(IPToU32(ip) + 1) }

func ipInSubnet(ip net.IP, n *net.IPNet) bool { return n.Contains(ip) }

// BroadcastAddr calculates the broadcast address for a subnet.
func BroadcastAddr(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	mask := net.IP(n.Mask).To4()
	var b [4]byte
	for i := 0; i < 4; i++ {
		b[i] = ip[i] | ^mask[i]
	}
	return net.IP(b[:])
}

// normalizeMACFlexible accepts ":", "-", or no separators and returns canonical lower-case with colons.
func normalizeMACFlexible(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
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
		parts := make([]string, 0, 6)
		for i := 0; i < 12; i += 2 {
			parts = append(parts, raw[i:i+2])
		}
		s = strings.Join(parts, ":")
	} else {
		s = strings.ReplaceAll(s, "-", ":")
	}
	m, err := net.ParseMAC(s)
	if err != nil {
		return "", err
	}
	return strings.ToLower(m.String()), nil
}

/* ----------------- Optional helpers used by callers ----------------- */

// SnapshotByIP returns a stable slice of IP keys sorted ascending. Useful for deterministic prints.
func SnapshotByIP(db *LeaseDB) []string {
	db.mu.Lock()
	ips := make([]string, 0, len(db.ByIP))
	for ip := range db.ByIP {
		ips = append(ips, ip)
	}
	db.mu.Unlock()
	sort.Strings(ips)
	return ips
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
