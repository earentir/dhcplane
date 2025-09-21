// Package config holds the JSON-config-related data types and logic
package config

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

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

// StaticRoute33 represents a classful route for DHCP option 33.
type StaticRoute33 struct {
	Destination string `json:"destination"` // dotted-quad network (classful: a.0.0.0 | a.b.0.0 | a.b.c.0)
	Gateway     string `json:"gateway"`     // IPv4
}

// config/config.go

// Config represents the DHCP server configuration.
type Config struct {
	Interface     string   `json:"interface,omitempty"`
	ServerIP      string   `json:"server_ip"`
	SubnetCIDR    string   `json:"subnet_cidr"`
	Gateway       string   `json:"gateway"`
	CompactOnLoad bool     `json:"compact_on_load"`
	DNS           []string `json:"dns"`
	Domain        string   `json:"domain,omitempty"`

	// Authoritative mode: when true, server sends NAKs on invalid requests.
	// Nil means "unset" and defaults to true.
	Authoritative *bool `json:"authoritative,omitempty"`

	LeaseSeconds       int  `json:"lease_seconds"`
	LeaseStickySeconds int  `json:"lease_sticky_seconds,omitempty"`
	AutoReload         bool `json:"auto_reload,omitempty"`

	Pools        []Pool       `json:"pools"`
	Exclusions   []string     `json:"exclusions,omitempty"`
	Reservations Reservations `json:"reservations,omitempty"`

	NTP            []string `json:"ntp,omitempty"`
	MTU            int      `json:"mtu,omitempty"`
	TFTPServerName string   `json:"tftp_server_name,omitempty"` // opt 66
	BootFileName   string   `json:"bootfile_name,omitempty"`    // opt 67
	WPADURL        string   `json:"wpad_url,omitempty"`
	WINS           []string `json:"wins,omitempty"`

	DomainSearch        []string                  `json:"domain_search,omitempty"`
	StaticRoutes        []StaticRoute             `json:"static_routes,omitempty"`
	MirrorRoutesTo249   bool                      `json:"mirror_routes_to_249,omitempty"`
	VendorSpecific43Hex string                    `json:"vendor_specific_43_hex,omitempty"` // opt 43 (hex payload)
	DeviceOverrides     map[string]DeviceOverride `json:"device_overrides,omitempty"`

	// suggest hostname (opt 12) when client does not supply one
	Hostname12 string `json:"hostname_12,omitempty"`

	// per Vendor Class Identifier (opt 60) overrides
	VendorClassOverrides map[string]DeviceOverride `json:"vendor_class_overrides,omitempty"`

	// per User Class (opt 77) overrides
	UserClassOverrides77 map[string]DeviceOverride `json:"user_class_overrides_77,omitempty"`

	EnableBroadcast28    bool            `json:"enable_broadcast_28,omitempty"`
	UseClassfulRoutes33  bool            `json:"use_classful_routes_33,omitempty"`
	Routes33             []StaticRoute33 `json:"routes_33,omitempty"`
	NetBIOSNodeType46    uint8           `json:"netbios_node_type_46,omitempty"`
	NetBIOSScopeID47     string          `json:"netbios_scope_id_47,omitempty"`
	MaxDHCPMessageSize57 uint16          `json:"max_dhcp_message_size_57,omitempty"`
	TFTPServers150       []string        `json:"tftp_servers_150,omitempty"`
	EchoRelayAgentInfo82 bool            `json:"echo_relay_agent_info_82,omitempty"`

	// Config-based banned MACs with metadata
	BannedMACs map[string]DeviceMeta `json:"banned_macs,omitempty"`

	// Allowed enumerations
	EquipmentTypes  []string `json:"equipment_types,omitempty"`
	ManagementTypes []string `json:"management_types,omitempty"`

	// Max console buffer
	ConsoleMaxLines int `json:"console_max_lines,omitempty"`

	// Log rotation settings
	Logging LoggingConfig `json:"logging"`

	DetectDHCPServers DHCPServerDetectionConfig `json:"detect_dhcp_servers,omitempty"`

	ARPAnomalyDetection ARPAnomalyDetectionConfig `json:"arp_anomaly_detection,omitempty"`
}

// ARPAnomalyDetectionConfig holds settings for ARP anomaly detection.
type ARPAnomalyDetectionConfig struct {
	Enabled       bool `json:"enabled,omitempty"`
	ProbeInterval int  `json:"probe_interval,omitempty"` // seconds, default 1800
	FirstScan     int  `json:"first_scan,omitempty"`     // seconds, default 60
}

// DHCPServerDetectionConfig holds settings for DHCP server detection.
type DHCPServerDetectionConfig struct {
	Enabled          bool     `json:"enabled,omitempty"`
	ActiveProbe      string   `json:"active_probe,omitempty"`
	ProbeInterval    int      `json:"probe_interval,omitempty"`
	WhitelistServers []string `json:"whitelist_servers,omitempty"`
	RateLimit        int      `json:"rate_limit,omitempty"`
}

// LoggingConfig represents log rotation settings.
type LoggingConfig struct {
	Path       string `json:"path,omitempty"`
	Filename   string `json:"filename,omitempty"`
	MaxSize    int    `json:"max_size,omitempty"` // megabytes
	MaxBackups int    `json:"max_backups,omitempty"`
	MaxAge     int    `json:"max_age,omitempty"` // days
	Compress   bool   `json:"compress,omitempty"`
}

/* ----------------- Config parsing & validation ----------------- */

// JSONErr represents a JSON parsing error with line/column info.
type JSONErr struct {
	Err    error
	Line   int
	Column int
}

func (e *JSONErr) Error() string {
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

// ParseStrict reads the config file strictly (unknown fields rejected) and
// preserves the same defaults/behavior as the original parseConfigStrict.
func ParseStrict(path string) (Config, *JSONErr) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, &JSONErr{Err: err}
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		if se, ok := err.(*json.SyntaxError); ok {
			line, col := locateJSONError(data, se.Offset)
			return cfg, &JSONErr{Err: err, Line: line, Column: col}
		}
		if ute, ok := err.(*json.UnmarshalTypeError); ok {
			line, col := locateJSONError(data, ute.Offset)
			return cfg, &JSONErr{Err: err, Line: line, Column: col}
		}
		return cfg, &JSONErr{Err: err}
	}
	// defaults
	if cfg.LeaseSeconds <= 0 {
		cfg.LeaseSeconds = 86400 // 24h
	}
	if cfg.LeaseStickySeconds <= 0 {
		cfg.LeaseStickySeconds = 86400 // default sticky window
	}
	if len(cfg.Pools) == 0 {
		return cfg, &JSONErr{Err: errors.New("config: at least one pool required")}
	}
	if cfg.Reservations == nil {
		cfg.Reservations = make(Reservations)
	}
	return cfg, nil
}

/* ----------------- Small helpers (package-local) ----------------- */

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

func parseIPv4(s string) net.IP {
	return net.ParseIP(strings.TrimSpace(s)).To4()
}

func stringInSlice(s string, list []string) bool {
	for _, v := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

// ParseHexPayload accepts "01 02", "0x01,0x02", "hex:01:02", etc.
func ParseHexPayload(s string) ([]byte, error) {
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

// ValidateAndNormalizeConfig applies defaults, normalizes MAC-keyed maps, it returns a COPY of cfg with fixes applied.
func ValidateAndNormalizeConfig(cfg Config) (Config, []string, error) {
	c := cfg
	var warns []string

	// Default: authoritative=true when unset.
	if c.Authoritative == nil {
		v := true
		c.Authoritative = &v
	}

	if len(c.EquipmentTypes) == 0 {
		c.EquipmentTypes = []string{"Switch", "Router", "AP", "Modem", "Gateway"}
	}
	if len(c.ManagementTypes) == 0 {
		c.ManagementTypes = []string{"ssh", "web", "telnet", "serial", "console"}
	}

	if c.Reservations == nil {
		c.Reservations = make(Reservations)
	} else {
		norm := make(Reservations, len(c.Reservations))
		for m, rv := range c.Reservations {
			nm, err := normalizeMACFlexible(m)
			if err != nil {
				return cfg, warns, fmt.Errorf("bad reservation MAC %q: %w", m, err)
			}
			if rv.EquipmentType != "" && !stringInSlice(rv.EquipmentType, c.EquipmentTypes) {
				warns = append(warns, fmt.Sprintf("warning: reservation %s has unknown equipment_type %q; allowed: %v",
					nm, rv.EquipmentType, c.EquipmentTypes))
			}
			if rv.ManagementType != "" && !stringInSlice(rv.ManagementType, c.ManagementTypes) {
				warns = append(warns, fmt.Sprintf("warning: reservation %s has unknown management_type %q; allowed: %v",
					nm, rv.ManagementType, c.ManagementTypes))
			}
			ip := parseIPv4(rv.IP)
			if ip == nil {
				return cfg, warns, fmt.Errorf("bad reservation IP %q", rv.IP)
			}
			rv.IP = ip.String()
			norm[nm] = rv
		}
		c.Reservations = norm
	}

	if c.DeviceOverrides == nil {
		c.DeviceOverrides = make(map[string]DeviceOverride)
	} else {
		norm := make(map[string]DeviceOverride, len(c.DeviceOverrides))
		for m, ov := range c.DeviceOverrides {
			nm, err := normalizeMACFlexible(m)
			if err != nil {
				return cfg, warns, fmt.Errorf("bad device_overrides MAC %q: %w", m, err)
			}
			norm[nm] = ov
		}
		c.DeviceOverrides = norm
	}

	// VendorClassOverrides: keyed by raw option-60 string
	if c.VendorClassOverrides == nil {
		c.VendorClassOverrides = make(map[string]DeviceOverride)
	}

	// UserClassOverrides77: keyed by user-class string(s)
	if c.UserClassOverrides77 == nil {
		c.UserClassOverrides77 = make(map[string]DeviceOverride)
	}

	if s := strings.TrimSpace(c.VendorSpecific43Hex); s != "" {
		if _, err := ParseHexPayload(s); err != nil {
			return cfg, warns, fmt.Errorf("vendor_specific_43_hex: %w", err)
		}
	}

	if c.BannedMACs == nil {
		c.BannedMACs = make(map[string]DeviceMeta)
	} else {
		for m, meta := range c.BannedMACs {
			nm, err := normalizeMACFlexible(m)
			if err != nil {
				return cfg, warns, fmt.Errorf("bad banned_macs MAC %q: %w", m, err)
			}
			if meta.EquipmentType != "" && !stringInSlice(meta.EquipmentType, c.EquipmentTypes) {
				warns = append(warns, fmt.Sprintf("warning: banned %s has unknown equipment_type %q; allowed: %v",
					nm, meta.EquipmentType, c.EquipmentTypes))
			}
			if meta.ManagementType != "" && !stringInSlice(meta.ManagementType, c.ManagementTypes) {
				warns = append(warns, fmt.Sprintf("warning: banned %s has unknown management_type %q; allowed: %v",
					nm, meta.ManagementType, c.ManagementTypes))
			}
		}
	}

	// Validate Routes33 if enabled
	if c.UseClassfulRoutes33 {
		for i, r := range c.Routes33 {
			gw := parseIPv4(r.Gateway)
			if gw == nil {
				return cfg, warns, fmt.Errorf("routes_33[%d]: bad gateway %q", i, r.Gateway)
			}
			octs := strings.Split(r.Destination, ".")
			if len(octs) != 4 {
				return cfg, warns, fmt.Errorf("routes_33[%d]: bad destination %q", i, r.Destination)
			}
			classful := (octs[1] == "0" && octs[2] == "0" && octs[3] == "0") ||
				(octs[2] == "0" && octs[3] == "0") ||
				(octs[3] == "0")
			if !classful || parseIPv4(r.Destination) == nil {
				return cfg, warns, fmt.Errorf("routes_33[%d]: destination %q must be classful network (a.0.0.0 | a.b.0.0 | a.b.c.0)", i, r.Destination)
			}
		}
	}

	if c.NetBIOSNodeType46 != 0 {
		switch c.NetBIOSNodeType46 {
		case 1, 2, 4, 8:
		default:
			return cfg, warns, fmt.Errorf("netbios_node_type_46 must be one of {1,2,4,8}")
		}
	}

	if c.MaxDHCPMessageSize57 != 0 && c.MaxDHCPMessageSize57 < 576 {
		return cfg, warns, fmt.Errorf("max_dhcp_message_size_57 must be >= 576")
	}

	for i, s := range c.TFTPServers150 {
		if parseIPv4(s) == nil {
			return cfg, warns, fmt.Errorf("tftp_servers_150[%d]: bad IPv4 %q", i, s)
		}
	}

	// Logging defaults and validation
	if c.Logging.Path != "" || c.Logging.Filename != "" {
		if c.Logging.MaxSize <= 0 {
			c.Logging.MaxSize = 20
		}
		if c.Logging.MaxBackups < 0 {
			return cfg, warns, fmt.Errorf("logging.max_backups must be >= 0")
		}
		if c.Logging.MaxBackups == 0 {
			c.Logging.MaxBackups = 5
		}
		if c.Logging.MaxAge < 0 {
			return cfg, warns, fmt.Errorf("logging.max_age must be >= 0")
		}
		if !c.Logging.Compress {
			c.Logging.Compress = true
		}
	}

	// DetectDHCPServers: defaults, clamps, normalization, validation
	{
		d := c.DetectDHCPServers

		// Defaults
		if !d.Enabled {
			if d.ActiveProbe == "" && d.ProbeInterval == 0 && d.RateLimit == 0 && len(d.WhitelistServers) == 0 {
				d.Enabled = true
			}
		}
		if d.ActiveProbe == "" {
			d.ActiveProbe = "off"
		}
		d.ActiveProbe = strings.ToLower(strings.TrimSpace(d.ActiveProbe))
		switch d.ActiveProbe {
		case "off", "safe", "aggressive":
		default:
			warns = append(warns, fmt.Sprintf("warning: detect_dhcp_servers.active_probe %q not in {off,safe,aggressive}; using off", d.ActiveProbe))
			d.ActiveProbe = "off"
		}

		if d.ProbeInterval <= 0 {
			d.ProbeInterval = 600
		}
		if d.ProbeInterval < 60 {
			warns = append(warns, "warning: detect_dhcp_servers.probe_interval clamped to 60s minimum")
			d.ProbeInterval = 60
		}

		if d.RateLimit <= 0 {
			d.RateLimit = 6
		}
		if d.RateLimit < 1 {
			d.RateLimit = 1
		}

		// Normalize whitelist entries
		if len(d.WhitelistServers) > 0 {
			out := make([]string, 0, len(d.WhitelistServers))
			for _, w := range d.WhitelistServers {
				w = strings.TrimSpace(w)
				if w == "" {
					continue
				}
				if ip := parseIPv4(w); ip != nil {
					out = append(out, ip.String())
					continue
				}
				if nm, err := normalizeMACFlexible(w); err == nil {
					out = append(out, nm)
					continue
				}
				warns = append(warns, fmt.Sprintf("warning: detect_dhcp_servers.whitelist_servers entry %q ignored (not IPv4 or MAC)", w))
			}
			d.WhitelistServers = out
		}

		c.DetectDHCPServers = d
	}

	return c, warns, nil
}
