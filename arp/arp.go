package arp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"dhcplane/config"
	"dhcplane/dhcpserver"
)

/* ----------------- Public API ----------------- */

type Entry struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Iface  string `json:"iface"`
	Source string `json:"source"` // scan|cache
	State  string `json:"state"`  // reserved|leased|free|excluded|self
	Note   string `json:"note"`   // mismatch|unknown|banned-mac|expired-lease|-
}

type Finding struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Iface    string `json:"iface"`
	Reason   string `json:"reason"` // unknown|mac-mismatch|banned-mac
	LeaseMAC string `json:"lease_mac"`
	ResMAC   string `json:"res_mac"`
}

// Scan is the library version used by the server scheduler.
func Scan(cfg *config.Config, db *dhcpserver.LeaseDB, iface string, allIfaces bool, timeout time.Duration) ([]Entry, []Finding, error) {
	return gather(cfg, db, iface, allIfaces, timeout)
}

// ScanForCLI is the CLI helper. When refresh=true on non-Linux,
// it pings targets to warm ARP cache before reading.
func ScanForCLI(cfg config.Config, leasePath, iface string, allIfaces, refresh bool, timeout time.Duration) ([]Entry, []Finding, error) {
	db := dhcpserver.NewLeaseDB(leasePath)
	_ = db.Load()

	// On macOS/Windows, optionally warm the ARP cache by pinging targets
	if refresh && runtime.GOOS != "linux" {
		targets := computeTargets(cfg)
		pingWarmup(targets, timeout)
	}
	return gather(&cfg, db, iface, allIfaces, timeout)
}

// PrintTable renders a plain table and legend to stdout.
func PrintTable(rows []Entry) {
	w := tabwriter.NewWriter(stdoutWriter{}, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tMAC\tIFACE\tSOURCE\tSTATE\tNOTE")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.IP, r.MAC, r.Iface, r.Source, r.State, r.Note)
	}
	_ = w.Flush()

	// Legend
	fmt.Println()
	fmt.Println("Legend:")
	fmt.Println("  STATE:")
	fmt.Println("    reserved  → IP reserved in config")
	fmt.Println("    leased    → IP has an active lease")
	fmt.Println("    free      → in pool with no active lease")
	fmt.Println("    excluded  → excluded/server/gateway/network/broadcast")
	fmt.Println("    self      → server or gateway IP")
	fmt.Println("  NOTE:")
	fmt.Println("    -             → expected")
	fmt.Println("    unknown       → ARP seen but not reserved/leased")
	fmt.Println("    mismatch      → ARP MAC differs from reserved/leased MAC")
	fmt.Println("    expired-lease → lease exists but expired")
	fmt.Println("    banned-mac    → MAC present in banned list")
}

/* ----------------- Internal implementation ----------------- */

func gather(cfg *config.Config, db *dhcpserver.LeaseDB, iface string, allIfaces bool, timeout time.Duration) ([]Entry, []Finding, error) {
	snap, err := readARPPlatform(cfg, iface, allIfaces, timeout)
	if err != nil {
		return nil, nil, err
	}

	_, subnet, _ := net.ParseCIDR(cfg.SubnetCIDR)
	serverIP := net.ParseIP(cfg.ServerIP).To4()
	gwIP := net.ParseIP(cfg.Gateway).To4()
	exc := map[string]struct{}{}
	for _, e := range cfg.Exclusions {
		if ip := net.ParseIP(e).To4(); ip != nil {
			exc[ip.String()] = struct{}{}
		}
	}
	resIP2MAC := map[string]string{}
	for m, r := range cfg.Reservations {
		resIP2MAC[r.IP] = strings.ToLower(m)
	}
	banned := dhcpserver.ParseBannedMACsEnv()
	for m := range cfg.BannedMACs {
		if nm, err := dhcpserver.CanonMAC(m); err == nil {
			banned[nm] = struct{}{}
		}
	}

	entries := make([]Entry, 0, len(snap))
	findings := []Finding{}
	now := time.Now().Unix()
	assume := int64(cfg.LeaseSeconds)

	isSelf := func(ip net.IP) bool { return ip.Equal(serverIP) || ip.Equal(gwIP) }

	for _, rec := range snap {
		ip := net.ParseIP(rec.IP).To4()
		if ip == nil || ip.IsMulticast() || ip.Equal(net.IPv4zero) || !subnet.Contains(ip) {
			continue
		}
		if _, ok := exc[ip.String()]; ok {
			entries = append(entries, Entry{IP: ip.String(), MAC: rec.MAC, Iface: rec.Iface, Source: rec.Source, State: "excluded"})
			continue
		}
		if isSelf(ip) {
			entries = append(entries, Entry{IP: ip.String(), MAC: rec.MAC, Iface: rec.Iface, Source: rec.Source, State: "self"})
			continue
		}

		state := "free"
		note := "-"
		var leaseMAC string

		if l, ok := db.FindByIP(ip.String()); ok {
			active := (l.Expiry > 0 && now <= l.Expiry) ||
				(l.Expiry == 0 && l.AllocatedAt > 0 && now <= l.AllocatedAt+assume)
			if active {
				state = "leased"
				leaseMAC = strings.ToLower(l.MAC)
			} else {
				note = "expired-lease"
			}
		}

		if rm, ok := resIP2MAC[ip.String()]; ok {
			state = "reserved"
			if !macEqual(rm, rec.MAC) {
				findings = append(findings, Finding{
					IP: ip.String(), MAC: rec.MAC, Iface: rec.Iface,
					Reason: "mac-mismatch", LeaseMAC: leaseMAC, ResMAC: rm,
				})
				note = "mismatch"
			}
		} else {
			if state != "leased" {
				findings = append(findings, Finding{
					IP: ip.String(), MAC: rec.MAC, Iface: rec.Iface,
					Reason: "unknown", LeaseMAC: leaseMAC, ResMAC: "",
				})
				note = "unknown"
			} else if leaseMAC != "" && !macEqual(leaseMAC, rec.MAC) {
				findings = append(findings, Finding{
					IP: ip.String(), MAC: rec.MAC, Iface: rec.Iface,
					Reason: "mac-mismatch", LeaseMAC: leaseMAC, ResMAC: "",
				})
				note = "mismatch"
			}
		}

		if nm, err := dhcpserver.CanonMAC(rec.MAC); err == nil {
			if _, bad := banned[nm]; bad {
				findings = append(findings, Finding{
					IP: ip.String(), MAC: rec.MAC, Iface: rec.Iface,
					Reason: "banned-mac", LeaseMAC: leaseMAC, ResMAC: resIP2MAC[ip.String()],
				})
				if note == "-" {
					note = "banned-mac"
				} else {
					note += ",banned-mac"
				}
			}
		}

		entries = append(entries, Entry{IP: ip.String(), MAC: rec.MAC, Iface: rec.Iface, Source: rec.Source, State: state, Note: note})
	}

	sort.Slice(entries, func(i, j int) bool {
		ki, kj := ipKey(entries[i].IP), ipKey(entries[j].IP)
		if ki == kj {
			return entries[i].Iface < entries[j].Iface
		}
		return ki < kj
	})
	return entries, findings, nil
}

func readARPPlatform(cfg *config.Config, iface string, allIfaces bool, timeout time.Duration) ([]Entry, error) {
	switch runtime.GOOS {
	case "linux":
		// Best-effort: if iface empty and not allIfaces, do nothing
		if !allIfaces && strings.TrimSpace(iface) == "" {
			return nil, fmt.Errorf("no interface specified")
		}
		targets := computeTargets(*cfg)
		entries := parseIPNeigh(iface, allIfaces)
		scanned := scanLinuxSweep(iface, allIfaces, targets, timeout)
		return mergeARP(entries, scanned), nil
	default:
		// macOS/Windows: parse arp -a cache only
		return parseArpDashA(iface, allIfaces)
	}
}

func computeTargets(cfg config.Config) []net.IP {
	_, subnet, err := net.ParseCIDR(cfg.SubnetCIDR)
	if err != nil {
		return nil
	}
	exc := map[string]struct{}{}
	for _, e := range cfg.Exclusions {
		if ip := net.ParseIP(e).To4(); ip != nil {
			exc[ip.String()] = struct{}{}
		}
	}
	serverIP := net.ParseIP(cfg.ServerIP).To4()
	gwIP := net.ParseIP(cfg.Gateway).To4()
	netIP := subnet.IP.Mask(subnet.Mask)
	bcast := dhcpserver.BroadcastAddr(subnet)

	skip := func(ip net.IP) bool {
		if ip == nil || !subnet.Contains(ip) {
			return true
		}
		if ip.Equal(serverIP) || ip.Equal(gwIP) || ip.Equal(netIP) || ip.Equal(bcast) {
			return true
		}
		if _, ok := exc[ip.String()]; ok {
			return true
		}
		return false
	}

	var out []net.IP
	for _, p := range cfg.Pools {
		start := dhcpserver.ParseIP4(p.Start)
		end := dhcpserver.ParseIP4(p.End)
		for ip := start; dhcpserver.IPToU32(ip) <= dhcpserver.IPToU32(end); ip = dhcpserver.IncIP(ip) {
			if !skip(ip) {
				out = append(out, append(net.IP(nil), ip...))
			}
		}
	}
	for _, r := range cfg.Reservations {
		ip := net.ParseIP(r.IP).To4()
		if !skip(ip) {
			out = append(out, append(net.IP(nil), ip...))
		}
	}
	return out
}

func parseIPNeigh(iface string, allIfaces bool) []Entry {
	cmd := exec.Command("ip", "-4", "neigh", "show")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}
	var res []Entry
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		// e.g., "192.168.1.10 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			continue
		}
		ip := f[0]
		ifaceName := ""
		mac := ""
		for i := 0; i < len(f)-1; i++ {
			if f[i] == "dev" && i+1 < len(f) {
				ifaceName = f[i+1]
			}
			if f[i] == "lladdr" && i+1 < len(f) {
				mac = f[i+1]
			}
		}
		if ifaceName == "" || mac == "" {
			continue
		}
		if !allIfaces && iface != "" && ifaceName != iface {
			continue
		}
		res = append(res, Entry{IP: ip, MAC: strings.ToLower(mac), Iface: ifaceName, Source: "cache"})
	}
	return res
}

func scanLinuxSweep(iface string, allIfaces bool, targets []net.IP, timeout time.Duration) []Entry {
	if len(targets) == 0 {
		return nil
	}
	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	for _, ip := range targets {
		ip := ip.String()
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			_ = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", int(timeout.Seconds())), ip).Run()
		}()
	}
	wg.Wait()
	return parseIPNeigh(iface, allIfaces)
}

// macOS/Windows cache reader with iface filtering on macOS and tolerant Windows parsing
func parseArpDashA(iface string, allIfaces bool) ([]Entry, error) {
	cmd := exec.Command("arp", "-a")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("arp -a: %v", err)
	}
	var res []Entry

	goos := runtime.GOOS
	sc := bufio.NewScanner(bytes.NewReader(out))

	// Windows: track current "Interface:" header lines
	currentWinIface := "" // we will stuff this in Iface to group entries

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		// Windows header line example:
		// Interface: 192.168.1.5 --- 0x17
		if goos == "windows" && strings.HasPrefix(line, "Interface:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				currentWinIface = fields[1]
			} else {
				currentWinIface = line
			}
			continue
		}

		// macOS example:
		// ? (192.168.1.10) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
		if strings.Contains(line, " on ") && strings.Contains(line, ") at ") {
			parts := strings.Split(line, ") at ")
			if len(parts) < 2 {
				continue
			}
			l := strings.LastIndex(parts[0], "(")
			if l == -1 {
				continue
			}
			ip := strings.TrimSpace(parts[0][l+1:])
			right := parts[1]

			fields := strings.Fields(right)
			if len(fields) == 0 {
				continue
			}
			mac := strings.ToLower(strings.ReplaceAll(fields[0], "-", ":"))

			ifaceName := ""
			if p := strings.Index(right, " on "); p != -1 {
				ifs := strings.Fields(right[p+4:])
				if len(ifs) > 0 {
					ifaceName = ifs[0]
				}
			}
			if !allIfaces && iface != "" && ifaceName != iface {
				continue
			}
			if net.ParseIP(ip) == nil || mac == "" {
				continue
			}
			res = append(res, Entry{IP: ip, MAC: mac, Iface: ifaceName, Source: "cache"})
			continue
		}

		// Windows entry lines, e.g.:
		//   192.168.1.10          aa-bb-cc-dd-ee-ff     dynamic
		fs := strings.Fields(line)
		if goos == "windows" && len(fs) >= 2 && net.ParseIP(fs[0]) != nil {
			ip := fs[0]
			mac := strings.ToLower(strings.ReplaceAll(fs[1], "-", ":"))
			// cannot reliably map to NIC name here; use currentWinIface as a group tag
			res = append(res, Entry{IP: ip, MAC: mac, Iface: currentWinIface, Source: "cache"})
		}
	}
	return res, nil
}

func mergeARP(a, b []Entry) []Entry {
	m := map[string]Entry{}
	for _, e := range a {
		key := e.IP + "|" + e.MAC + "|" + e.Iface
		m[key] = e
	}
	for _, e := range b {
		key := e.IP + "|" + e.MAC + "|" + e.Iface
		m[key] = e
	}
	out := make([]Entry, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		ki, kj := ipKey(out[i].IP), ipKey(out[j].IP)
		if ki == kj {
			return out[i].Iface < out[j].Iface
		}
		return ki < kj
	})
	return out
}

func pingWarmup(targets []net.IP, timeout time.Duration) {
	if len(targets) == 0 {
		return
	}
	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	goos := runtime.GOOS

	for _, ip := range targets {
		ipStr := ip.String()
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			var cmd *exec.Cmd
			switch goos {
			case "windows":
				// -n 1 one echo; -w timeout in ms
				ms := int(timeout / time.Millisecond)
				if ms <= 0 {
					ms = 1000
				}
				cmd = exec.Command("ping", "-n", "1", "-w", fmt.Sprintf("%d", ms), ipStr)
			default:
				// macOS and others with BSD ping: -c 1 one echo
				cmd = exec.Command("ping", "-c", "1", ipStr)
			}
			_ = cmd.Run()
		}()
	}
	wg.Wait()
}

/* ----------------- Small helpers ----------------- */

func ipKey(s string) uint32 {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return ^uint32(0)
	}
	return dhcpserver.IPToU32(ip)
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

/* ----------------- tiny stdout adapter ----------------- */

// stdoutWriter lets tabwriter write to stdout without importing os in this file.
type stdoutWriter struct{}

func (stdoutWriter) Write(p []byte) (int, error) { return fmt.Print(string(p)) }

// pretty JSON helpers for debugging (unused, kept for future)
func _dumpJSON(v any) { b, _ := json.MarshalIndent(v, "", "  "); fmt.Println(string(b)) }
