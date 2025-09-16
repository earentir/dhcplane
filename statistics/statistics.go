// Package statistics contains allocation counting, lease classification,
// whole-subnet detail building, and console rendering (tables / grid).
// It does not read files or environment variables; callers must provide:
//   - the live config.Config
//   - a LeaseIter to walk current leases without duplicating data
//   - predicates for declined IPs and banned MACs
package statistics

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"dhcplane/config"

	"github.com/logrusorgru/aurora"
)

/* ----------------- Public types & input shape ----------------- */

// LeaseLite is a lightweight row provided by the caller via LeaseIter.
type LeaseLite struct {
	IP          string
	MAC         string
	Hostname    string
	AllocatedAt int64 // epoch seconds
	Expiry      int64 // epoch seconds
}

// LeaseView is the compact row shape for simple lists (current/expiring/expired).
type LeaseView struct {
	IP          string
	MAC         string
	Hostname    string
	AllocatedAt int64 // epoch seconds
	Expiry      int64 // epoch seconds
}

// DetailRow is the unified row for the full subnet scan with Type.
type DetailRow struct {
	IP          string
	Type        string // leased | reserved | banned-mac | banned-ip | free | unused
	MAC         string
	Hostname    string
	AllocatedAt int64
	Expiry      int64
}

// LeaseIter lets the caller stream live leases without copying maps.
// The closure should hold appropriate locks while iterating.
type LeaseIter func(yield func(LeaseLite))

/* ----------------- Counting & classification ----------------- */

// CountAllocations returns allocation counts for multiple rolling windows.
func CountAllocations(iter LeaseIter, assumeLeaseDur time.Duration, now time.Time) (perMinute, perHour, perDay, perWeek, perMonth int) {
	n := now.Unix()
	w1 := n - 60
	w2 := n - 3600
	w3 := n - 24*3600
	w4 := n - 7*24*3600
	w5 := n - 30*24*3600

	iter(func(l LeaseLite) {
		alloc := deriveAllocEpoch(l.AllocatedAt, l.Expiry, assumeLeaseDur, n)
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
	})
	return
}

// ClassifyLeases splits leases into current, expiring (<= last 1/8), and expired.
// Sorting matches the original behavior: current/expiring by Expiry asc, expired by Expiry desc.
func ClassifyLeases(iter LeaseIter, assumeLeaseDur time.Duration, now time.Time) (curr, expiring, expired []LeaseView) {
	n := now.Unix()
	thresholdExpiring := int64(assumeLeaseDur.Seconds() / 8)

	iter(func(l LeaseLite) {
		alloc := deriveAllocEpoch(l.AllocatedAt, l.Expiry, assumeLeaseDur, n)
		rem := l.Expiry - n

		v := LeaseView{
			IP:          l.IP,
			MAC:         l.MAC,
			Hostname:    l.Hostname,
			AllocatedAt: alloc, // match original behavior
			Expiry:      l.Expiry,
		}

		if rem <= 0 {
			expired = append(expired, v)
			return
		}
		if rem <= thresholdExpiring {
			expiring = append(expiring, v)
			return
		}
		curr = append(curr, v)
	})

	sort.Slice(curr, func(i, j int) bool { return curr[i].Expiry < curr[j].Expiry })
	sort.Slice(expiring, func(i, j int) bool { return expiring[i].Expiry < expiring[j].Expiry })
	sort.Slice(expired, func(i, j int) bool { return expired[i].Expiry > expired[j].Expiry })
	return
}

/* ----------------- Detail rows (full subnet walk) ----------------- */

// BuildDetailRows walks the whole host range and classifies every IP.
// Types: "leased", "reserved", "banned-mac", "banned-ip", "free" (in pools), "unused" (outside pools).
// It fills MAC/Hostname/AllocatedAt/Expiry when available (leased rows).
func BuildDetailRows(
	cfg config.Config,
	iter LeaseIter,
	isDeclined func(string) bool,
	isBannedMAC func(string) bool,
	now time.Time,
) ([]DetailRow, error) {

	_, ipnet, err := net.ParseCIDR(cfg.SubnetCIDR)
	if err != nil {
		return nil, fmt.Errorf("bad subnet_cidr %q: %w", cfg.SubnetCIDR, err)
	}
	network := ipnet.IP.Mask(ipnet.Mask).To4()
	if network == nil {
		return nil, fmt.Errorf("subnet %s is not IPv4", cfg.SubnetCIDR)
	}
	bcast := broadcastAddr(ipnet)
	first := incIP(network)
	last := u32ToIP(ipToU32(bcast) - 1)

	// Precompute pool ranges
	type urange struct{ a, b uint32 }
	var pools []urange
	for _, p := range cfg.Pools {
		start := net.ParseIP(strings.TrimSpace(p.Start)).To4()
		end := net.ParseIP(strings.TrimSpace(p.End)).To4()
		if start == nil || end == nil {
			continue
		}
		as := ipToU32(start)
		be := ipToU32(end)
		if be < as {
			as, be = be, as
		}
		pools = append(pools, urange{a: as, b: be})
	}
	inPools := func(u uint32) bool {
		for _, r := range pools {
			if u >= r.a && u <= r.b {
				return true
			}
		}
		return false
	}

	// Active leases (unexpired)
	active := make(map[string]LeaseLite)
	activeBanned := make(map[string]bool)
	nsec := now.Unix()

	iter(func(l LeaseLite) {
		if nsec <= l.Expiry {
			active[l.IP] = l
			if isBannedMAC != nil && isBannedMAC(l.MAC) {
				activeBanned[l.IP] = true
			}
		}
	})

	// Exclusions
	excluded := make(map[string]struct{})
	for _, e := range cfg.Exclusions {
		if ip := net.ParseIP(strings.TrimSpace(e)).To4(); ip != nil {
			excluded[ip.String()] = struct{}{}
		}
	}

	// Reservations (map IP -> MAC as stored; assume cfg may already be normalized via validation step)
	reservedIPs := make(map[string]struct{})
	reservedIPToMAC := make(map[string]string)
	for macKey, r := range cfg.Reservations {
		if ip := net.ParseIP(strings.TrimSpace(r.IP)).To4(); ip != nil {
			s := ip.String()
			reservedIPs[s] = struct{}{}
			reservedIPToMAC[s] = macKey
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

	rows := make([]DetailRow, 0, int(ipToU32(last)-ipToU32(first)+1))
	for u := ipToU32(first); u <= ipToU32(last); u++ {
		ip := u32ToIP(u).To4()
		s := ip.String()

		_, isEx := excluded[s]
		_, isRes := reservedIPs[s]
		resMAC := reservedIPToMAC[s]
		isDec := false
		if isDeclined != nil {
			isDec = isDeclined(s)
		}
		isSpecial := (serverIP != nil && ip.Equal(serverIP)) ||
			(gatewayIP != nil && ip.Equal(gatewayIP)) ||
			ip.Equal(network) || ip.Equal(bcast)
		inPool := inPools(u)

		if l, ok := active[s]; ok {
			if activeBanned[s] {
				rows = append(rows, DetailRow{
					IP: s, Type: "banned-mac", MAC: l.MAC, Hostname: l.Hostname,
					AllocatedAt: l.AllocatedAt, Expiry: l.Expiry,
				})
				continue
			}
			rows = append(rows, DetailRow{
				IP: s, Type: "leased", MAC: l.MAC, Hostname: l.Hostname,
				AllocatedAt: l.AllocatedAt, Expiry: l.Expiry,
			})
			continue
		}

		switch {
		case isSpecial || isEx || isDec:
			rows = append(rows, DetailRow{IP: s, Type: "banned-ip"})
		case isRes:
			rows = append(rows, DetailRow{IP: s, Type: "reserved", MAC: resMAC})
		case !inPool:
			rows = append(rows, DetailRow{IP: s, Type: "unused"})
		default:
			rows = append(rows, DetailRow{IP: s, Type: "free"})
		}
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].IP < rows[j].IP })
	return rows, nil
}

/* ----------------- Rendering ----------------- */

// PrintLeaseTable prints a table for the given rows and includes formatted timing.
func PrintLeaseTable(title string, rows []LeaseView, assumeLeaseDur time.Duration, now time.Time) {
	if len(rows) == 0 {
		fmt.Printf("\n%s: (none)\n", title)
		return
	}
	fmt.Printf("\n%s:\n", title)
	fmt.Printf("%-16s  %-17s  %-19s  %-10s  %-10s  %s\n",
		"IP", "MAC", "AllocatedAt", "Elapsed", "Remaining", "Hostname")

	nsec := now.Unix()
	for _, v := range rows {
		alloc := deriveAllocEpoch(v.AllocatedAt, v.Expiry, assumeLeaseDur, nsec)
		elapsedSecs := nsec - alloc
		if elapsedSecs < 0 {
			elapsedSecs = 0
		}
		remainingSecs := v.Expiry - nsec
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

// PrintDetailsTable prints a single tabular view including Type.
// It hides "free" rows; for non-leased rows, timing columns are left blank.
func PrintDetailsTable(title string, rows []DetailRow, assumeLeaseDur time.Duration, now time.Time) {
	// Filter out "free"
	filtered := make([]DetailRow, 0, len(rows))
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

	nsec := now.Unix()
	for _, r := range filtered {
		var alloc, elapsed, remaining int64
		var allocStr, elapsedStr, remainStr string

		if r.AllocatedAt > 0 || r.Expiry > 0 {
			alloc = deriveAllocEpoch(r.AllocatedAt, r.Expiry, assumeLeaseDur, nsec)
			elapsed = nsec - alloc
			if elapsed < 0 {
				elapsed = 0
			}
			remaining = r.Expiry - nsec
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

// DrawSubnetGrid renders the entire IPv4 subnet (host range only) as a colour grid:
//
//	red       █ = leased (unexpired; from leases)
//	brown     █ = reserved/fixed (from config.reservations; only if not actively leased)
//	dark gray █ = banned/unusable IPs (exclusions, network/broadcast/server/gateway, declined)
//	light gray█ = banned MAC leases (active leases owned by banned MACs)
//	green     █ = free host IP inside the configured pools
//	cyan      █ = unused host IP outside all configured pools
func DrawSubnetGrid(
	cfg config.Config,
	iter LeaseIter,
	isDeclined func(string) bool,
	isBannedMAC func(string) bool,
	columns int,
	now time.Time,
) error {
	if columns <= 0 {
		columns = 25
	}

	blkLeased := aurora.Red("█")
	blkReserved := aurora.Brown("█")
	blkBannedIP := aurora.Gray(8, "█")   // dark gray
	blkBannedMAC := aurora.Gray(14, "█") // light gray
	blkFree := aurora.Green("█")
	blkUnused := aurora.Cyan("█")

	_, ipnet, err := net.ParseCIDR(cfg.SubnetCIDR)
	if err != nil {
		return fmt.Errorf("bad subnet_cidr %q: %w", cfg.SubnetCIDR, err)
	}
	network := ipnet.IP.Mask(ipnet.Mask).To4()
	if network == nil {
		return fmt.Errorf("subnet %s is not IPv4", cfg.SubnetCIDR)
	}
	bcast := broadcastAddr(ipnet)
	first := incIP(network)
	last := u32ToIP(ipToU32(bcast) - 1)

	// Precompute pool ranges
	type urange struct{ a, b uint32 }
	var pools []urange
	for _, p := range cfg.Pools {
		start := net.ParseIP(strings.TrimSpace(p.Start)).To4()
		end := net.ParseIP(strings.TrimSpace(p.End)).To4()
		if start == nil || end == nil {
			continue
		}
		as := ipToU32(start)
		be := ipToU32(end)
		if be < as {
			as, be = be, as
		}
		pools = append(pools, urange{a: as, b: be})
	}
	inPools := func(u uint32) bool {
		for _, r := range pools {
			if u >= r.a && u <= r.b {
				return true
			}
		}
		return false
	}

	// Active leases and banned-mac markings
	active := make(map[string]LeaseLite)
	activeBanned := make(map[string]bool)
	nsec := now.Unix()

	iter(func(l LeaseLite) {
		if nsec <= l.Expiry {
			active[l.IP] = l
			if isBannedMAC != nil && isBannedMAC(l.MAC) {
				activeBanned[l.IP] = true
			}
		}
	})

	// Exclusions
	excluded := make(map[string]struct{})
	for _, e := range cfg.Exclusions {
		if ip := net.ParseIP(strings.TrimSpace(e)).To4(); ip != nil {
			excluded[ip.String()] = struct{}{}
		}
	}

	// Reservations (IP -> MAC display)
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

	// Counters for legend
	var countLeased, countReserved, countBannedMAC, countBannedIP, countFree, countUnused int

	fmt.Println()
	fmt.Printf("Subnet usage grid (%s):\n\n", cfg.SubnetCIDR)

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
		isDec := false
		if isDeclined != nil {
			isDec = isDeclined(s)
		}
		_, leased := active[s]
		isActiveBanned := activeBanned[s]
		isSpecial := (serverIP != nil && ip.Equal(serverIP)) ||
			(gatewayIP != nil && ip.Equal(gatewayIP)) ||
			ip.Equal(network) || ip.Equal(bcast)
		inPool := inPools(curU)

		// Priority: banned MAC leases → banned/excluded IPs → leased → reserved → unused → free
		switch {
		case isActiveBanned:
			fmt.Print(blkBannedMAC, " ")
			countBannedMAC++
		case isSpecial || isExcluded || isDec:
			fmt.Print(blkBannedIP, " ")
			countBannedIP++
		case leased:
			fmt.Print(blkLeased, " ")
			countLeased++
		case isReserved:
			fmt.Print(blkReserved, " ")
			countReserved++
		case !inPool:
			fmt.Print(blkUnused, " ")
			countUnused++
		default:
			fmt.Print(blkFree, " ")
			countFree++
		}

		col++
		if col >= columns {
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
		blkFree, " = free in pools (", countFree, ")  ",
		blkUnused, " = unused (not in pools) (", countUnused, ")",
	)
	fmt.Println()
	return nil
}

/* ----------------- Local helpers (no external deps) ----------------- */

func ipToU32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v4)
}

func u32ToIP(v uint32) net.IP {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return net.IP(b[:]) // 4-byte slice (safe for To4/indexing)
}

func incIP(ip net.IP) net.IP { return u32ToIP(ipToU32(ip) + 1) }

func broadcastAddr(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	mask := net.IP(n.Mask).To4()
	var b [4]byte
	for i := 0; i < 4; i++ {
		b[i] = ip[i] | ^mask[i]
	}
	return net.IP(b[:])
}

// deriveAllocEpoch matches the original logic:
// if AllocatedAt missing, derive from Expiry and assumed duration (clamped to now).
func deriveAllocEpoch(alloc int64, expiry int64, assumeLeaseDur time.Duration, now int64) int64 {
	if alloc <= 0 || alloc > now {
		if expiry > 0 {
			alloc = expiry - int64(assumeLeaseDur.Seconds())
			if alloc > now {
				alloc = now
			}
		} else {
			alloc = now
		}
	}
	return alloc
}

func formatEpoch(ts int64) string {
	if ts <= 0 {
		return ""
	}
	t := time.Unix(ts, 0).Local()
	return t.Format("2006/01/02 15:04:05")
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
