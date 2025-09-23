# dhcplane
![dhcplane](https://github.com/user-attachments/assets/9ce25e91-fa42-427c-bfe3-c76e0b3198c1)

A fast, single-binary **DHCPv4 server** written in Go (built on `insomniacslk/dhcp`) with:

- JSON configuration (strictly validated; shows line/column on errors)
- Address pools, exclusions, reservations (with notes & metadata)
- Sticky leases, optional compaction, and tolerant migration of older lease formats
- Per-device overrides (DNS/TFTP/Bootfile)
- Classless static routes (121), optional mirror to 249, custom vendor option 43 payloads
- Live config reload (watcher + `SIGHUP`)
- Banned MAC handling (from config and/or env var)
- Rich CLI: run server, view leases, stats, full subnet grid, config checking, config management (add/remove), and reload
- Clear logging (file and/or console), PID file, graceful shutdown

---

## Table of contents

- [Quick start](#quick-start)
- [Build](#build)
- [Why root or CAP_NET_BIND_SERVICE?](#why-root-or-cap_net_bind_service)
- [Configuration](#configuration)
  - [Full schema](#full-schema)
  - [Example `config.json`](#example-configjson)
  - [Reservations format (with metadata)](#reservations-format-with-metadata)
  - [Banned MACs](#banned-macs)
  - [Per-device overrides](#per-device-overrides)
  - [Static routes](#static-routes)
  - [Vendor option 43](#vendor-option-43)
- [Leases DB](#leases-db)
  - [Format](#format)
  - [Backwards-compatible loading](#backwards-compatible-loading)
  - [Sticky window & compaction](#sticky-window--compaction)
- [Running](#running)
  - [Examples](#examples)
- [Commands](#commands)
  - [`serve`](#serve)
  - [`leases`](#leases)
  - [`stats`](#stats)
  - [`check`](#check)
  - [`reload`](#reload)
  - [`manage add/remove`](#manage-addremove)
- [Flags](#flags)
- [Environment variables](#environment-variables)
- [Signals & lifecycle](#signals--lifecycle)
- [Logging](#logging)
- [Security notes](#security-notes)
- [Appendix: IP selection policy](#appendix-ip-selection-policy-summary)

---

## Quick start

```bash
# 1) Build
go build -o dhcplane .

# 2) Prepare config and empty lease DB
cp config.example.json config.json
echo '{"by_ip":{},"by_mac":{}}' > leases.json

# 3) Allow binding to UDP:67 without root (Linux)
sudo setcap 'cap_net_bind_service=+ep' "$(pwd)/dhcplane"

# 4) Run
./dhcplane serve --console
```

> Tip: add `--console` to expose the interactive console socket while still seeing logs on stdout/stderr.

---

## Build

Requires Go 1.21+.

```bash
go build -o dhcplane .
```

Binary is self-contained; no external services needed.

---

## Why root or `CAP_NET_BIND_SERVICE`?

DHCPv4 servers listen on UDP port **67** (privileged). Options:

- Run as root, **or**
- Grant the binary capability (Linux):

```bash
sudo setcap 'cap_net_bind_service=+ep' /path/to/dhcplane
```

This attaches to that specific binary. **Recompiling creates a new file**, so you must re-apply `setcap` to the new binary path.

---

## Configuration

The server loads a strict JSON file (unknown fields are rejected). On `serve` startup and on every reload/watch event, config is validated.

### Full schema

```json
{
  "interface": "eth0",
  "server_ip": "192.168.178.1",
  "subnet_cidr": "192.168.178.0/24",
  "gateway": "192.168.178.1",
  "compact_on_load": false,
  "dns": ["1.1.1.1", "9.9.9.9"],
  "domain": "lan",
  "lease_db_path": "leases.json",
  "pid_file": "dhcplane.pid",
  "lease_seconds": 86400,
  "lease_sticky_seconds": 86400,
  "auto_reload": true,

  "pools": [
    {"start": "192.168.178.50", "end": "192.168.178.199"}
  ],
  "exclusions": ["192.168.178.100"],

  "reservations": {
    "aa:bb:cc:dd:ee:ff": {
      "ip": "192.168.178.10",
      "note": "laser printer",
      "first_seen": 1725550000,
      "equipment_type": "Printer",
      "manufacturer": "HP",
      "management_type": "web",
      "management_interface": "http://192.168.178.10"
    }
  },

  "ntp": ["192.168.178.1"],
  "mtu": 1500,
  "tftp_server_name": "192.168.178.2",
  "bootfile_name": "pxelinux.0",
  "wpad_url": "http://wpad.lan/wpad.dat",
  "wins": ["192.168.178.3"],

  "domain_search": ["lan", "corp.lan"],
  "static_routes": [
    {"cidr": "10.10.0.0/16", "gateway": "192.168.178.254"}
  ],
  "mirror_routes_to_249": true,
  "vendor_specific_43_hex": "01:04:de:ad:be:ef",

  "device_overrides": {
    "00-11-22-33-44-55": {
      "dns": ["192.168.178.53"],
      "tftp_server_name": "192.168.178.2",
      "bootfile_name": "special.efi"
    }
  },

  "banned_macs": {
    "dc:ed:83:f3:68:5b": {
      "first_seen": 1725550000,
      "note": "guest device blocked",
      "equipment_type": "Gateway",
      "manufacturer": "Unknown"
    }
  },

  "equipment_types": ["Switch","Router","AP","Modem","Gateway","Printer"],
  "management_types": ["ssh","web","telnet","serial","console"]
}
```

Defaults:
Defaults:

- `lease_seconds`: `86400` (24h) if ≤ 0
- `lease_sticky_seconds`: `86400` (sticky window) if ≤ 0
- At least one pool is required
- Unknown fields are rejected (strict mode)
- `lease_db_path`: defaults to `leases.json` when omitted
- `pid_file`: defaults to `dhcplane.pid` when omitted

### Example config

- `lease_seconds`: `86400` (24h) if ≤ 0
- `lease_sticky_seconds`: `86400` (sticky window) if ≤ 0
- At least one pool is required
- Unknown fields are rejected (strict mode)

### Example `config.json`

```json
{
  "interface": "",
  "server_ip": "192.168.178.1",
  "subnet_cidr": "192.168.178.0/24",
  "gateway": "192.168.178.1",
  "dns": ["1.1.1.1","9.9.9.9"],
  "lease_seconds": 86400,
  "lease_sticky_seconds": 86400,
  "auto_reload": true,
  "pools": [
    {"start":"192.168.178.50","end":"192.168.178.199"}
  ],
  "exclusions": ["192.168.178.100"],
  "reservations": {
    "aa:bb:cc:dd:ee:ff":{"ip":"192.168.178.10","note":"printer"}
  },
  "domain": "lan",
  "ntp": ["192.168.178.1"],
  "mtu": 1500,
  "tftp_server_name": "192.168.178.2",
  "bootfile_name": "pxelinux.0",
  "wpad_url": "",
  "wins": [],
  "domain_search": ["lan"],
  "static_routes": [],
  "mirror_routes_to_249": false,
  "vendor_specific_43_hex": "",
  "device_overrides": {},
  "banned_macs": {}
}
```

### Reservations format (with metadata)

`reservations` keys are MACs (accept `aa:bb:...`, `aa-bb-...`, or `aabb...`). Values:

```json
{
  "ip": "192.168.178.10",
  "note": "human note",
  "first_seen": 1725550000,
  "equipment_type": "Switch",
  "manufacturer": "Ubiquiti",
  "management_type": "web",
  "management_interface": "https://192.168.178.10"
}
```

> Backwards compatible: the legacy `{"mac":"ip"}` style is also accepted on load.

### Banned MACs

Banned MACs can be declared in config under `banned_macs` (with optional metadata), **and/or** via env var `dhcplane_BANNED_MACS` (comma/space/newline-separated list, any delimiter style, e.g. `aabbccddeeff`, `aa:bb:...`, `aa-bb-...`).
Banned MACs:

- Are logged on contact
- Receive a NAK on DHCP REQUEST when the config’s `authoritative` flag is true (default)
- Are marked in the **grid** and **details** outputs

### Per-device overrides

`device_overrides` lets you override **only**:

- DNS servers (option 6)
- TFTP server name (66)
- Bootfile name (67)

Global config remains in effect for everything else.

### Static routes

`static_routes` becomes Option 121 (RFC 3442). If `mirror_routes_to_249` is true, the same payload is also sent as proprietary Microsoft option 249.

```json
"static_routes": [
  {"cidr":"10.10.0.0/16","gateway":"192.168.178.254"}
]
```

### Vendor option 43

Provide a raw hex payload in many styles: `"01:04:de:ad:be:ef"`, `"01 04 de ad be ef"`, `"hex:0104deadbeef"`, `"0x01,0x04,0xDE..."`.

---

## Leases DB

### Format

`leases.json` is a simple map persisted by the server:

```json
{
  "by_ip": {
    "192.168.178.100": {
      "mac": "aa:bb:cc:dd:ee:ff",
      "ip": "192.168.178.100",
      "hostname": "host-name",
      "allocated_at": 1725551111,
      "expiry": 1725637511,
      "first_seen": 1725550000
    }
  },
  "by_mac": {
    "aa:bb:cc:dd:ee:ff": { /* same structure as above */ }
  }
}
```

All timestamps are **epoch seconds**. Formatting to local time happens only when printing.

### Backwards-compatible loading

If you used a prior version that stored RFC3339 timestamps, the server will **tolerantly** read and coerce them to epoch on load.

### Sticky window & compaction

- **Sticky window** (`lease_sticky_seconds`): influences IP selection so a device tends to get the same address again (even after expiry within the sticky window), as long as it’s safe.
- **Compaction** removes leases that expired longer than the sticky window ago. If `compact_on_load` is true, compaction runs at startup and on reload.

---

## Running

The server listens on UDP:67 on the configured interface (or all interfaces if empty). It is **authoritative** by default (sends NAKs on invalid requests).

### Examples

Serve with console echo and file log:

```bash
./dhcplane serve \
  --config ./config.json \
  --console
```

Check the config:

```bash
./dhcplane check -c ./config.json
```

Live reload via PID file (default `dhcplane.pid`):

```bash
./dhcplane reload -c ./config.json
```

List current leases (pretty JSON):

```bash
./dhcplane leases -c ./config.json
```

Stats & tables:

```bash
# Summary + leased/expiring/expired tables
./dhcplane stats -c ./config.json

# Full subnet table (hides free addresses) with Type column
./dhcplane stats -c ./config.json --details

# colour grid of the whole subnet
./dhcplane stats -c ./config.json --grid
```

Add or update a reservation:

```bash
# MAC, IP, then an optional free-form note
./dhcplane manage add dc:ed:83:f3:68:5b 192.168.178.55 "kitchen display"
```

Remove a reservation:

```bash
./dhcplane manage remove dc:ed:83:f3:68:5b
```

---

## Commands

### `serve`

Start the DHCP server. Validates config before binding. Creates/updates a PID file. Supports `SIGHUP` reload and graceful termination.

Key features at runtime:

- Sticky leases
- Reservation enforcement over leases
- Per-device overrides (DNS/TFTP/Bootfile)
- Vendor option 43
- Routes 121 (+249 mirror)
- WPAD (252), WINS (44), MTU (26), Domain(15), Domain search (119)
- Auto-reload (filesystem watcher) when `auto_reload` is true

### `leases`

Print leases from `leases.json` as a JSON array with formatted timestamps (local time), including `AllocatedAt`, `Expiry`, and `FirstSeen`.

### `stats`

Print allocation rates for the last 1m/1h/24h/7d/30d and lease groupings.

Flags:

- `--details`: show a unified table across the whole subnet with Type classification:
  - `leased` (active leases)
  - `reserved` (IP is fixed in config, not currently leased)
  - `banned-mac` (active lease owned by a banned MAC)
  - `banned-ip` (network/broadcast/server/gateway/exclusions/declined quarantine)
  - `free` (hidden in details output)
- `--grid`: render a colour block grid (green free, red leased, brown reserved, light-gray banned-mac, dark-gray banned/excluded IPs). Requires a colour terminal.

### `check`

Strictly validate `config.json`. Unknown fields, wrong types, etc., return precise line/column.

### `reload`

Reads PID from `pid_file` in the config and sends `SIGHUP`. Before signaling, re-validates the config and refuses to reload if invalid.

### `manage add/remove`

Manipulate `reservations` in `config.json`:

- `manage add <mac> <ip> [note...]`
  - Validates MAC and IPv4
  - Warns if IP is out of subnet or currently leased to a different MAC
  - Inserts/updates with `first_seen` (epoch) if missing, preserves any existing metadata
- `manage remove <mac>`
  - Deletes the reservation if present

Edits are written atomically via `config.json.tmp` → rename.

---

## Flags

Global flags (apply to all commands unless noted):

- `-c, --config string`
  Path to JSON config (default `config.json`)
- `--console`
  Serve the interactive console over UNIX socket (logs always print to stdout/stderr)

Command-specific flags:

- `stats --details`
- `stats --grid`
- `console attach --transparent`

---

## Environment variables

- `dhcplane_BANNED_MACS`
  Extra banned MACs; separated by comma/space/newline. Accepts `aa:bb:...`, `aa-bb-...`, or `aabb...`.

- `COLUMNS`
  If set, used as terminal width hint for grid layout.

---

## Signals & lifecycle

- `SIGHUP`
  Reload config. If `compact_on_load` is true, compaction runs post-reload.
- `SIGINT`/`SIGTERM`
  Graceful shutdown: server stops, leases DB is saved, watcher/log files closed.

When `auto_reload` is true, the process also watches the config file’s directory and applies changes shortly after writes (with validation and first-seen stamping for reservations/banned MACs where missing).

---

## Logging

- File logger is created using the `logging` section (default `dhcplane.log`); logs are always mirrored to stdout/stderr.
- Internal errors are additionally printed to stderr in red for operator visibility.
- PID file is written at the `pid_file` path in the config.

Example log lines:

```log
START iface="" bind=0.0.0.0:67 server_ip=192.168.178.1 subnet=192.168.178.0/24 gateway=192.168.178.1 lease=24h0m0s sticky=24h0m0s
AUTO-RELOAD: watching ./config.json
DISCOVER from aa:bb:cc:dd:ee:ff hostname="printer" xid=0x12345678
OFFER aa:bb:cc:dd:ee:ff -> 192.168.178.100
ACK aa:bb:cc:dd:ee:ff <- 192.168.178.100 lease=24h0m0s (alloc=2025/09/05 20:40:01, exp=2025/09/06 20:40:01)
```

---

## Security notes

- Only enable `authoritative` in the config on networks where this server should NAK competing/invalid requests.
- Use `exclusions` to protect infrastructure IPs that are inside pools.
- Banned MACs are enforced at request time; keep in mind MAC spoofing is possible on L2.
- Consider running under a service account with only `cap_net_bind_service` capability if possible, not full root.
- Always validate `config.json` with `check` before deploying edits in production.

---

## Appendix: IP selection policy (summary)

1. **Reservation wins**: If the MAC has a reservation, use it (unless actively leased to a different MAC).
2. **Sticky preference**: If the MAC had a prior lease, try that IP again, subject to safety (in-subnet, not excluded/declined/reserved for someone else, not actively leased by another MAC).
3. **Brand-new** IPs: Prefer addresses never seen in the DB.
4. **Recycle expired**: If no new IPs, reuse expired, safe IPs (respecting reservations).
5. If none apply: pool exhausted → NAK (when authoritative) or silent failure.
