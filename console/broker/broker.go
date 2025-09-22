package broker

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"dhcplane/console"
)

type Options struct {
	Config console.Config
}

type Broker struct {
	cfg      console.Config
	metaBuf  []byte
	maxLines int

	ringMu   sync.Mutex
	clients  map[*client]struct{}
	ring     [][]byte
	head     int
	capacity int

	stateMu    sync.Mutex
	running    bool
	listener   net.Listener
	socketPath string
}

type client struct {
	conn net.Conn
	bw   *bufio.Writer
	ch   chan []byte
}

func New(opts Options) *Broker {
	cfg := console.Config{
		MaxLines:   opts.Config.MaxLines,
		Counters:   append([]console.CounterSpec(nil), opts.Config.Counters...),
		Highlights: make([]console.HighlightSpec, 0, len(opts.Config.Highlights)),
	}
	for _, h := range opts.Config.Highlights {
		cp := h
		if h.Style != nil {
			st := *h.Style
			cp.Style = &st
		}
		cfg.Highlights = append(cfg.Highlights, cp)
	}

	if cfg.MaxLines <= 0 {
		cfg.MaxLines = console.DefaultMaxLines
	}

	meta := console.MakeMeta(cfg)
	metaBytes, _ := json.Marshal(meta)
	metaBytes = append(metaBytes, '\n')

	size := cfg.EffectiveMaxLines()

	return &Broker{
		cfg:      cfg,
		metaBuf:  metaBytes,
		maxLines: size,
		clients:  make(map[*client]struct{}),
		ring:     make([][]byte, size),
		capacity: size,
	}
}

func (b *Broker) Start() error {
	path, ln, err := listenFirstAvailable()
	if err != nil {
		return err
	}
	_ = os.Chmod(path, 0o600)

	b.stateMu.Lock()
	b.running = true
	b.listener = ln
	b.socketPath = path
	b.stateMu.Unlock()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				b.stateMu.Lock()
				running := b.running
				b.stateMu.Unlock()
				if !running {
					return
				}
				continue
			}
			b.handleNewClient(c)
		}
	}()

	return nil
}

func (b *Broker) Stop() {
	b.stateMu.Lock()
	ln := b.listener
	path := b.socketPath
	b.running = false
	b.listener = nil
	b.socketPath = ""
	b.stateMu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	if path != "" {
		_ = os.Remove(path)
	}

	b.ringMu.Lock()
	for cli := range b.clients {
		_ = cli.bw.Flush()
		_ = cli.conn.Close()
		delete(b.clients, cli)
	}
	b.ringMu.Unlock()
}

func (b *Broker) Append(line string) {
	b.appendWithWhen(time.Now(), line)
}

func (b *Broker) Appendf(format string, args ...any) {
	b.Append(fmt.Sprintf(format, args...))
}

func (b *Broker) appendWithWhen(when time.Time, line string) {
	ev := console.Line{Type: "line", TsUs: when.UnixMicro(), Text: line, Level: console.LevelOf(line)}
	buf, _ := json.Marshal(ev)
	buf = append(buf, '\n')

	b.enqueue(buf)
	b.broadcast(buf)
}

func (b *Broker) handleNewClient(conn net.Conn) {
	b.ringMu.Lock()
	if len(b.clients) >= 5 {
		b.ringMu.Unlock()
		_ = conn.Close()
		return
	}
	cli := &client{
		conn: conn,
		bw:   bufio.NewWriterSize(conn, 64<<10),
		ch:   make(chan []byte, 512),
	}
	b.clients[cli] = struct{}{}
	b.ringMu.Unlock()

	go func() {
		defer func() {
			b.ringMu.Lock()
			delete(b.clients, cli)
			b.ringMu.Unlock()
			_ = conn.Close()
		}()

		if err := b.safeSend(cli, b.metaBuf); err != nil {
			return
		}

		b.replay(cli)

		for msg := range cli.ch {
			if _, err := cli.bw.Write(msg); err != nil {
				return
			}
			if err := cli.bw.Flush(); err != nil {
				return
			}
		}
	}()
}

func (b *Broker) replay(cli *client) {
	b.ringMu.Lock()
	defer b.ringMu.Unlock()
	for i := 0; i < b.capacity; i++ {
		idx := (b.head + i) % b.capacity
		if b.ring[idx] != nil {
			_ = b.safeSend(cli, b.ring[idx])
		}
	}
}

func (b *Broker) enqueue(buf []byte) {
	b.ringMu.Lock()
	b.ring[b.head] = buf
	b.head = (b.head + 1) % b.capacity
	b.ringMu.Unlock()
}

func (b *Broker) broadcast(buf []byte) {
	b.ringMu.Lock()
	defer b.ringMu.Unlock()
	for cli := range b.clients {
		if !b.trySend(cli, buf) {
			dropped := 0
			for len(cli.ch) == cap(cli.ch) {
				<-cli.ch
				dropped++
			}
			_ = b.trySend(cli, buf)
			if dropped > 0 {
				notice := console.Notice{Type: "notice", Text: fmt.Sprintf("[viewer lagged; dropped %d lines]", dropped)}
				nb, _ := json.Marshal(notice)
				nb = append(nb, '\n')
				_ = b.trySend(cli, nb)
			}
		}
	}
}

func (b *Broker) trySend(cli *client, buf []byte) bool {
	select {
	case cli.ch <- buf:
		return true
	default:
		return false
	}
}

func (b *Broker) safeSend(cli *client, buf []byte) error {
	select {
	case cli.ch <- buf:
		return nil
	default:
		<-cli.ch
		cli.ch <- buf
		return nil
	}
}

func listenFirstAvailable() (string, net.Listener, error) {
	candidates := []string{
		"/run/dhcplane/consoleui.sock",
		"/tmp/consoleui.sock",
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		candidates = append(candidates, filepath.Join(xdg, "dhcplane.sock"))
	}
	for _, p := range candidates {
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		_ = os.Remove(p)
		ln, err := net.Listen("unix", p)
		if err == nil {
			return p, ln, nil
		}
	}
	return "", nil, fmt.Errorf("console broker: no usable UNIX socket path")
}
