package consoleui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type BrokerOptions struct {
	MaxLines int
}

type Broker struct {
	maxLines int

	counterMu  sync.Mutex
	counters   []*counterRule
	hlMu       sync.Mutex
	highlights []*highlightRule

	brokerMu   sync.Mutex
	brokerCli  map[*brokerClient]struct{}
	brokerRing [][]byte
	brokerHead int
	brokerSize int

	stateMu    sync.Mutex
	brokerOn   bool
	brokerLn   net.Listener
	brokerPath string
}

// brokerClient is a single attached viewer connected to the broker socket.
type brokerClient struct {
	conn net.Conn
	bw   *bufio.Writer
	ch   chan []byte // bounded queue (drop-oldest policy)
}

func NewBroker(opts BrokerOptions) *Broker {
	if opts.MaxLines <= 0 {
		opts.MaxLines = 10000
	}
	return &Broker{
		maxLines:   opts.MaxLines,
		brokerCli:  make(map[*brokerClient]struct{}),
		brokerRing: make([][]byte, opts.MaxLines),
		brokerSize: opts.MaxLines,
	}
}

func (b *Broker) Start() error {
	path, ln, err := listenFirstAvailable()
	if err != nil {
		return err
	}
	_ = os.Chmod(path, 0o600)

	b.stateMu.Lock()
	b.brokerOn = true
	b.brokerLn = ln
	b.brokerPath = path
	b.stateMu.Unlock()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				b.stateMu.Lock()
				on := b.brokerOn
				b.stateMu.Unlock()
				if !on {
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
	ln := b.brokerLn
	path := b.brokerPath
	b.brokerOn = false
	b.brokerLn = nil
	b.brokerPath = ""
	b.stateMu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	if path != "" {
		_ = os.Remove(path)
	}

	b.brokerMu.Lock()
	for cli := range b.brokerCli {
		_ = cli.bw.Flush()
		_ = cli.conn.Close()
		delete(b.brokerCli, cli)
	}
	b.brokerMu.Unlock()
}

func (b *Broker) Append(line string) {
	b.appendWithWhen(time.Now(), line)
}

func (b *Broker) Appendf(format string, args ...any) { b.Append(fmt.Sprintf(format, args...)) }

func (b *Broker) RegisterCounter(match string, caseSensitive bool, label string, windowSeconds int) {
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	b.counterMu.Lock()
	defer b.counterMu.Unlock()
	b.counters = append(b.counters, &counterRule{
		match:         match,
		caseSensitive: caseSensitive,
		label:         label,
		window:        time.Duration(windowSeconds) * time.Second,
	})
}

func (b *Broker) HighlightMap(match string, caseSensitive bool, style Style) {
	b.hlMu.Lock()
	defer b.hlMu.Unlock()
	b.highlights = append(b.highlights, &highlightRule{
		match:         match,
		caseSensitive: caseSensitive,
		style:         &style,
	})
}

func (b *Broker) appendWithWhen(when time.Time, line string) {
	ev := wireLine{Type: "line", TsUs: when.UnixMicro(), Text: line, Level: levelOf(line)}
	buf, _ := json.Marshal(ev)
	buf = append(buf, '\n')

	b.brokerEnqueue(buf)
	b.brokerBroadcast(buf)
}

func (b *Broker) snapshotMeta() wireMeta {
	b.counterMu.Lock()
	counters := make([]*counterRule, len(b.counters))
	copy(counters, b.counters)
	b.counterMu.Unlock()

	b.hlMu.Lock()
	highlights := make([]*highlightRule, len(b.highlights))
	copy(highlights, b.highlights)
	b.hlMu.Unlock()

	m := wireMeta{Type: "meta", MaxLines: b.maxLines}
	for _, c := range counters {
		m.Counters = append(m.Counters, wireCounter{
			Match:         c.match,
			CaseSensitive: c.caseSensitive,
			Label:         c.label,
			WindowS:       int(c.window / time.Second),
		})
	}
	for _, h := range highlights {
		if h.style != nil {
			cp := *h.style
			m.Highlights = append(m.Highlights, wireHighlight{
				Match:         h.match,
				CaseSensitive: h.caseSensitive,
				Style:         &cp,
			})
		}
	}
	return m
}

func (b *Broker) handleNewClient(conn net.Conn) {
	b.brokerMu.Lock()
	if len(b.brokerCli) >= 5 {
		b.brokerMu.Unlock()
		_ = conn.Close()
		return
	}
	cli := &brokerClient{
		conn: conn,
		bw:   bufio.NewWriterSize(conn, 64<<10),
		ch:   make(chan []byte, 512),
	}
	b.brokerCli[cli] = struct{}{}
	b.brokerMu.Unlock()

	go func() {
		defer func() {
			b.brokerMu.Lock()
			delete(b.brokerCli, cli)
			b.brokerMu.Unlock()
			_ = conn.Close()
		}()

		meta := b.snapshotMeta()
		if mb, err := json.Marshal(meta); err == nil {
			mb = append(mb, '\n')
			if err := b.safeSend(cli, mb); err != nil {
				return
			}
		}

		b.replayBuffered(cli)

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

func (b *Broker) replayBuffered(cli *brokerClient) {
	b.brokerMu.Lock()
	defer b.brokerMu.Unlock()
	for i := 0; i < b.brokerSize; i++ {
		idx := (b.brokerHead + i) % b.brokerSize
		if b.brokerRing[idx] != nil {
			_ = b.safeSend(cli, b.brokerRing[idx])
		}
	}
}

func (b *Broker) brokerEnqueue(buf []byte) {
	b.brokerMu.Lock()
	b.brokerRing[b.brokerHead] = buf
	b.brokerHead = (b.brokerHead + 1) % b.brokerSize
	b.brokerMu.Unlock()
}

func (b *Broker) brokerBroadcast(buf []byte) {
	b.brokerMu.Lock()
	defer b.brokerMu.Unlock()
	for cli := range b.brokerCli {
		if !b.trySend(cli, buf) {
			var dropped int
			for len(cli.ch) == cap(cli.ch) {
				<-cli.ch
				dropped++
			}
			_ = b.trySend(cli, buf)
			if dropped > 0 {
				n := wireNotice{Type: "notice", Text: fmt.Sprintf("[viewer lagged; dropped %d lines]", dropped)}
				nb, _ := json.Marshal(n)
				nb = append(nb, '\n')
				_ = b.trySend(cli, nb)
			}
		}
	}
}

func (b *Broker) trySend(cli *brokerClient, buf []byte) bool {
	select {
	case cli.ch <- buf:
		return true
	default:
		return false
	}
}

func (b *Broker) safeSend(cli *brokerClient, buf []byte) error {
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
