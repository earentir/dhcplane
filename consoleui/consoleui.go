// Package consoleui provides a generic console toolkit with a headless server broker
// and an interactive tview client used by `dhcplane console attach`.
package consoleui

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/spf13/cobra"
)

// Style defines a simple tview tag style: [FG:BG:ATTRS] ... [-:-:-]
// FG/BG accept named colors ("red") or hex ("#ff3366"); empty keeps current.
// Attrs is a compact string like "b", "bu", "i", "u", "d", "t".
type Style struct {
	FG    string
	BG    string
	Attrs string
}

// Options defines options for the console UI.
type Options struct {
	NoColour      bool
	MaxLines      int
	MouseEnabled  bool
	HelpExtra     []string
	OnExit        func(code int)
	DisableTopBar bool // false = show top bar (Title | Counters); true = legacy: no top bar
}

type counterRule struct {
	match         string
	caseSensitive bool
	label         string
	window        time.Duration
	// rolling timestamps (most recent kept)
	times []time.Time
}

type highlightRule struct {
	match         string
	caseSensitive bool
	// Either style or styler is used. If both are set, styler wins.
	style  *Style
	styler func(s string, noColour bool) string
}

// wireMeta is sent once to each newly attached client to transfer rules and limits.
type wireMeta struct {
	Type       string          `json:"type"` // "meta"
	MaxLines   int             `json:"max_lines"`
	Counters   []wireCounter   `json:"counters"`
	Highlights []wireHighlight `json:"highlights"`
}
type wireCounter struct {
	Match         string `json:"match"`
	CaseSensitive bool   `json:"case_sensitive"`
	Label         string `json:"label"`
	WindowS       int    `json:"window_s"`
}
type wireHighlight struct {
	Match         string `json:"match"`
	CaseSensitive bool   `json:"case_sensitive"`
	Style         *Style `json:"style,omitempty"`
}

// wireLine carries a single console line with its original timestamp and a coarse level.
type wireLine struct {
	Type  string `json:"type"`  // "line"
	TsUs  int64  `json:"ts_us"` // original time on server (microseconds)
	Text  string `json:"text"`  // exact line as appended
	Level string `json:"level"` // "info" | "error"
}

// wireNotice informs a slow client that some lines were dropped locally.
type wireNotice struct {
	Type string `json:"type"` // "notice"
	Text string `json:"text"`
}

// UI represents the interactive client UI.
type UI struct {
	app        *tview.Application
	logView    *tview.TextView
	inputField *tview.InputField
	statusText *tview.TextView
	topSep     *tview.TextView
	bottomSep  *tview.TextView
	topBar     *tview.TextView // top bar with Title (left) | Counters (right)
	root       tview.Primitive
	modal      tview.Primitive
	prevFocus  tview.Primitive

	// state
	mu                  sync.Mutex
	lines               []string
	maxLines            int
	filter              string
	filterActive        bool
	filterCaseSensitive bool
	paused              bool
	mouseOn             bool
	noColour            bool
	title               string
	helpExtra           []string
	onExit              func(int)
	topBarEnabled       bool // derived from !opts.DisableTopBar

	// rules
	counterMu  sync.Mutex
	counters   []*counterRule
	hlMu       sync.Mutex
	highlights []*highlightRule
}

// New creates a new console UI with the given options.
func New(opts Options) *UI {
	if opts.MaxLines <= 0 {
		opts.MaxLines = 10000
	}
	u := &UI{
		lines:         make([]string, 0, opts.MaxLines),
		maxLines:      opts.MaxLines,
		mouseOn:       opts.MouseEnabled,
		noColour:      opts.NoColour,
		helpExtra:     append([]string(nil), opts.HelpExtra...),
		topBarEnabled: !opts.DisableTopBar,
	}

	if opts.OnExit != nil {
		u.onExit = opts.OnExit
	} else {
		u.onExit = func(code int) {
			u.app.EnableMouse(false)
			u.app.Stop()
			go func() {
				time.Sleep(25 * time.Millisecond)
				os.Exit(code)
			}()
		}
	}

	u.app = tview.NewApplication()
	u.logView = tview.NewTextView().SetScrollable(true).SetWrap(false)
	u.inputField = tview.NewInputField().SetLabel("> ").SetFieldWidth(0)
	u.statusText = tview.NewTextView().SetWrap(false)
	u.topSep = tview.NewTextView().SetWrap(false)
	u.bottomSep = tview.NewTextView().SetWrap(false)
	u.topBar = tview.NewTextView().SetWrap(false)

	// colour mode for text views
	u.logView.SetDynamicColors(!u.noColour)
	u.statusText.SetDynamicColors(!u.noColour)
	u.topBar.SetDynamicColors(!u.noColour)

	// layout
	var root *tview.Flex
	if u.topBarEnabled {
		root = tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(u.topBar, 1, 0, false).
			AddItem(u.logView, 0, 1, false).
			AddItem(u.bottomSep, 1, 0, false).
			AddItem(
				tview.NewFlex().SetDirection(tview.FlexRow).
					AddItem(u.inputField, 1, 0, true).
					AddItem(u.statusText, 1, 0, false),
				2, 0, true)
	} else {
		root = tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(u.topSep, 1, 0, false).
			AddItem(u.logView, 0, 1, false).
			AddItem(u.bottomSep, 1, 0, false).
			AddItem(
				tview.NewFlex().SetDirection(tview.FlexRow).
					AddItem(u.inputField, 1, 0, true).
					AddItem(u.statusText, 1, 0, false),
				2, 0, true)
	}
	u.root = root

	// behavior
	u.bindKeys()
	u.app.EnableMouse(u.mouseOn)
	u.app.SetRoot(u.root, true)
	u.app.SetFocus(u.inputField)
	u.setLogSeparators(false) // input focused

	// Initial paint
	if u.topBarEnabled {
		u.updateTopBarDirect()
	}
	u.updateBottomBarDirect()

	return u
}

// SetTitle sets the title of the UI, shown in the help modal.
func (u *UI) SetTitle(s string) {
	u.mu.Lock()
	u.title = s
	u.mu.Unlock()
	if u.topBarEnabled {
		u.updateTopBarDirect()
	}
}

// Append appends a new line to the console UI (client side only).
func (u *UI) Append(line string) {
	u.appendWithWhen(time.Now(), line)
}

// Appendf is like Append but with formatting.
func (u *UI) Appendf(format string, args ...any) { u.Append(fmt.Sprintf(format, args...)) }

// RegisterCounter registers a counter with the given match string (substring),
// case sensitivity, label, and rolling window in seconds (default 60s if <=0).
// Each time a line is appended that contains the match string, the counter is
// incremented. The status bar shows the count of matches within the rolling window.
func (u *UI) RegisterCounter(match string, caseSensitive bool, label string, windowSeconds int) {
	if windowSeconds <= 0 {
		windowSeconds = 60
	}
	u.counterMu.Lock()
	defer u.counterMu.Unlock()
	u.counters = append(u.counters, &counterRule{
		match:         match,
		caseSensitive: caseSensitive,
		label:         label,
		window:        time.Duration(windowSeconds) * time.Second,
	})
}

// Tick increments the counter with the given label by one.
func (u *UI) Tick(label string) {
	now := time.Now()
	u.counterMu.Lock()
	defer u.counterMu.Unlock()
	for _, c := range u.counters {
		if c.label == label {
			c.times = append(c.times, now)
			break
		}
	}
	if u.topBarEnabled {
		u.updateTopBarDirect()
	}
}

// HighlightMap registers a highlight rule with the given match string (substring),
// case sensitivity, and style. Each time a line is appended, all registered
// highlight rules are applied in order (first-registered wins) to style matching
// substrings. If no style is given (empty), the match is ignored.
func (u *UI) HighlightMap(match string, caseSensitive bool, style Style) {
	u.hlMu.Lock()
	defer u.hlMu.Unlock()
	u.highlights = append(u.highlights, &highlightRule{
		match:         match,
		caseSensitive: caseSensitive,
		style:         &style,
	})
}

// HighlightMapFunc registers a rule with a custom styler.
// The styler is called with the matched substring and noColour flag.
func (u *UI) HighlightMapFunc(match string, caseSensitive bool, styler func(s string, noColour bool) string) {
	u.hlMu.Lock()
	defer u.hlMu.Unlock()
	u.highlights = append(u.highlights, &highlightRule{
		match:         match,
		caseSensitive: caseSensitive,
		styler:        styler,
	})
}

// MakeTagStyler returns a styler that wraps text with a tview tag [fg:bg:attrs]..[-:-:-].
// fg/bg can be named or hex; attrs is like "b", "bu", "i", "u", "d", "t".
func MakeTagStyler(fg, bg, attrs string) func(s string, noColour bool) string {
	return func(s string, noColour bool) string {
		if noColour || s == "" {
			return s
		}
		open := "[" + fg + ":" + bg + ":" + attrs + "]"
		return open + s + "[-:-:-]"
	}
}

// ---- internals ----

// appendWithWhen is the internal implementation for Append with a provided timestamp.
// Used by the client to preserve server-side timestamps for counters.
func (u *UI) appendWithWhen(when time.Time, line string) {
	u.mu.Lock()
	u.lines = append(u.lines, line)
	if len(u.lines) > u.maxLines {
		u.lines = u.lines[len(u.lines)-u.maxLines:]
	}
	paused := u.paused
	u.mu.Unlock()

	// counters: scan matchers quickly
	u.counterMu.Lock()
	if len(u.counters) > 0 {
		for _, cr := range u.counters {
			if cr.match == "" {
				continue
			}
			if cr.caseSensitive {
				if strings.Contains(line, cr.match) {
					cr.times = append(cr.times, when)
				}
			} else {
				if strings.Contains(strings.ToLower(line), strings.ToLower(cr.match)) {
					cr.times = append(cr.times, when)
				}
			}
		}
	}
	// prune old samples per counter
	for _, cr := range u.counters {
		if len(cr.times) == 0 {
			continue
		}
		cut := time.Now().Add(-cr.window)
		keep := cr.times[:0]
		for _, t := range cr.times {
			if t.After(cut) {
				keep = append(keep, t)
			}
		}
		cr.times = keep
	}
	u.counterMu.Unlock()

	u.Do(func() {
		if !paused {
			atBottom := u.atBottom()
			u.logView.Clear()
			for _, l := range u.filteredLines() {
				fmt.Fprintln(u.logView, u.styleLine(l))
			}
			if atBottom {
				u.logView.ScrollToEnd()
			}
		}
		if u.topBarEnabled {
			u.updateTopBarDirect()
		}
		u.updateBottomBarDirect() // toggles and keys
	})
}

// Do queues the given function to be executed in the UI event loop.
func (u *UI) Do(fn func()) {
	u.app.QueueUpdateDraw(fn)
}

func (u *UI) bindKeys() {
	u.inputField.SetChangedFunc(func(text string) {
		u.mu.Lock()
		if u.filterActive {
			u.filter = text
		}
		u.mu.Unlock()
		if u.filterActive {
			u.refreshDirect()
		}
	})

	u.inputField.SetDoneFunc(func(key tcell.Key) {
		switch key {
		case tcell.KeyEnter:
			u.mu.Lock()
			if u.filterActive {
				u.filterActive = false
			} else {
				u.filterActive = true
				u.filter = u.inputField.GetText()
			}
			u.mu.Unlock()
			u.refreshDirect()
			u.updateBottomBarDirect()
		case tcell.KeyEsc:
			u.mu.Lock()
			u.filterActive = false
			u.filter = ""
			u.inputField.SetText("")
			u.mu.Unlock()
			u.refreshDirect()
			u.updateBottomBarDirect()
		}
	})

	u.app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyTab:
			if u.app.GetFocus() == u.logView {
				u.app.SetFocus(u.inputField)
				u.setLogSeparators(false)
			} else {
				u.app.SetFocus(u.logView)
				u.setLogSeparators(true)
			}
			return nil
		case tcell.KeyBacktab:
			if u.app.GetFocus() == u.inputField {
				u.app.SetFocus(u.logView)
				u.setLogSeparators(true)
			} else {
				u.app.SetFocus(u.inputField)
				u.setLogSeparators(false)
			}
			return nil
		case tcell.KeyCtrlC:
			u.onExit(130)
			return nil
		case tcell.KeyRune:
			switch ev.Rune() {
			case 'q', 'Q':
				if u.app.GetFocus() != u.inputField {
					u.onExit(0)
					return nil
				}
				return ev
			case 'm':
				if u.app.GetFocus() == u.logView {
					u.mu.Lock()
					u.mouseOn = !u.mouseOn
					on := u.mouseOn
					u.mu.Unlock()
					u.app.EnableMouse(on)
					u.updateBottomBarDirect() // <- reflect mouse toggle
					return nil
				}
			case '?':
				if u.app.GetFocus() == u.logView {
					u.showHelpModal()
					return nil
				}
			case ' ':
				if u.app.GetFocus() != u.inputField {
					u.mu.Lock()
					u.paused = !u.paused
					u.mu.Unlock()
					u.updateBottomBarDirect() // <- reflect running/pause
					return nil
				}
			case 'c':
				if u.app.GetFocus() != u.inputField {
					u.mu.Lock()
					u.filterCaseSensitive = !u.filterCaseSensitive
					u.mu.Unlock()
					u.refreshDirect()
					u.updateBottomBarDirect() // <- reflect case toggle
					return nil
				}
			}
		case tcell.KeyUp:
			if u.app.GetFocus() == u.logView {
				row, col := u.logView.GetScrollOffset()
				if row > 0 {
					u.logView.ScrollTo(row-1, col)
				}
				return nil
			}
		case tcell.KeyDown:
			if u.app.GetFocus() == u.logView {
				row, col := u.logView.GetScrollOffset()
				u.logView.ScrollTo(row+1, col)
				return nil
			}
		case tcell.KeyPgUp:
			if u.app.GetFocus() == u.logView {
				_, _, _, h := u.logView.GetInnerRect()
				if h < 1 {
					h = 1
				}
				row, col := u.logView.GetScrollOffset()
				nr := row - (h - 1)
				if nr < 0 {
					nr = 0
				}
				u.logView.ScrollTo(nr, col)
				return nil
			}
		case tcell.KeyPgDn:
			if u.app.GetFocus() == u.logView {
				_, _, _, h := u.logView.GetInnerRect()
				if h < 1 {
					h = 1
				}
				row, col := u.logView.GetScrollOffset()
				u.logView.ScrollTo(row+(h-1), col)
				return nil
			}
		case tcell.KeyHome:
			if u.app.GetFocus() == u.logView {
				u.logView.ScrollToBeginning()
				return nil
			}
		case tcell.KeyEnd:
			if u.app.GetFocus() == u.logView {
				u.logView.ScrollToEnd()
				return nil
			}
		}
		return ev
	})
}

func (u *UI) refreshDirect() {
	u.logView.Clear()
	for _, l := range u.filteredLines() {
		fmt.Fprintln(u.logView, u.styleLine(l))
	}
	u.setLogSeparators(u.app.GetFocus() == u.logView)
	if u.topBarEnabled {
		u.updateTopBarDirect()
	}
	u.updateBottomBarDirect()
}

func (u *UI) bottomLeftStatus() string {
	key := func(s string) string {
		if u.noColour {
			return s
		}
		return "[blue::b]" + s + "[-:-:-]"
	}
	// Keys/help only. (Counters are shown in the top bar when enabled.)
	return fmt.Sprintf("%s help | %s switch | %s quit",
		key("?"), key("Tab"), key("Ctrl+C"),
	)
}

func (u *UI) legacyLeftStatus() string {
	key := func(s string) string {
		if u.noColour {
			return s
		}
		return "[blue::b]" + s + "[-:-:-]"
	}
	return fmt.Sprintf("%s help | %s switch | %s quit%s",
		key("?"), key("Tab"), key("Ctrl+C"), u.counterSnapshot(),
	)
}

func (u *UI) rightStatus(filterOn, caseOn, mouseOn, running bool) string {
	// Here, "active" (green) should mean: user can select with mouse.
	// That happens when tview mouse is DISABLED (mouseOn == false).
	selectionEnabled := !mouseOn

	col := func(active bool, label string) string {
		if u.noColour {
			return label
		}
		if active {
			return "[green::b]" + label + "[-:-:-]"
		}
		return "[yellow]" + label + "[-:-:-]"
	}

	return fmt.Sprintf("%s | %s | %s | %s",
		col(filterOn, "Filter"),
		col(caseOn, "Case Sensitive"),
		col(selectionEnabled, "Mouse"), // green = terminal selection enabled
		col(running, "Running"),
	)
}

func (u *UI) updateBottomBarDirect() {
	u.mu.Lock()
	filterOn := u.filterActive
	caseOn := u.filterCaseSensitive
	mouseOn := u.mouseOn
	paused := u.paused
	u.mu.Unlock()

	var left string
	if u.topBarEnabled {
		left = u.bottomLeftStatus() // no counters here
	} else {
		left = u.legacyLeftStatus() // legacy: counters remain on bottom
	}
	right := u.rightStatus(filterOn, caseOn, mouseOn, !paused)

	_, _, w, _ := u.statusText.GetInnerRect()
	if w <= 0 {
		u.statusText.SetText(left + "  " + right)
		return
	}
	pad := w - visualLen(left) - visualLen(right)
	if pad < 1 {
		pad = 1
	}
	u.statusText.SetText(left + strings.Repeat(" ", pad) + right)
}

func (u *UI) updateTopBarDirect() {
	if !u.topBarEnabled {
		return
	}
	u.mu.Lock()
	title := u.title
	u.mu.Unlock()

	left := title
	right := u.counterSnapshot()

	_, _, w, _ := u.topBar.GetInnerRect()
	if w <= 0 {
		u.topBar.SetText(left + "  " + right)
		return
	}
	pad := w - visualLen(left) - visualLen(right)
	if pad < 1 {
		pad = 1
	}
	u.topBar.SetText(left + strings.Repeat(" ", pad) + right)
}

func (u *UI) setLogSeparators(focused bool) {
	_, _, w, _ := u.logView.GetInnerRect()
	if w <= 0 {
		w = 1
	}
	ch := '─'
	if focused {
		ch = '═'
	}
	line := strings.Repeat(string(ch), w)

	// Top line only when top bar is disabled (legacy mode)
	if !u.topBarEnabled {
		u.topSep.SetText(line)
	}
	u.bottomSep.SetText(line)
}

func (u *UI) styleLine(line string) string {
	if u.noColour || len(u.highlights) == 0 || line == "" {
		return line
	}
	out := line
	u.hlMu.Lock()
	defer u.hlMu.Unlock()

	for _, h := range u.highlights {
		if h.match == "" {
			continue
		}
		if h.styler != nil {
			// Case-sensitive or insensitive replace with custom styler
			if h.caseSensitive {
				out = strings.ReplaceAll(out, h.match, h.styler(h.match, u.noColour))
			} else {
				out = replaceAllInsensitive(out, h.match, func(s string) string { return h.styler(s, u.noColour) })
			}
			continue
		}
		if h.style != nil {
			if h.caseSensitive {
				out = strings.ReplaceAll(out, h.match, u.applyStyle(h.match, *h.style))
			} else {
				out = replaceAllInsensitive(out, h.match, func(s string) string { return u.applyStyle(s, *h.style) })
			}
		}
	}
	return out
}

func (u *UI) applyStyle(s string, st Style) string {
	if u.noColour || s == "" {
		return s
	}
	open := "[" + st.FG + ":" + st.BG + ":" + st.Attrs + "]"
	return open + s + "[-:-:-]"
}

func replaceAllInsensitive(s, sub string, rep func(string) string) string {
	if sub == "" {
		return s
	}
	ls := strings.ToLower(s)
	ln := strings.ToLower(sub)

	var b strings.Builder
	i := 0
	for {
		j := strings.Index(ls[i:], ln)
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		j += i
		b.WriteString(s[i:j])
		b.WriteString(rep(s[j : j+len(sub)]))
		i = j + len(sub)
	}
	return b.String()
}

func (u *UI) filteredLines() []string {
	u.mu.Lock()
	defer u.mu.Unlock()

	if !u.filterActive || strings.TrimSpace(u.filter) == "" {
		out := make([]string, len(u.lines))
		copy(out, u.lines)
		return out
	}
	out := make([]string, 0, len(u.lines))
	if u.filterCaseSensitive {
		for _, l := range u.lines {
			if strings.Contains(l, u.filter) {
				out = append(out, l)
			}
		}
	} else {
		want := strings.ToLower(u.filter)
		for _, l := range u.lines {
			if strings.Contains(strings.ToLower(l), want) {
				out = append(out, l)
			}
		}
	}
	return out
}

func (u *UI) atBottom() bool {
	filtered := u.filteredLines()
	total := len(filtered)
	row, _ := u.logView.GetScrollOffset()
	_, _, _, h := u.logView.GetInnerRect()
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

func (u *UI) counterSnapshot() string {
	u.counterMu.Lock()
	defer u.counterMu.Unlock()

	parts := make([]string, 0, len(u.counters))
	now := time.Now()
	for _, c := range u.counters {
		// prune for display too (cheap)
		cut := now.Add(-c.window)
		cnt := 0
		for i := len(c.times) - 1; i >= 0; i-- {
			if c.times[i].After(cut) {
				cnt++
			} else {
				break
			}
		}
		parts = append(parts, fmt.Sprintf(" | %s:%d", c.label, cnt))
	}

	// Fit within available width? We can't measure here; we truncate in updateBottomBarDirect by padding.
	// As a compact heuristic, we keep them all; the outer pad calculation will cut with "+N" if needed.
	// To provide "+N", we need width; since we don't have it here, we return full and let wrapping/pad handle.
	// To avoid wrapping, we keep it linear. If it wraps, tview will clip silently.

	// We still try to avoid overlong by doing nothing; the status line remains one row high.
	out := strings.Builder{}
	for _, p := range parts {
		out.WriteString(p)
	}
	return out.String()
}

func (u *UI) showHelpModal() {
	u.prevFocus = u.app.GetFocus()
	lines := []string{
		u.title,
		"",
		"Focus & Quit",
		"  Tab / Shift+Tab     Switch focus (Log ↔ Input)",
		"  Ctrl+C              Quit immediately",
		"  q (log focus)       Quit",
		"",
		"Log View (when focused)",
		"  Up/Down             Scroll one line",
		"  PgUp/PgDn           Scroll one page",
		"  Home/End            Jump to top/bottom",
		"  Space               Pause/Resume autoscroll",
		"  c                   Toggle case sensitivity for filter",
		"  m                   Toggle mouse mode (green = terminal selection enabled)",
		"  ?                   Toggle this help",
		"",
		"Filter (Input line)",
		"  Type text to set filter pattern",
		"  Enter               Enable/Disable filter (keeps text)",
		"  Esc                 Clear & disable filter",
	}
	if u.topBarEnabled {
		lines = append(lines, "",
			"Top Bar",
			"  Shows Title (left) and registered counters (right).")
	} else {
		lines = append(lines, "",
			"Bottom Status",
			"  Shows keys and counters (legacy mode).")
	}
	lines = append(lines, "",
		"Status Bar",
		"  Shows keys on the left and toggles on the right. Mouse badge is green when you can",
		"  select with the mouse (i.e., tview mouse handling is OFF).",
	)

	if len(u.helpExtra) > 0 {
		lines = append(lines, "")
		lines = append(lines, u.helpExtra...)
	}
	help := strings.Join(lines, "\n")

	m := tview.NewModal().
		SetText(help).
		AddButtons([]string{"Close"}).
		SetDoneFunc(func(_ int, _ string) { u.closeModal() })
	u.modal = m
	u.app.SetRoot(m, true)
	u.app.SetFocus(m)
}

func (u *UI) closeModal() {
	if u.modal == nil {
		return
	}
	u.modal = nil
	u.app.SetRoot(u.root, true)
	if u.prevFocus != nil {
		u.app.SetFocus(u.prevFocus)
		u.setLogSeparators(u.app.GetFocus() == u.logView)
	}
}

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
				n++
			}
		default:
			if !inTag {
				n++
			}
		}
	}
	return n
}

// levelOf derives a coarse level from the line prefix.
func levelOf(s string) string {
	if strings.HasPrefix(s, "ERROR: ") {
		return "error"
	}
	return "info"
}

// chooseSocketPathForDial picks the first existing socket path in the same order.
// It only checks for presence and returns the first match.
func chooseSocketPathForDial() (string, error) {
	candidates := []string{
		"/run/dhcplane/consoleui.sock",
		"/tmp/consoleui.sock",
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		candidates = append(candidates, filepath.Join(xdg, "dhcplane.sock"))
	}
	for _, p := range candidates {
		if fi, err := os.Stat(p); err == nil && (fi.Mode()&os.ModeSocket) != 0 {
			return p, nil
		}
	}
	return "", errors.New("console attach: UNIX socket not found in default locations")
}

// ---- attach client ----

// AttachOptions control how the client connects and renders.
type AttachOptions struct {
	Socket      string // optional override; if empty, auto-detect default path order
	NoColour    bool
	Transparent bool
	Title       string // optional title override
}

// Attach connects to the server socket and renders the full interactive UI locally.
func Attach(opts AttachOptions) error {
	path := opts.Socket
	if path == "" {
		var err error
		path, err = chooseSocketPathForDial()
		if err != nil {
			return err
		}
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		return fmt.Errorf("console attach: %w", err)
	}
	defer conn.Close()

	u := New(Options{
		NoColour:     opts.NoColour,
		MaxLines:     10000, // will be adjusted on meta
		MouseEnabled: true,
	})
	if opts.Transparent {
		tview.Styles.PrimitiveBackgroundColor = tcell.ColorDefault
		tview.Styles.ContrastBackgroundColor = tcell.ColorDefault
		tview.Styles.MoreContrastBackgroundColor = tcell.ColorDefault
	}
	if opts.Title != "" {
		u.SetTitle(opts.Title)
	} else {
		u.SetTitle("DHCPlane Console (attached)")
	}

	// reader goroutine: consume NDJSON from server and feed the local UI
	r := bufio.NewReaderSize(conn, 64<<10)
	go func() {
		for {
			b, err := r.ReadBytes('\n')
			if err != nil {
				u.Append("[notice] disconnected from server")
				u.onExit(1)
				return
			}
			// peek type
			var typ struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(b, &typ); err != nil {
				continue
			}
			switch typ.Type {
			case "meta":
				var m wireMeta
				if json.Unmarshal(b, &m) == nil {
					// update limits and rules locally
					u.mu.Lock()
					u.maxLines = m.MaxLines
					u.mu.Unlock()
					for _, c := range m.Counters {
						u.RegisterCounter(c.Match, c.CaseSensitive, c.Label, c.WindowS)
					}
					for _, h := range m.Highlights {
						if h.Style != nil {
							u.HighlightMap(h.Match, h.CaseSensitive, *h.Style)
						}
					}
				}
			case "line":
				var ev wireLine
				if json.Unmarshal(b, &ev) == nil {
					when := time.Unix(0, 0)
					if ev.TsUs > 0 {
						when = time.UnixMicro(ev.TsUs)
					} else {
						when = time.Now()
					}
					u.appendWithWhen(when, ev.Text)
				}
			case "notice":
				var n wireNotice
				if json.Unmarshal(b, &n) == nil {
					u.Append(n.Text)
				}
			}
		}
	}()

	// run local UI loop (blocks until exit)
	return u.app.Run()
}

// ---- cobra integration (same binary client command) ----

// InstallAttachCommand adds a "console attach" subcommand to the provided Cobra root.
// Usage: dhcplane console attach [--socket PATH] [--nocolour] [--transparent]
func InstallAttachCommand(root *cobra.Command) {
	var socket string
	var nocolour bool
	var transparent bool

	consoleCmd := &cobra.Command{
		Use:   "console",
		Short: "Console-related commands",
	}
	attachCmd := &cobra.Command{
		Use:   "attach",
		Short: "Attach to the running console via UNIX socket",
		RunE: func(_ *cobra.Command, _ []string) error {
			return Attach(AttachOptions{
				Socket:      socket,
				NoColour:    nocolour,
				Transparent: transparent,
				Title:       "DHCPlane Console (attached)",
			})
		},
	}
	attachCmd.Flags().StringVar(&socket, "socket", "", "UNIX socket path override")
	attachCmd.Flags().BoolVar(&nocolour, "nocolour", false, "Disable ANSI colours")
	attachCmd.Flags().BoolVar(&transparent, "transparent", false, "Use terminal background")

	consoleCmd.AddCommand(attachCmd)
	root.AddCommand(consoleCmd)
}
