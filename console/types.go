package console

import "strings"

const DefaultMaxLines = 10000

// Style defines a simple tview tag style: [FG:BG:ATTRS] ... [-:-:-]
// FG/BG accept named colors ("red") or hex ("#ff3366"); empty keeps current.
// Attrs is a compact string like "b", "bu", "i", "u", "d", "t".
type Style struct {
	FG    string `json:"fg"`
	BG    string `json:"bg"`
	Attrs string `json:"attrs"`
}

// CounterSpec describes a rolling counter filter matched against log lines.
type CounterSpec struct {
	Match         string `json:"match"`
	CaseSensitive bool   `json:"case_sensitive"`
	Label         string `json:"label"`
	WindowSeconds int    `json:"window_s"`
}

// HighlightSpec describes a substring highlight with an optional style.
type HighlightSpec struct {
	Match         string `json:"match"`
	CaseSensitive bool   `json:"case_sensitive"`
	Style         *Style `json:"style,omitempty"`
}

// Config captures shared presentation rules exchanged between broker and UI.
type Config struct {
	MaxLines   int
	Counters   []CounterSpec
	Highlights []HighlightSpec
}

// EffectiveMaxLines returns a sane positive value for ring buffer sizing.
func (cfg Config) EffectiveMaxLines() int {
	if cfg.MaxLines <= 0 {
		return DefaultMaxLines
	}
	return cfg.MaxLines
}

// Meta is the first message broker sends to each client describing limits and rules.
type Meta struct {
	Type       string          `json:"type"`
	MaxLines   int             `json:"max_lines"`
	Counters   []CounterSpec   `json:"counters"`
	Highlights []HighlightSpec `json:"highlights"`
}

// Line carries a single console line with its original timestamp and a coarse level.
type Line struct {
	Type  string `json:"type"`
	TsUs  int64  `json:"ts_us"`
	Text  string `json:"text"`
	Level string `json:"level"`
}

// Notice informs a slow client that some lines were dropped locally.
type Notice struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// MakeMeta converts the static config into a Meta payload ready for JSON encoding.
func MakeMeta(cfg Config) Meta {
	counters := append([]CounterSpec(nil), cfg.Counters...)
	highlights := make([]HighlightSpec, 0, len(cfg.Highlights))
	for _, h := range cfg.Highlights {
		cp := h
		if h.Style != nil {
			st := *h.Style
			cp.Style = &st
		}
		highlights = append(highlights, cp)
	}
	return Meta{
		Type:       "meta",
		MaxLines:   cfg.EffectiveMaxLines(),
		Counters:   counters,
		Highlights: highlights,
	}
}

// LevelOf derives a coarse level from the line prefix.
func LevelOf(s string) string {
	if strings.HasPrefix(s, "ERROR: ") {
		return "error"
	}
	return "info"
}
