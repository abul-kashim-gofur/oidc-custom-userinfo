package logging

import (
	"io"
	"log/slog"
	"os"
)

type config struct {
	out         io.Writer
	format      Format
	contextKeys []ContextKeyValue
	level       slog.Level
}

type WithOption interface{ set(*config) }

type Format string

const (
	JSON = Format("JSON")
	Text = Format("TEXT")
)

func (f Format) set(cfg *config) { cfg.format = f }

type withOutput struct{ out io.Writer }

func (wo *withOutput) set(cfg *config) { cfg.out = wo.out }

func WithOutput(out io.Writer) WithOption { return &withOutput{out: out} }

type withContextKeyResolvers ContextKeyValue

func (ckr *withContextKeyResolvers) set(cfg *config) {
	cfg.contextKeys = append(cfg.contextKeys, ContextKeyValue(*ckr))
}

// WithContextResolvers allows for attaching resolver functions that pick
// there log value from the current context
func WithContextResolver(r ContextKeyValue) WithOption {
	a := withContextKeyResolvers(r)
	return &a
}

type level slog.Level

func (l level) set(cfg *config) { cfg.level = slog.Level(l) }

// WithLevel sets the logging output level
func WithLevel(lvl slog.Level) WithOption { return level(lvl) }

func New(options ...WithOption) *slog.Logger {
	cfg := config{
		out:    os.Stdout,
		format: JSON,
		level:  slog.LevelInfo,
	}

	for _, opt := range options {
		opt.set(&cfg)
	}

	ho := &slog.HandlerOptions{
		AddSource: cfg.level == slog.LevelDebug,
		Level:     cfg.level,
	}

	var h slog.Handler

	switch cfg.format {
	case JSON:
		h = slog.NewJSONHandler(cfg.out, ho)
	case Text:
		h = slog.NewTextHandler(cfg.out, ho)
	default:
		panic("unknown format: " + cfg.format)
	}

	if len(cfg.contextKeys) > 0 {
		h = &contextKeysLogger{resolver: cfg.contextKeys, h: h}
	}

	return slog.New(h)
}
