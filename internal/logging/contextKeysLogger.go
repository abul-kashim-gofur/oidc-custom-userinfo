package logging

import (
	"context"
	"log/slog"
)

// ensure that contextKeysLogger meets the slog.Handler interface
var _ slog.Handler = &contextKeysLogger{}

// ContextKeyValue can read values from the context to be added into the log.
// If the value cannot be found, or is invalid, the ContextKeyValue should
// return an empty array.
type ContextKeyValue func(context.Context) []slog.Attr

// contextKeysLogger extracts values from the context and before passing them
// onto the base Handler for logging
type contextKeysLogger struct {
	h        slog.Handler
	resolver []ContextKeyValue
}

// newChild creates a new contextKeysLogger using the handler h
func (l *contextKeysLogger) newChild(h slog.Handler) slog.Handler {
	return &contextKeysLogger{h: h, resolver: l.resolver}
}

// Handle attaches each found value to the slog record before passing the it onto
// the base handler
func (l *contextKeysLogger) Handle(ctx context.Context, r slog.Record) error {
	for _, resolver := range l.resolver {
		for _, attr := range resolver(ctx) {
			r.AddAttrs(attr)
		}
	}
	return l.h.Handle(ctx, r)
}

// Enabled wraps over the base loggers enabled
func (l *contextKeysLogger) Enabled(ctx context.Context, lvl slog.Level) bool {
	return l.h.Enabled(ctx, lvl)
}

func (l *contextKeysLogger) WithAttrs(attrs []slog.Attr) slog.Handler {
	return l.newChild(l.h.WithAttrs(attrs))
}

func (l *contextKeysLogger) WithGroup(name string) slog.Handler {
	return l.newChild(l.h.WithGroup(name))
}
