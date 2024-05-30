package transports

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// LoggingRoundTripper logs details about the request/response
type LoggingRoundTripper struct {
	Log  *slog.Logger
	Next http.RoundTripper
}

// RoundTrip implements the RoundTripper interface
func (ltr *LoggingRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	requestID, err := randomID()

	if err != nil {
		return nil, fmt.Errorf("requestID: %w", err)
	}

	started := time.Now()
	log := ltr.Log.With(
		slog.String("httpRequestID", requestID),
		slog.Group("httpRequest",
			slog.String("method", r.Method),
			slog.String("url", r.URL.String()),
			slog.Time("timeStarted", started),
		),
	)

	log.DebugContext(r.Context(), "starting HTTP request",
		slog.Any("headers", printableHeaders(r.Header)),
	)

	var res *http.Response

	// defer the response log so that we always log
	defer func() {
		if err != nil {
			log.ErrorContext(r.Context(), "received error",
				slog.Any("err", err),
			)
			return
		}

		ended := time.Now()
		log.DebugContext(r.Context(), "received response",
			slog.Group("httpResponse",
				slog.Any("headers", printableHeaders(r.Header)),
				slog.Int("statusCode", res.StatusCode),
				slog.Int("contentLength", int(res.ContentLength)),
				slog.Time("timeEnded", ended),
				slog.Duration("took", ended.Sub(started)),
			))
	}()

	res, err = ltr.Next.RoundTrip(r)

	return res, err
}

// returns a slog group value of headers than can be
// logged. No sensitive headers are returned.
func printableHeaders(h http.Header) slog.Value {
	var printable []slog.Attr

	for _, n := range []string{
		"Content-Type",
		"User-Agent",
		"Accept",
		"Accept-Encoding",
		"Accept-Language",
	} {
		if v := h.Get(n); v != "" {
			printable = append(printable, slog.String(n, v))
		}
	}

	return slog.GroupValue(printable...)
}

// randomID creates a 16 byte, hex encoded, random ID
func randomID() (string, error) {
	var id [16]byte

	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}

	return hex.EncodeToString(id[:]), nil
}
