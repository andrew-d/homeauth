package main

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/felixge/httpsnoop"
)

type logAttrs struct {
	attrs []slog.Attr
}

var logAttrsKey = &struct{}{}

func RequestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Add a type to our request's context that we can get
			// to later and add more attributes.
			customAttrs := &logAttrs{}

			ctx := r.Context()
			ctx = context.WithValue(ctx, logAttrsKey, customAttrs)
			r = r.WithContext(ctx)

			m := httpsnoop.CaptureMetrics(next, w, r)

			// Now that the request has been run, build the set of
			// attributes that we're going to log, starting with
			// the standard attributes and then adding any custom
			// ones.
			attrs := []slog.Attr{
				slog.String("method", r.Method),
				slog.String("url", r.URL.String()),
				slog.String("remote_addr", r.RemoteAddr),
				slog.Int("status", m.Code),
				slog.Duration("duration", m.Duration),
				slog.Int64("bytes", m.Written),
			}
			attrs = append(attrs, customAttrs.attrs...)

			log.LogAttrs(ctx, slog.LevelInfo, "HTTP request", attrs...)
		})
	}
}

// AddRequestLogAttrs will add the given attributes to the set of attributes
// that are logged in the request's log line.
func AddRequestLogAttrs(r *http.Request, attrs ...slog.Attr) {
	logAttrs, ok := r.Context().Value(logAttrsKey).(*logAttrs)
	if !ok {
		return
	}
	logAttrs.attrs = append(logAttrs.attrs, attrs...)
}
