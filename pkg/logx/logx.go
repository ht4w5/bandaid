package logx

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

type contextKey struct{}

var loggerKey contextKey

func WithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

func FromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}

func NewLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "none":
		return slog.New(slog.DiscardHandler)
	case "error":
		l = slog.LevelError
	case "warn":
		l = slog.LevelWarn
	case "info":
		l = slog.LevelInfo
	case "debug":
		l = slog.LevelDebug
	default:
		n, err := strconv.Atoi(level)
		if err == nil {
			l = slog.Level(n)
		} else {
			l = slog.LevelInfo
		}
	}

	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level:     l,
		AddSource: l == slog.LevelDebug,
	}))
}
