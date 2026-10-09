package logx

import (
	"context"
	"log/slog"
	"net/http"
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

func LogHTTPRequest(logger *slog.Logger, req *http.Request) {
	if req == nil || logger == nil {
		return
	}

	url := ""
	if req.URL != nil {
		url = req.URL.String()
	}

	logger.Debug(
		"sent request",
		"method", req.Method,
		"url", url,
	)
}

func LogHTTPResponse(logger *slog.Logger, resp *http.Response) {
	if resp == nil || logger == nil {
		return
	}

	url := ""
	method := ""
	if resp.Request != nil {
		method = resp.Request.Method
		if resp.Request.URL != nil {
			url = resp.Request.URL.String()
		}
	}

	level := slog.LevelDebug
	if resp.StatusCode >= http.StatusBadRequest {
		level = slog.LevelWarn
	}

	logger.Log(context.Background(), level, "got response",
		"status", resp.StatusCode,
		"method", method,
		"url", url,
	)
}
