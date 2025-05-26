package app

import (
	"fmt"
	"log/slog"
	"os"
)

const (
	envVarLogLevel = "LOG_LEVEL"
)

func newLogger() (*slog.Logger, error) {
	level := slog.LevelInfo

	if s := os.Getenv(envVarLogLevel); s != "" {
		var v slog.Level
		if err := v.UnmarshalText([]byte(s)); err != nil {
			return nil, fmt.Errorf("failed to parse "+envVarLogLevel+" env variable: %w", err)
		}
		level = v
	}

	var addSource bool
	if level <= slog.LevelDebug {
		addSource = true
	}

	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level:     level,
		AddSource: addSource,
	})

	return slog.New(h), nil
}

func errAttr(err error) slog.Attr {
	return slog.Any("error", err)
}
