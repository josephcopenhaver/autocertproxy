package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/josephcopenhaver/autocertproxy/internal/app/config"
)

func Run() {
	var logger *slog.Logger
	if v, err := newLogger(); err != nil {
		panic(fmt.Errorf("failed to create logger: %w", err))
	} else {
		logger = v
	}

	slog.SetDefault(logger)

	var ctx context.Context
	{
		v, cancel := rootContext(context.Background(), logger)
		defer cancel()

		ctx = v
	}

	var cfg config.Config
	if err := config.Load(&cfg); err != nil {
		const msg = "failed to load config"
		logger.LogAttrs(ctx, slog.LevelError,
			msg,
			errAttr(err),
		)
		panic(fmt.Errorf("%s: %w", msg, err))
	}

	if err := cfg.Validate(); err != nil {
		const msg = "failed to validate config"
		logger.LogAttrs(ctx, slog.LevelError,
			msg,
			errAttr(err),
		)
		panic(fmt.Errorf("%s: %w", msg, err))
	}

	for _, arg := range os.Args {
		switch arg {
		case "-h", "--h", "-help", "--help":
			logger.LogAttrs(ctx, slog.LevelInfo,
				"help: all configs are env variables: to see them run the program with --config but be warned that this will print sensitive information",
			)

			return
		case "-show-config", "--show-config":
			logger.LogAttrs(ctx, slog.LevelInfo,
				"env variable based runtime configuration",
				slog.Any("envconfig", cfg),
			)
			return
		case "-v", "--v", "-version", "--version":
			// TODO: print a version indicator
			return
		}
	}

	p, err := newProxy(ctx, cfg, logger)
	if err != nil {
		const msg = "failed to create a new proxy"
		logger.LogAttrs(ctx, slog.LevelError,
			msg,
			errAttr(err),
		)
		panic(fmt.Errorf("%s: %w", msg, err))
	}

	logger.LogAttrs(ctx, slog.LevelWarn,
		"starting proxy",
	)

	var loggedErrResp bool
	defer func() {
		if r := recover(); r != nil {
			defer panic(r)

			if !loggedErrResp {
				// this should never happen, but just in case
				logger.LogAttrs(ctx, slog.LevelError,
					"proxy panicked",
					slog.Any("cause", r),
				)
			}
		}
	}()

	if err := p.ListenAndServe(ctx, logger); err != nil {
		loggedErrResp = true
		const msg = "proxy failed"
		logger.LogAttrs(ctx, slog.LevelError,
			msg,
			errAttr(err),
		)
		panic(fmt.Errorf("%s: %w", msg, err))
	}

	logger.LogAttrs(ctx, slog.LevelWarn,
		"proxy stopped",
	)
}
