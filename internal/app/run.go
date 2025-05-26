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
		if arg == "-h" || arg == "--h" || arg == "-help" || arg == "--help" {

			logger.LogAttrs(ctx, slog.LevelInfo,
				"help: all configs are env variables",
				slog.Any("envconfig", cfg),
			)

			return
		}

		if arg == "--version" {
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

	if err := p.ListenAndServe(ctx, logger); err != nil {
		panic(err)
	}

	logger.LogAttrs(ctx, slog.LevelWarn,
		"server shutdown successful",
	)
}
