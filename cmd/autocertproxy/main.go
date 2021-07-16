package main

import (
	"log"
	"os"

	"github.com/josephcopenhaver/autocertproxy/internal/logging"
	"github.com/josephcopenhaver/autocertproxy/internal/proxy"
	"github.com/josephcopenhaver/autocertproxy/internal/proxy/config"

	"go.uber.org/zap"
)

func main() {

	if err := logging.SetLogLevel(zap.InfoLevel); err != nil {
		log.Fatal(err)
	}

	logger := logging.Logger

	var cfg config.Config
	if err := config.Load(&cfg); err != nil {
		logger.Fatalw(
			"failed to load config",
			"error", err,
		)
	}

	for _, arg := range os.Args {
		if arg == "-h" || arg == "--h" || arg == "-help" || arg == "--help" {

			logger.Infow(
				"help: all configs are env variables",
				"envconfig", cfg,
			)

			return
		}

		if arg == "--version" {
			// TODO: print a version indicator
			return
		}
	}

	if err := logging.SetLogLevel(cfg.LogLevel); err != nil {
		logger.Fatalw(
			"failed to set log level",
			"error", err,
		)
	}

	logger = logging.Logger // use new log level

	if err := cfg.Validate(); err != nil {
		logger.Fatalw(
			"invalid config",
			"error", err,
		)
	}

	p, err := proxy.New(cfg, logger)
	if err != nil {
		logger.Fatalw(
			"failed to create a new proxy",
			"error", err,
		)
	}

	ctx, cancel := proxy.RootContext()
	defer cancel()

	if err := p.ListenAndServe(ctx); err != nil {
		logger.Errorw(
			"server shutdown unexpectedly",
			"error", err,
		)
		return
	}

	logger.Warnw("server shutdown successful")
}
