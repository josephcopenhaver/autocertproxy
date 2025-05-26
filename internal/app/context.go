package app

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func rootContext(ctx context.Context, logger *slog.Logger) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(ctx)

	procDone := make(chan os.Signal, 1)

	signal.Notify(procDone, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		defer cancel()

		ctxChan := ctx.Done()

		select {
		case <-procDone:
			// Likely an external process has signaled for a shutdown to happen gracefully.
			//
			// Technically a process may try to kill itself, but the normal thing is for the
			// context cancel func to be used for that case.
			logger.LogAttrs(ctx, slog.LevelWarn,
				"shutdown requested",
				slog.String("signaler", "process"),
			)
		case <-ctxChan:
			// The context has either been cancelled due to a failure, expired due to a timeout
			// deadline being reached, or has naturally/gracefully come to its expected end.
			logger.LogAttrs(ctx, slog.LevelWarn,
				"shutdown requested",
				slog.String("signaler", "context"),
				errAttr(ctx.Err()),
				slog.Any("cause", context.Cause(ctx)),
			)
		}
	}()

	return ctx, cancel
}
