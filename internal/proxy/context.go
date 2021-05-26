package proxy

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// RootContext returns a context that is canceled when the
// system process receives an interrupt, sigint, or sigterm
//
// Also returns a function that can be used to cancel the context.
func RootContext() (context.Context, func()) {

	ctx, cancel := context.WithCancel(context.Background())

	procDone := make(chan os.Signal, 1)

	signal.Notify(procDone, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		defer cancel()

		done := ctx.Done()

		select {
		case <-procDone:
		case <-done:
		}
	}()

	return ctx, cancel
}
