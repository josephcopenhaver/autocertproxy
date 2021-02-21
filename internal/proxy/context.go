package proxy

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// RootContext returns a context that is canceled when the
// system process receives an interrupt, sigint, or sigterm
func RootContext() context.Context {

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan os.Signal, 1)

	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-done
		cancel()
	}()

	return ctx
}
