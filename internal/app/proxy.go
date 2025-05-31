package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/josephcopenhaver/autocertproxy/internal/app/config"
	"golang.org/x/crypto/acme/autocert"
)

type proxy struct {
	cfg         config.Config
	dstProxyUrl *url.URL
}

func newProxy(ctx context.Context, cfg config.Config, logger *slog.Logger) (proxy, error) {

	dstUrlStr := cfg.DstScheme + "://" + cfg.DstHost
	if cfg.DstScheme == "http" {
		if cfg.DstPort != 80 {
			dstUrlStr += ":" + strconv.Itoa(cfg.DstPort)
		}
	} else if cfg.DstScheme == "https" {
		if cfg.DstPort != 443 {
			dstUrlStr += ":" + strconv.Itoa(cfg.DstPort)
		}
	}
	if cfg.DstBasePath != "" {
		if cfg.DstBasePath[0] != '/' {
			dstUrlStr += "/"
		}
		dstUrlStr += cfg.DstBasePath
	}

	dstProxyUrl, err := url.Parse(dstUrlStr)
	if err != nil {
		logger.LogAttrs(ctx, slog.LevelError,
			"failed to parse destination url",
			errAttr(err),
		)
		return proxy{}, err
	}
	dstProxyUrl.Scheme = strings.ToLower(dstProxyUrl.Scheme)
	if s := dstProxyUrl.Scheme; s != "http" && s != "https" {
		logger.LogAttrs(ctx, slog.LevelError,
			"failed to parse destination url: scheme must be either http or https",
			errAttr(err),
		)
		return proxy{}, err
	}

	if err := os.MkdirAll(cfg.AutocertCacheDir, 0700); err != nil {
		logger.LogAttrs(ctx, slog.LevelError,
			"failed to make autocert cache directory",
			errAttr(err),
		)
		return proxy{}, err
	}

	return proxy{
		cfg:         cfg,
		dstProxyUrl: dstProxyUrl,
	}, nil
}

func (p *proxy) ListenAndServe(ctx context.Context, logger *slog.Logger) error {
	cfg := p.cfg

	logger.LogAttrs(ctx, slog.LevelWarn,
		"server starting",
	)

	am := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.SslHostnames...),
		Cache:      autocert.DirCache(cfg.AutocertCacheDir),
		Email:      cfg.AdminEmail,
	}

	type serverContext struct {
		name    string
		errChan <-chan error
	}
	var srvContexts []serverContext

	//
	// start http to https redirect policy handler on port cfg.ListenHttpPort
	//

	if cfg.ForceHttps {

		srvCtx := serverContext{
			name: "http",
		}

		srvCtxIdx := len(srvContexts)
		srvContexts = append(srvContexts, srvCtx)

		redirectHosts := make(map[string]string, len(cfg.SslHostnames)+1)
		for _, v := range cfg.SslHostnames {
			redirectHosts[v] = v
		}
		redirectHosts[""] = cfg.SslHostnames[0]

		handler := func(w http.ResponseWriter, req *http.Request) {

			newUrl := *req.URL
			host := req.Host

			if strings.Contains(host, ":") {
				if reqHost, reqPort, err := net.SplitHostPort(host); err == nil && reqPort != "" {
					host = reqHost
				}
			}

			targetHost, ok := redirectHosts[host]
			if !ok || targetHost == "" {

				w.WriteHeader(http.StatusBadRequest)
				return
			}

			newUrl.Scheme = "https"

			newUrl.Host = targetHost

			http.Redirect(w, req, newUrl.String(), cfg.SslRedirectStatusCode)
		}

		srv := http.Server{
			Addr:    net.JoinHostPort(cfg.ListenHttpHost, strconv.Itoa(cfg.ListenHttpPort)),
			Handler: http.HandlerFunc(handler),
		}

		srvContexts[srvCtxIdx].errChan = listenAndServe(ctx, logger, listenAndServeConfig{
			name:            srvCtx.name,
			srv:             &srv,
			shutdownTimeout: cfg.ShutdownTimeout,
		})
	}

	//
	// start letsencrypt+proxy handling server on port cfg.ListenHttpsPort
	//

	{

		srvCtx := serverContext{
			name: "https",
		}

		srvCtxIdx := len(srvContexts)
		srvContexts = append(srvContexts, srvCtx)

		var handler http.Handler = httputil.NewSingleHostReverseProxy(p.dstProxyUrl)

		// determine the request's host header value
		var dstHostHeader string
		if cfg.DstHostHeader != "" {
			dstHostHeader = cfg.DstHostHeader
		} else {
			dstHostHeader = cfg.DstHost
		}

		// set the dest host header value as specified
		{
			next := handler

			handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

				// ensure host header is scrubbed
				if r.Header != nil && len(r.Header.Get("Host")) > 0 {
					prevHeader := r.Header

					defer func() {
						r.Header = prevHeader
					}()

					h := prevHeader.Clone()
					h.Del("Host")

					r.Header = h
				}

				// ensure the request host name is temporarily altered
				if r.Host != dstHostHeader {
					prevHost := r.Host

					defer func() {
						r.Host = prevHost
					}()

					r.Host = dstHostHeader
				}

				next.ServeHTTP(w, r)
			})
		}

		if cfg.ResponseBufferEnabled {
			next := handler

			handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

				// read response body till end
				var resp *http.Response
				{
					rec := httptest.NewRecorder()

					next.ServeHTTP(rec, r)

					resp = rec.Result()
				}

				// send response headers
				{
					h := w.Header()
					for k, values := range resp.Header {
						for _, v := range values {
							h.Add(k, v)
						}
					}
				}

				w.WriteHeader(resp.StatusCode)

				// send response body
				_, err := io.Copy(w, resp.Body)
				_ = err // intentionally ignoring error, upstream or downstream must have had an issue
			})
		}

		if cfg.Authorization != "" {
			next := handler

			handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

				// validate authorization
				{
					user, pass, ok := r.BasicAuth()

					if !ok || user+":"+pass != cfg.Authorization {
						http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
						return
					}
				}

				next.ServeHTTP(w, r)
			})
		}

		srv := http.Server{
			Addr:      net.JoinHostPort(cfg.ListenHttpsHost, strconv.Itoa(cfg.ListenHttpsPort)),
			TLSConfig: am.TLSConfig(),
			Handler:   handler,
		}

		srvContexts[srvCtxIdx].errChan = listenAndServe(ctx, logger, listenAndServeConfig{
			name:            srvCtx.name,
			srv:             &srv,
			shutdownTimeout: cfg.ShutdownTimeout,
			tlsEnabled:      true,
		})
	}

	//
	// wait for goroutines to finish
	// and handle any shutdown errors
	//

	shutdownErrors := make([]error, 0, len(srvContexts))
	for _, srvContext := range srvContexts {
		c := srvContext.errChan
		if err, ok := <-c; ok {
			shutdownErrors = append(shutdownErrors, fmt.Errorf("error server %s: %w", srvContext.name, err))

			// confirms the channel is closed, meaning the goroutine has finished
			<-c
		}
	}

	switch len(shutdownErrors) {
	case 0:
		return nil
	case 1:
		return shutdownErrors[0]
	default:
		return errors.Join(shutdownErrors...)
	}
}

type httpServerCloser interface {
	Shutdown(ctx context.Context) error
	Close() error
}

type httpServer interface {
	httpServerCloser
	ListenAndServe() error
	ListenAndServeTLS(certFile, keyFile string) error
}

type listenAndServeConfig struct {
	name, tlsCertFile, tlsKeyFile string
	shutdownTimeout               time.Duration
	srv                           httpServer
	tlsEnabled                    bool
}

var (
	errServerGracefulShutdown = errors.New("server graceful shutdown failed")
	errServerClose            = errors.New("server close failed")
	errServerNotStarted       = errors.New("server not started")
	errServerPanic            = errors.New("server panicked")
)

func listenAndServe(ctx context.Context, logger *slog.Logger, cfg listenAndServeConfig) <-chan error {
	errChan := make(chan error, 1)

	var listenAndServe func() error
	if !cfg.tlsEnabled {
		listenAndServe = cfg.srv.ListenAndServe
	} else {
		listenAndServe = func() error {
			return cfg.srv.ListenAndServeTLS(cfg.tlsCertFile, cfg.tlsKeyFile)
		}
	}

	go asyncListenAndServe(ctx, logger, errChan, cfg.name, listenAndServe, cfg.shutdownTimeout, cfg.srv)

	return errChan
}

func asyncListenAndServe(ctx context.Context, logger *slog.Logger, errChan chan error, name string, listenAndServe func() error, shutdownTimeout time.Duration, hsc httpServerCloser) {
	defer close(errChan)

	serveRespChan := make(chan error, 1)

	if err := ctx.Err(); err != nil {
		logger.LogAttrs(ctx, slog.LevelError,
			"server ListenAndServe not attempted",
			slog.String("server", name),
			errAttr(err),
		)
		errChan <- errors.Join(errServerNotStarted, err)
		return
	}

	go func() {
		defer close(serveRespChan)

		serveRespChan <- listenAndServe()
	}()

	ctxDone := ctx.Done()
	select {
	case err, ok := <-serveRespChan:
		if !ok {
			logger.LogAttrs(ctx, slog.LevelError,
				"server exited unexpectedly",
				slog.String("server", name),
				slog.String("graceful-shutdown", "not attempted"),
				slog.String("reason", "panic"),
			)
			errChan <- errServerPanic
			return
		}

		// waits for server goroutine to finish
		<-serveRespChan

		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.LogAttrs(ctx, slog.LevelError,
				"server exited unexpectedly",
				slog.String("server", name),
				slog.String("graceful-shutdown", "not attempted"),
				slog.String("reason", "error"),
				errAttr(err),
			)
			errChan <- err
		}
		return
	case <-ctxDone:
		// context has been cancelled, so we should try to shutdown the server gracefully
	}

	logger.LogAttrs(ctx, slog.LevelWarn,
		"gracefully shutting down server",
		slog.String("server", name),
	)

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := hsc.Shutdown(shutdownCtx); err != nil {
		logger.LogAttrs(ctx, slog.LevelError,
			"server graceful shutdown failed",
			slog.String("server", name),
			slog.String("graceful-shutdown", "attempted"),
			errAttr(err),
		)

		// server failed to shutdown gracefully
		// so force close it
		if closeErr := hsc.Close(); closeErr != nil {
			logger.LogAttrs(ctx, slog.LevelError,
				"server forced shutdown failed",
				slog.String("server", name),
				errAttr(closeErr),
			)
			errChan <- errors.Join(errServerClose, closeErr, errServerGracefulShutdown, err)
			return
		}

		errChan <- errors.Join(errServerGracefulShutdown, err)
		return
	}

	if err := <-serveRespChan; err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.LogAttrs(ctx, slog.LevelError,
			"server exited unexpectedly",
			slog.String("server", name),
			slog.String("graceful-shutdown", "attempted"),
			errAttr(err),
		)
		errChan <- err
		return
	}

	logger.LogAttrs(ctx, slog.LevelWarn,
		"server stopped",
		slog.String("server", name),
	)
}
