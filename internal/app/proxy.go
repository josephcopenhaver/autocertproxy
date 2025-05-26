package app

import (
	"context"
	"errors"
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
	"sync"
	"sync/atomic"

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
			slog.String("url", dstUrlStr),
			errAttr(err),
		)
		return proxy{}, err
	}
	dstProxyUrl.Scheme = strings.ToLower(dstProxyUrl.Scheme)
	if s := dstProxyUrl.Scheme; s != "http" && s != "https" {
		logger.LogAttrs(ctx, slog.LevelError,
			"failed to parse destination url: scheme must be either http or https",
			slog.String("url", dstUrlStr),
			errAttr(err),
		)
		return proxy{}, err
	}

	if err := os.MkdirAll(cfg.AutocertCacheDir, 0700); err != nil {
		logger.LogAttrs(ctx, slog.LevelError,
			"failed to make autocert cache directory",
			slog.String("directory", cfg.AutocertCacheDir),
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
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	cfg := p.cfg

	logger.LogAttrs(ctx, slog.LevelInfo,
		"server starting",
		slog.Any("config", cfg),
		slog.String("dst_url", p.dstProxyUrl.String()),
	)

	am := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.SslHostnames...),
		Cache:      autocert.DirCache(cfg.AutocertCacheDir),
		Email:      cfg.AdminEmail,
	}

	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()

	newWGDoneOnce := func() func() {
		return sync.OnceFunc(func() {
			wg.Done()
		})
	}

	type ServerContext struct {
		Name    string
		ErrChan chan error
	}

	var srvContexts []ServerContext

	//
	// start http to https redirect policy handler on port cfg.ListenHttpPort
	//

	if cfg.ForceHttps {

		errChan := make(chan error, 2)

		srvContext := ServerContext{
			Name:    "http",
			ErrChan: errChan,
		}

		srvContexts = append(srvContexts, srvContext)

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

		var shuttingDown int32
		wg.Add(1)
		srvDone := newWGDoneOnce()
		go func() {
			defer srvDone()
			defer cancel()

			err := srv.ListenAndServe()
			if atomic.LoadInt32(&shuttingDown) == 0 {
				logger.LogAttrs(ctx, slog.LevelError,
					"server exited unexpectedly",
					slog.String("server", srvContext.Name),
					errAttr(err),
				)
			} else if errors.Is(err, http.ErrServerClosed) {
				return
			}

			errChan <- err
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()

			<-ctx.Done()

			shutdownContext, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
			defer cancel()

			atomic.StoreInt32(&shuttingDown, 1)
			if err := srv.Shutdown(shutdownContext); err != nil {
				errChan <- err

				// server failed to shutdown gracefully
				// so mark it as done even though it failed
				// to become done which ensures this function returns
				//
				// it will likely leak a goroutine when this happens
				// assuming the server is still listening properly
				srvDone()
			}
		}()
	}

	//
	// start letsencrypt+proxy handling server on port cfg.ListenHttpsPort
	//

	{

		errChan := make(chan error, 2)

		srvContext := ServerContext{
			Name:    "https",
			ErrChan: errChan,
		}

		srvContexts = append(srvContexts, srvContext)

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
			prevHandler := handler

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

				prevHandler.ServeHTTP(w, r)
			})
		}

		if cfg.ResponseBufferEnabled {
			prevHandler := handler

			handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

				// read response body till end
				var resp *http.Response
				{
					rec := httptest.NewRecorder()

					prevHandler.ServeHTTP(rec, r)

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
			prevHandler := handler

			handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

				// validate authorization
				{
					user, pass, ok := r.BasicAuth()

					if !ok || user+":"+pass != cfg.Authorization {
						http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
						return
					}
				}

				prevHandler.ServeHTTP(w, r)
			})
		}

		srv := http.Server{
			Addr:      net.JoinHostPort(cfg.ListenHttpsHost, strconv.Itoa(cfg.ListenHttpsPort)),
			TLSConfig: am.TLSConfig(),
			Handler:   handler,
		}

		var shuttingDown int32
		wg.Add(1)
		srvDone := newWGDoneOnce()
		go func() {
			defer srvDone()
			defer cancel()

			err := srv.ListenAndServeTLS("", "")
			if atomic.LoadInt32(&shuttingDown) == 0 {
				logger.LogAttrs(ctx, slog.LevelError,
					"server exited unexpectedly",
					slog.String("server", srvContext.Name),
					errAttr(err),
				)
			} else if errors.Is(err, http.ErrServerClosed) {
				return
			}

			errChan <- err
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()

			<-ctx.Done()

			shutdownContext, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
			defer cancel()

			atomic.StoreInt32(&shuttingDown, 1)
			if err := srv.Shutdown(shutdownContext); err != nil {
				errChan <- err

				// server failed to shutdown gracefully
				// so mark it as done even though it failed
				// to become done which ensures this function returns
				//
				// it will likely leak a goroutine when this happens
				// assuming the server is still listening properly
				srvDone()
			}
		}()
	}

	//
	// wait for goroutines to finish
	//

	wg.Wait()

	//
	// handle any shutdown errors
	//

	var shutdownErrors []error
	for _, srvContext := range srvContexts {
		var stop bool
		for !stop {
			select {
			case err := <-srvContext.ErrChan:
				shutdownErrors = append(shutdownErrors, err)
			default:
				stop = true
			}
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
