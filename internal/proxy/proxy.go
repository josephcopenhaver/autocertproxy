package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/josephcopenhaver/autocertproxy/internal/proxy/config"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sync/errgroup"
)

var (
	ErrServerContextPanicked  = errors.New("server context panicked")
	ErrServerShutdownPanicked = errors.New("server shutdown panicked")
)

type proxy struct {
	cfg         config.Config
	dstUdsFile  string
	dstProxyUrl *url.URL
	Logger      *zap.SugaredLogger
}

func New(cfg config.Config, logger *zap.SugaredLogger) (proxy, error) {

	var dstUrlStr string
	var dstUdsFile string

	switch cfg.DstScheme {
	case "http":

		dstUrlStr = cfg.DstScheme + "://" + cfg.DstHost
		if cfg.DstPort != 80 {
			dstUrlStr += ":" + strconv.Itoa(cfg.DstPort)
		}
	case "https":

		dstUrlStr = cfg.DstScheme + "://" + cfg.DstHost
		if cfg.DstPort != 443 {
			dstUrlStr += ":" + strconv.Itoa(cfg.DstPort)
		}
	case "unix", "http+unix", "https+unix":

		scheme := "http"
		if strings.HasPrefix(cfg.DstScheme, "https+") {
			scheme = "https"
		}

		host := "127.0.0.1"
		if cfg.DstHostHeader != "" {
			host = cfg.DstHostHeader
		}

		dstUrlStr = scheme + "://" + host

		dstUdsFile = cfg.DstHost
		if dstUdsFile == "" {
			return proxy{}, fmt.Errorf("must specify a file as DST_HOST when using %s scheme", cfg.DstScheme)
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
		logger.Errorw(
			"failed to parse destination url",
			"url", dstUrlStr,
			"error", err,
		)
		return proxy{}, err
	}
	dstProxyUrl.Scheme = strings.ToLower(dstProxyUrl.Scheme)
	if s := dstProxyUrl.Scheme; s != "http" && s != "https" {
		logger.Errorw(
			"failed to parse destination url: scheme must be either http or https",
			"url", dstUrlStr,
			"error", err,
		)
		return proxy{}, err
	}

	if err := os.MkdirAll(cfg.AutocertCacheDir, 0700); err != nil {
		logger.Errorw(
			"failed to make autocert cache directory",
			"error", err,
			"directory", cfg.AutocertCacheDir,
		)
		return proxy{}, err
	}

	return proxy{
		cfg:         cfg,
		dstUdsFile:  dstUdsFile,
		dstProxyUrl: dstProxyUrl,
		Logger:      logger,
	}, nil
}

func (p *proxy) ListenAndServe(ctx context.Context) error {

	logger := p.Logger
	cfg := p.cfg
	pctx := ctx

	{
		logFields := []interface{}{
			"config", cfg,
			"dst_url", p.dstProxyUrl.String(),
		}
		if p.dstUdsFile != "" {
			logFields = append(logFields,
				"dst_unix_domain_socket_file", p.dstUdsFile,
			)
		}
		logger.Infow(
			"server listners starting",
			logFields...,
		)
	}

	errgrp, ctx := errgroup.WithContext(ctx)

	logSrvStart := func(name, addr string) {
		logger.Warnw(
			"server listener starting",
			"name", name,
			"addr", addr,
		)
	}

	logSrvErr := func(name string, errChan chan error, run func() error) {

		err := ErrServerContextPanicked
		defer func() {
			if err == nil || err == http.ErrServerClosed {
				return
			}

			errChan <- err
		}()

		err = run()
		if err == nil || err == http.ErrServerClosed {
			return
		}

		if pctx.Err() == nil {
			logger.Errorw(
				"server listener exited incorrectly",
				"name", name,
				"error", err,
			)
		}
	}

	registerShutdown := func(srv *http.Server, errChan chan error) {
		go func() {

			err := ErrServerShutdownPanicked
			defer func() {
				errChan <- err
			}()

			<-ctx.Done()

			shutdownContext, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
			defer cancel()

			err = srv.Shutdown(shutdownContext)
			if err == http.ErrServerClosed {
				err = nil
			}
		}()
	}

	am := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.SslHostnames...),
		Cache:      autocert.DirCache(cfg.AutocertCacheDir),
		Email:      cfg.AdminEmail,
	}

	//
	// start http to https redirect policy handler on port cfg.ListenHttpPort
	//

	if cfg.ForceHttps {

		serverName := "http"

		redirectHosts := make(map[string]string, len(cfg.SslHostnames)+1)
		for _, v := range cfg.SslHostnames {
			redirectHosts[v] = v
		}
		redirectHosts[""] = cfg.SslHostnames[0]

		var handler http.HandlerFunc = func(w http.ResponseWriter, req *http.Request) {

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
			Handler: handler,
		}

		errChan := make(chan error, 2)

		logSrvStart(serverName, srv.Addr)

		go logSrvErr(serverName, errChan, srv.ListenAndServe)

		registerShutdown(&srv, errChan)

		errgrp.Go(func() error {
			return <-errChan
		})
	}

	//
	// start letsencrypt+proxy handling server on port cfg.ListenHttpsPort
	//

	{

		serverName := "https"

		var handler http.HandlerFunc

		if p.dstUdsFile != "" {

			tran, ok := http.DefaultTransport.(*http.Transport)
			if !ok {
				panic("failed to cast http.DefaultTransport to *http.Transport when making a unix socket dialer")
			}
			tran = tran.Clone()
			dialer := net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			tran.DialContext = func(ctx context.Context, _ string, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", p.dstUdsFile)
			}

			proxy := httputil.NewSingleHostReverseProxy(p.dstProxyUrl)
			proxy.Transport = tran

			handler = proxy.ServeHTTP
		} else {

			handler = httputil.NewSingleHostReverseProxy(p.dstProxyUrl).ServeHTTP
		}

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

			handler = func(w http.ResponseWriter, r *http.Request) {

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

				next(w, r)
			}
		}

		if cfg.ResponseBufferEnabled {
			next := handler

			handler = func(w http.ResponseWriter, r *http.Request) {

				// read response body till end
				var resp *http.Response
				{
					rec := httptest.NewRecorder()

					next(rec, r)

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
			}
		}

		if cfg.Authorization != "" {
			next := handler

			handler = func(w http.ResponseWriter, r *http.Request) {

				// validate authorization
				{
					user, pass, ok := r.BasicAuth()

					if !ok || user+":"+pass != cfg.Authorization {
						http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
						return
					}
				}

				next(w, r)
			}
		}

		srv := http.Server{
			Addr:      net.JoinHostPort(cfg.ListenHttpsHost, strconv.Itoa(cfg.ListenHttpsPort)),
			TLSConfig: am.TLSConfig(),
			Handler:   handler,
		}

		errChan := make(chan error, 2)

		logSrvStart(serverName, srv.Addr)

		go logSrvErr(serverName, errChan, func() error {
			return srv.ListenAndServeTLS("", "")
		})

		registerShutdown(&srv, errChan)

		errgrp.Go(func() error {
			return <-errChan
		})
	}

	logger.Warnw(
		"waiting for shutdown signal",
	)

	return errgrp.Wait()
}
