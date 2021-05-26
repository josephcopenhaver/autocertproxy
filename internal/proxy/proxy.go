package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/josephcopenhaver/autocertproxy/internal/proxy/config"
	"golang.org/x/crypto/acme/autocert"
)

type proxy struct {
	cfg         config.Config
	dstProxyUrl *url.URL
	Logger      *zap.SugaredLogger
}

func New(cfg config.Config, logger *zap.SugaredLogger) (proxy, error) {

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
		logger.Errorw(
			"failed to parse destination url",
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
		dstProxyUrl: dstProxyUrl,
		Logger:      logger,
	}, nil
}

func (p *proxy) ListenAndServe(ctx context.Context) error {

	logger := p.Logger
	cfg := p.cfg

	logger.Infow(
		"server starting",
		"config", cfg,
		"dst_url", p.dstProxyUrl.String(),
	)

	am := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.SslHostnames...),
		Cache:      autocert.DirCache(cfg.AutocertCacheDir),
		Email:      cfg.AdminEmail,
	}

	var wg sync.WaitGroup

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

		wg.Add(1)
		go func() {
			defer wg.Done()

			wg.Add(1)
			go func() {
				defer wg.Done()

				<-ctx.Done()

				shutdownContext, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
				defer cancel()

				if err := srv.Shutdown(shutdownContext); err != nil {
					errChan <- err
				}
			}()
			errChan <- srv.ListenAndServe()
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

		wg.Add(1)
		go func() {
			defer wg.Done()

			wg.Add(1)
			go func() {
				defer wg.Done()

				<-ctx.Done()

				shutdownContext, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
				defer cancel()

				if err := srv.Shutdown(shutdownContext); err != nil {
					errChan <- err
				}
			}()
			errChan <- srv.ListenAndServeTLS("", "")
		}()
	}

	//
	// wait for server shutdowns
	//

	wg.Wait()

	//
	// handle any shutdown errors
	//

	var shutdownErr error

	for _, srvContext := range srvContexts {

		if err := <-srvContext.ErrChan; err != nil && err != http.ErrServerClosed {

			shutdownErr = err

			logger.Errorw(
				"server shutdown error",
				"name", srvContext.Name,
				"error", err,
			)
		}
	}

	return shutdownErr
}
