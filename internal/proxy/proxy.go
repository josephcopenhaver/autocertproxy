package proxy

import (
	"context"
	"net"
	"net/http"
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

		if p.cfg.Authorization != "" {
			proxyHandler := handler

			handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

				// validate authorization
				{
					user, pass, ok := r.BasicAuth()

					if !ok || user+":"+pass != p.cfg.Authorization {
						http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
						return
					}
				}

				proxyHandler.ServeHTTP(w, r)
			})
		}

		srv := http.Server{
			Addr:      net.JoinHostPort(cfg.ListenHttpsHost, strconv.Itoa(cfg.ListenHttpsPort)),
			TLSConfig: am.TLSConfig(),
			Handler:   handler,
		}

		wg.Add(1)
		go func() {

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
