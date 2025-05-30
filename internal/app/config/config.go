package config

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

// TODO: allow for configuration of upstream Host header in proxied requests

type Config struct {
	LogLevel              string        `json:"LOG_LEVEL" envconfig:"LOG_LEVEL"`
	ForceHttps            bool          `json:"FORCE_HTTPS" envconfig:"FORCE_HTTPS" default:"true"`
	ShutdownTimeout       time.Duration `json:"SHUTDOWN_TIMEOUT" envconfig:"SHUTDOWN_TIMEOUT" default:"29s"`
	SslHostnames          []string      `json:"SSL_HOSTNAMES" envconfig:"SSL_HOSTNAMES" default:""`
	SslRedirectStatusCode int           `json:"SSL_REDIRECT_STATUS_CODE" envconfig:"SSL_REDIRECT_STATUS_CODE" default:"307"`
	ListenHttpHost        string        `json:"LISTEN_HTTP_HOST" envconfig:"LISTEN_HTTP_HOST" default:""`
	ListenHttpPort        int           `json:"LISTEN_HTTP_PORT" envconfig:"LISTEN_HTTP_PORT" default:"80"`
	ListenHttpsHost       string        `json:"LISTEN_HTTPS_HOST" envconfig:"LISTEN_HTTPS_HOST" default:""`
	ListenHttpsPort       int           `json:"LISTEN_HTTPS_PORT" envconfig:"LISTEN_HTTPS_PORT" default:"443"`
	DstScheme             string        `json:"DST_SCHEME" envconfig:"DST_SCHEME" default:"http"`
	DstBasePath           string        `json:"DST_BASE_PATH" envconfig:"DST_BASE_PATH" default:""`
	DstHost               string        `json:"DST_HOST" envconfig:"DST_HOST" default:"127.0.0.1"`
	DstHostHeader         string        `json:"DST_HOST_HEADER" envconfig:"DST_HOST_HEADER" default:""`
	DstPort               int           `json:"DST_PORT" envconfig:"DST_PORT" default:"8080"`
	ResponseBufferEnabled bool          `json:"RESPONSE_BUFFER_ENABLED" envconfig:"RESPONSE_BUFFER_ENABLED" default:"false"`
	AdminEmail            string        `json:"ADMIN_EMAIL" envconfig:"ADMIN_EMAIL" default:""`
	AutocertCacheDir      string        `json:"AUTOCERT_CACHE_DIR" envconfig:"AUTOCERT_CACHE_DIR" default:"./.autocert"`
	Authorization         string        `json:"AUTHORIZATION" default:""`
}

func Load(cfg *Config) error {
	return envconfig.Process("", cfg)
}
