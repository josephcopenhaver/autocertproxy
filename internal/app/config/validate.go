package config

import (
	"errors"
	"net/mail"
	"strings"
)

var (
	ErrNoSslHostnames       = errors.New("no SSL_HOSTNAMES provided")
	ErrInvalidAdminEmail    = errors.New("not a valid admin email")
	ErrInvalidAuthorization = errors.New("not a valid basic authorization value")
)

func (c Config) Validate() error {

	if len(c.SslHostnames) < 1 {
		return ErrNoSslHostnames
	}

	if c.AdminEmail != "" && !isEmailValid(c.AdminEmail) {
		return ErrInvalidAdminEmail
	}

	if c.Authorization != "" && !isAuthorizationValid(c.Authorization) {
		return ErrInvalidAuthorization
	}

	return nil
}

func isEmailValid(e string) bool {

	_, err := mail.ParseAddress(e)

	return err == nil
}

// isAuthorizationValid tests if both username and password are provided
func isAuthorizationValid(s string) bool {

	idx := strings.Index(s, ":")

	return (idx > 0 && idx < len(s)-1)
}
