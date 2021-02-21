package config

import (
	"errors"
	"net/mail"
)

var (
	ErrNoSslHostnames    = errors.New("no SSL_HOSTNAMES provided")
	ErrInvalidAdminEmail = errors.New("not a valid admin email")
)

func (c Config) Validate() error {

	if len(c.SslHostnames) < 1 {
		return ErrNoSslHostnames
	}

	if c.AdminEmail != "" && !isEmailValid(c.AdminEmail) {
		return ErrInvalidAdminEmail
	}

	return nil
}

func isEmailValid(e string) bool {

	_, err := mail.ParseAddress(e)

	return err == nil
}
