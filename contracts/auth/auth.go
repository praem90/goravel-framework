package auth

import (
	"time"

	"github.com/goravel/framework/contracts/config"
	"github.com/goravel/framework/contracts/http"
)

type Factory interface {
    GetDefaultDriver() Guard
    SetDefaultDriver(string) Factory
    Extend(string, AuthGuardFunc) Factory
    Guard(string) Guard
}

type AuthGuardFunc func(string, config.Config, http.Context, UserProvider) Guard

type Auth interface {
	// Guard attempts to get the guard against the local cache.
	Guard(name string) Auth
	// Parse the given token.
	Parse(token string) (*Payload, error)
	// User returns the current authenticated user.
	User(user any) error
	// Id returns the current user id.
	Id() (string, error)
	// Login logs a user into the application.
	Login(user any) (token string, err error)
	// LoginUsingID logs the given user ID into the application.
	LoginUsingID(id any) (token string, err error)
	// Refresh the token for the current user.
	Refresh() (token string, err error)
	// Logout logs the user out of the application.
	Logout() error
}

type Payload struct {
	Guard    string
	Key      string
	ExpireAt time.Time
	IssuedAt time.Time
}
