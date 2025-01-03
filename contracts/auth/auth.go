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
	User() *any
	Id() (string, error)
    Guard(guard string) Guard
    GetDefaultDriver() Guard
    Check() bool
}

type Payload struct {
	Guard    string
	Key      string
	ExpireAt time.Time
	IssuedAt time.Time
}
