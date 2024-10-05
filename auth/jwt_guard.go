package auth

import (
	contractsauth "github.com/goravel/framework/contracts/auth"
	"github.com/goravel/framework/contracts/config"
	"github.com/goravel/framework/contracts/http"
)

type JwtGuard struct {
}

// setUser implements auth.Guard.
func (j JwtGuard) SetUser(any) contractsauth.Guard {
	panic("unimplemented")
}

// Check implements auth.Guard.
func (j JwtGuard) Check() bool {
	panic("unimplemented")
}

// Guest implements auth.Guard.
func (j JwtGuard) Guest() bool {
	panic("unimplemented")
}

// HasUser implements auth.Guard.
func (j JwtGuard) HasUser() bool {
	panic("unimplemented")
}

// Id implements auth.Guard.
func (j JwtGuard) Id() string {
	panic("unimplemented")
}

// User implements auth.Guard.
func (j JwtGuard) User() *any {
	panic("unimplemented")
}

// Validate implements auth.Guard.
func (j JwtGuard) Validate(map[string]string) bool {
	panic("unimplemented")
}

func NewJwtGuard(string, config.Config, http.Context) contractsauth.Guard {
	return JwtGuard{}
}
