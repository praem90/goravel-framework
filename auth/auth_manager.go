package auth

import (
	"fmt"

	contractsauth "github.com/goravel/framework/contracts/auth"
	"github.com/goravel/framework/contracts/foundation"
	"github.com/goravel/framework/contracts/http"
)

type AuthManager struct {
	app    foundation.Application
	ctx    http.Context
	guards map[string]contractsauth.AuthGuardFunc
}


// GetDefaultDriver implements auth.Factory.
func (f AuthManager) GetDefaultDriver() contractsauth.Guard {
	config := f.app.MakeConfig()
	name := config.GetString("auth.defaults.guard")

	return f.Guard(name)
}

// SetDefaultDriver implements auth.Factory.
func (f AuthManager) SetDefaultDriver(name string) contractsauth.Factory {
	config := f.app.MakeConfig()
	config.Add("auth.defaults.guard", name)

	return f
}

// Extend implements auth.Factory.
func (f AuthManager) Extend(name string, callback contractsauth.AuthGuardFunc) contractsauth.Factory {
	f.guards[name] = callback

	return f
}

// Guard implements auth.Factory.
func (f AuthManager) Guard(name string) contractsauth.Guard {
	driver := f.app.MakeConfig().GetString(fmt.Sprintf("auth.guards.%s.driver", name))

	if guardFn, exists := f.guards[driver]; exists {
		config := f.app.MakeConfig()
		return guardFn(name, config, f.ctx)
	}

	return nil
}

func NewAuthManager(app foundation.Application, ctx http.Context) contractsauth.Factory {
	return AuthManager{
		app:    app,
		ctx:    ctx,
		guards: map[string]contractsauth.AuthGuardFunc{},
	}
}
