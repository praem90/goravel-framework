package auth

import (
	"fmt"

	contractsauth "github.com/goravel/framework/contracts/auth"
	"github.com/goravel/framework/contracts/config"
	"github.com/goravel/framework/contracts/foundation"
	"github.com/goravel/framework/contracts/http"
)

type UserProviderFunc func(foundation.Application, config.Config) contractsauth.UserProvider

type AuthManager struct {
	app    foundation.Application
	ctx    http.Context
	customGuards map[string]contractsauth.AuthGuardFunc
	guards map[string]contractsauth.Guard
	providers map[string]contractsauth.UserProvider
	customProviders map[string]UserProviderFunc
}


// GetDefaultDriver implements auth.Factory.
func (f AuthManager) GetDefaultDriver() contractsauth.Guard {
	config := f.app.MakeConfig()

    if config == nil {
        return nil
    }

	name := config.GetString("auth.defaults.guard")

	return f.Guard(name)
}

// SetDefaultDriver implements auth.Factory.
func (f AuthManager) SetDefaultDriver(name string) contractsauth.Factory {
	config := f.app.MakeConfig()

    if config != nil {
        config.Add("auth.defaults.guard", name)
    }

	return f
}

// Extend implements auth.Factory.
func (f AuthManager) Extend(name string, callback contractsauth.AuthGuardFunc) contractsauth.Factory {
	f.customGuards[name] = callback

	return f
}

// Guard implements auth.Factory.
func (f AuthManager) Guard(name string) contractsauth.Guard {
	config := f.app.MakeConfig()
    if config == nil {
        return nil
    }

	driver := config.GetString(fmt.Sprintf("auth.guards.%s.driver", name))

	if guard, exists := f.guards[driver]; exists {
        return guard
    }

	if guardFn, exists := f.customGuards[driver]; exists {
		config := f.app.MakeConfig()
        provider := config.GetString(fmt.Sprintf("auth.guards.%s.provider", name))
		f.guards[name] = guardFn(name, config, f.ctx, f.createUserProvider(provider))

        return f.guards[name]
	}

	return nil
}

func (f AuthManager) createUserProvider(name string) contractsauth.UserProvider {
    return nil
}

func NewAuthManager(app foundation.Application, ctx http.Context) contractsauth.Factory {
	return AuthManager{
		app:    app,
		ctx:    ctx,
		guards: map[string]contractsauth.Guard{},
		customGuards: map[string]contractsauth.AuthGuardFunc{},
	}
}
