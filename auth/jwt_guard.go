package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	contractsauth "github.com/goravel/framework/contracts/auth"
	"github.com/goravel/framework/contracts/config"
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/support/carbon"
)

type JwtGuard struct {
    name string;
    ctx http.Context;
    config config.Config;
    user any;
    provider contractsauth.UserProvider;
}

// setUser implements auth.Guard.
func (j JwtGuard) SetUser(user any) contractsauth.Guard {
    j.user = user

    return j
}

// Check implements auth.Guard.
func (j JwtGuard) Check() bool {
    return j.User() != nil
}

// Guest implements auth.Guard.
func (j JwtGuard) Guest() bool {
    return !j.Check()
}

// HasUser implements auth.Guard.
func (j JwtGuard) HasUser() bool {
    return j.user != nil
}

// Id implements auth.Guard.
func (j JwtGuard) Id() (string, error) {
    if j.User() != nil {
        user, ok := j.user.(map[string]interface{})

        if ok != false {
            return "", errors.ErrUnsupported
        }

        userId, ok := user["id"].(string)

        if ok != false {
            return "", errors.ErrUnsupported
        }

        return userId, nil
    }

    return "", errors.New("Unauthendicated")
}

// User implements auth.Guard.
func (j JwtGuard) User() *any {
    if j.user != nil {
        return &j.user
    }

    request := j.ctx.Request()

    if request == nil {
        return nil
    }

    token := request.Header("Authorization", "")

    bearerLen := len("Bearer ")

    if len(token) <= bearerLen {
        return nil
    }

    token = token[bearerLen:]

    if token == "" {
        return nil
    }

	jwtSecret := j.config.GetString("jwt.secret")

	tokenClaims, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (any, error) {
		return []byte(jwtSecret), nil
	}, jwt.WithTimeFunc(func() time.Time {
		return carbon.Now().StdTime()
	}))

	if err != nil {
        return nil
	}

	if tokenClaims == nil || !tokenClaims.Valid {
		return nil
	}

	claims, ok := tokenClaims.Claims.(*Claims)

	if !ok {
		return nil
	}

    j.user, err = j.provider.RetriveById(claims.Key)

    if err != nil {
        return nil
    }

    return &j.user
}

// Validate implements auth.Guard.
func (j JwtGuard) Validate(map[string]string) bool {
    staticGuard := NewJwtGuard(j.name, j.config, j.ctx, j.provider)

    return staticGuard.User() != nil
}

func NewJwtGuard(name string, config config.Config, ctx http.Context, provider contractsauth.UserProvider) contractsauth.Guard {
	return JwtGuard{
        name: name,
        config: config,
        ctx: ctx,
        provider: provider,
    }
}
