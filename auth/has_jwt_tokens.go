package auth

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/goravel/framework/contracts/config"
	"github.com/goravel/framework/support/carbon"
	"github.com/spf13/cast"
)

type HasJwtTokens struct {

}

func (h *HasJwtTokens) CreateToken(config config.Config, id any) (token string, err error) {
	jwtSecret := config.GetString("jwt.secret")
	if jwtSecret == "" {
		return "", ErrorEmptySecret
	}

	nowTime := carbon.Now()
	ttl := config.GetInt("jwt.ttl")
	if ttl == 0 {
		// 100 years
		ttl = 60 * 24 * 365 * 100
	}
	expireTime := nowTime.AddMinutes(ttl).StdTime()
	key := cast.ToString(id)
	if key == "" {
		return "", ErrorInvalidKey
	}
	claims := Claims{
		key,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expireTime),
			IssuedAt:  jwt.NewNumericDate(nowTime.StdTime()),
			Subject:   "jwt",
		},
	}

	tokenClaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err = tokenClaims.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}

    return token, nil
}

