package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWT struct {
	Secret string
}

func NewJWT(secret string) *JWT {
	return &JWT{
		Secret: secret,
	}
}

type CustomClaims struct {
	GUID      string `json:"guid"`
	SessionID string `json:"session_id"`
	jwt.RegisteredClaims
}

func (j *JWT) Create(guid, sessionID string, ttl time.Duration) (string, error) {
	claims := CustomClaims{
		GUID:      guid,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl).UTC()),
			IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString([]byte(j.Secret))
}

func (j *JWT) Parse(tokenStr string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(j.Secret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, jwt.ErrTokenExpired
		}
		return nil, fmt.Errorf("token invalid: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}
