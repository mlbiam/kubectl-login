package oidc

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type OidcSession struct {
	IdToken      string
	RefreshToken string
	Issuer       string
	TokenUrl     string
	AuthUrl      string
}

func (session *OidcSession) isTokenNeedsRefresh() (bool, error) {

	token, _, err := jwt.NewParser().ParseUnverified(session.IdToken, jwt.MapClaims{})
	if err != nil {
		return false, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, errors.New("invalid claims")
	}

	expRaw, ok := claims["exp"]
	if !ok {
		return false, errors.New("missing exp claim")
	}

	expFloat, ok := expRaw.(float64)
	if !ok {
		return false, errors.New("invalid exp claim type")
	}

	expTime := time.Unix(int64(expFloat), 0)
	now := time.Now()
	if expTime.Before(now.Add(20 * time.Second)) {
		return true, nil
	}

	return false, nil
}
