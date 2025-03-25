package oidc

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func createTestJWT(expiration time.Time) string {
	claims := jwt.MapClaims{
		"exp": expiration.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, _ := token.SignedString([]byte("test-secret")) // Signature doesn't matter for ParseUnverified
	return signedToken
}

func TestIsTokenNeedsRefresh(t *testing.T) {
	tests := []struct {
		name        string
		expiryDelta time.Duration
		expect      bool
	}{
		{
			name:        "Expired token",
			expiryDelta: -10 * time.Second,
			expect:      true,
		},
		{
			name:        "Valid token (expires in 1 hour)",
			expiryDelta: 1 * time.Hour,
			expect:      false,
		},
		{
			name:        "Token expiring in 19 seconds, should be renewed",
			expiryDelta: 19 * time.Second,
			expect:      true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := createTestJWT(time.Now().Add(tc.expiryDelta))
			session := &OidcSession{IdToken: token}
			needsRefresh, err := session.isTokenNeedsRefresh()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if needsRefresh != tc.expect {
				t.Errorf("expected %v, got %v", tc.expect, needsRefresh)
			}
		})
	}
}
