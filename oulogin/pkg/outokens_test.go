package outokens

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	oulogintest "github.com/tremolosecurity/kubectl-login/test"
)

func createTestJWT(expiration time.Time) string {
	claims := jwt.MapClaims{
		"exp": expiration.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, _ := token.SignedString([]byte("test-secret")) // Signature doesn't matter for ParseUnverified
	return signedToken
}

func getPEMFromTLSCertificate(cert tls.Certificate) (certPEM, keyPEM []byte, err error) {
	// Encode certificate
	for _, certDER := range cert.Certificate {
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		}
		certPEM = append(certPEM, pem.EncodeToMemory(block)...)
	}

	// Encode private key
	switch key := cert.PrivateKey.(type) {
	case *x509.Certificate:
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: key.Raw,
		})
	case interface{}:
		keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to marshal private key: %w", err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		})
	}

	return certPEM, keyPEM, nil
}

func TestIdentityProvider(t *testing.T) {
	idp, err := oulogintest.StartTestOIDCProvider()

	if err != nil {
		t.Fatalf("could not start idp %v", err)
	}

	pem, _, err := getPEMFromTLSCertificate(idp.Server.TLS.Certificates[0])

	session, err := NewOidcSession(idp.Issuer, "", string(pem), "")

	if err != nil {
		t.Fatalf("could init session %v", err)
	}

	if session.authUrl == "" {
		t.Error("No authorization url")
	}

	if session.tokenUrl == "" {
		t.Error("No token url")
	}

	idp.Close()
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
			session := OidcSession{idToken: token}
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
