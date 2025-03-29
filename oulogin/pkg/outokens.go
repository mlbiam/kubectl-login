package outokens

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type OidcSession struct {
	idToken      string
	refreshToken string
	issuer       string
	tokenUrl     string
	authUrl      string
	clientID     string
	caCert       string
	tlsConfig    *tls.Config
}

type OIDCDiscoveryDoc struct {
	TokenEndpoint string `json:"token_endpoint"`
	AzEndpoint    string `json:"authorization_endpoint"`
}

func NewOidcSession(issuer string, clientID string, caCert string, idToken string) (*OidcSession, error) {

	session := &OidcSession{
		issuer:   issuer,
		clientID: clientID,
		idToken:  idToken,
	}

	if caCert != "" {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM([]byte(caCert)) {
			return nil, fmt.Errorf("failed to append CA certificate")
		}
		session.tlsConfig = &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
		}
	} else {
		session.tlsConfig = &tls.Config{}
	}

	err := session.loadUrlsFromIssuer(context.Background())

	if err != nil {
		return nil, err
	} else {
		return session, nil
	}

}

func (session *OidcSession) isTokenNeedsRefresh() (bool, error) {

	token, _, err := jwt.NewParser().ParseUnverified(session.idToken, jwt.MapClaims{})
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

func (session *OidcSession) loadUrlsFromIssuer(ctx context.Context) error {
	// Make sure issuer doesn't end with a slash
	issuer := strings.TrimSuffix(session.issuer, "/")

	discoveryURL := issuer + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second,

		Transport: &http.Transport{
			TLSClientConfig: session.tlsConfig,
		}}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery request failed with status: %s", resp.Status)
	}

	fmt.Printf(resp.Header["Content-Type"][0])

	// bodyBytes, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	panic(err)
	// }

	// bodyString := string(bodyBytes)
	// fmt.Println(bodyString)

	var doc OIDCDiscoveryDoc

	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("failed to decode discovery document: %w", err)
	}

	if doc.TokenEndpoint == "" {
		return fmt.Errorf("token_endpoint not found in discovery document")
	}

	if doc.AzEndpoint == "" {
		return fmt.Errorf("authorization_endpoint not found in discovery document")
	}

	session.authUrl = doc.AzEndpoint
	session.tokenUrl = doc.TokenEndpoint

	return nil
}

func (session *OidcSession) refreshIdToken(ctx context.Context) (*oauth2.Token, error) {
	config := &oauth2.Config{
		ClientID: session.clientID,
		Endpoint: oauth2.Endpoint{
			TokenURL: session.tokenUrl,
		},
	}

	tokenSource := config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: session.refreshToken,
	})

	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, err
	}

	return newToken, nil
}
