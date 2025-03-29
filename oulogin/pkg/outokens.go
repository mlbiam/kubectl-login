package outokens

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type OidcSession struct {
	IDToken      string      `json:"id_token"`
	RefreshToken string      `json:"refresh_token"`
	Issuer       string      `json:"issuer"`
	TokenUrl     string      `json:"token_url"`
	AuthUrl      string      `json:"auth_url"`
	ClientID     string      `json:"client_id"`
	CaCert       string      `json:"ca_cert"`
	TLSConfig    *tls.Config `json:"-"`
}

type OIDCDiscoveryDoc struct {
	TokenEndpoint string `json:"token_endpoint"`
	AzEndpoint    string `json:"authorization_endpoint"`
}

func NewOidcSession(issuer string, clientID string, caCert string, idToken string) (*OidcSession, error) {
	var err error
	session := &OidcSession{
		Issuer:   issuer,
		ClientID: clientID,
		IDToken:  idToken,
	}

	session.TLSConfig, err = createTLSConfig(caCert)

	if err != nil {
		return nil, err
	}

	err = session.loadUrlsFromIssuer(context.Background())

	if err != nil {
		return nil, err
	} else {
		return session, nil
	}

}

func createTLSConfig(caCert string) (*tls.Config, error) {
	if caCert != "" {
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM([]byte(caCert)) {
			return nil, fmt.Errorf("failed to append CA certificate")
		}
		return &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
		}, nil
	}
	return &tls.Config{}, nil
}

func (session *OidcSession) isTokenNeedsRefresh() (bool, error) {

	token, _, err := jwt.NewParser().ParseUnverified(session.IDToken, jwt.MapClaims{})
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
	issuer := strings.TrimSuffix(session.Issuer, "/")

	discoveryURL := issuer + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second,

		Transport: &http.Transport{
			TLSClientConfig: session.TLSConfig,
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

	session.AuthUrl = doc.AzEndpoint
	session.TokenUrl = doc.TokenEndpoint

	return nil
}

func (session *OidcSession) refreshIdToken(ctx context.Context) (*oauth2.Token, error) {
	config := &oauth2.Config{
		ClientID: session.ClientID,
		Endpoint: oauth2.Endpoint{
			TokenURL: session.TokenUrl,
		},
	}

	tokenSource := config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: session.RefreshToken,
	})

	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, err
	}

	return newToken, nil
}

func SaveSessionToTempFile(session *OidcSession) (string, error) {
	tempFile, err := os.CreateTemp("", "oidcsession_*.json")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	enc := json.NewEncoder(tempFile)
	err = enc.Encode(session)
	if err != nil {
		return "", err
	}

	return tempFile.Name(), nil
}

func LoadSessionFromFile(filePath string) (*OidcSession, error) {
	f, err := os.OpenFile(filePath, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	// Lock the file until the process exits
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("could not lock session file: %w", err)
	}
	defer f.Close()
	var session OidcSession
	decoder := json.NewDecoder(f)
	err = decoder.Decode(&session)
	if err != nil {
		return nil, err
	}

	session.TLSConfig, err = createTLSConfig(session.CaCert)
	if err != nil {
		return nil, err
	}

	return &session, nil
}
