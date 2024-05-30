package test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"
)

// OIDC simulates the behaviour of the Azure OIDC server
type OIDC struct {
	u          *url.URL
	kid        string
	signer     jose.Signer
	privateKey *rsa.PrivateKey
	cert       *x509.Certificate
}

// Issuer of the oidc server
func (o *OIDC) Issuer() string { return o.u.String() }

// URL returns the URL of the OIDC Server
func (o *OIDC) URL() url.URL { return *o.u }

// GenerateJWT creates a new JWT token, signed by the OIDC server's
// signer. Default values can be overridden by setting them on cl.
func (o *OIDC) GenerateJWT(tb testing.TB, cl jwt.Claims) string {
	if cl.Issuer == "" {
		cl.Issuer = o.Issuer()
	}
	if len(cl.Audience) == 0 {
		cl.Audience = []string{"some-client"}
	}
	if cl.IssuedAt == nil {
		cl.IssuedAt = jwt.NewNumericDate(Time)
	}
	if cl.Expiry == nil {
		cl.Expiry = jwt.NewNumericDate(Time.Add(time.Minute))
	}
	if cl.Subject == "" {
		cl.Subject = "user_sub"
	}

	raw, err := jwt.
		Signed(o.signer).
		Claims(cl).
		CompactSerialize()

	require.NoError(tb, err)
	return raw
}

// simplified version of what's returned by Azure OIDC well-known endpoint
// see https://login.microsoftonline.com/ea80952e-a476-42d4-aaf4-5457852b0f7e/v2.0/.well-known/openid-configuration
func (o *OIDC) openidConfiguration(w http.ResponseWriter, r *http.Request) {
	r.Header.Add("Content-Type", "application/json")

	tokenEp, err := url.JoinPath(o.u.String(), "/oauth2/v2.0/token")

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	keysEp, err := url.JoinPath(o.u.String(), "/discovery/v2.0/keys")

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(struct {
		Issuer                           string   `json:"issuer"`
		TokenEndpoint                    string   `json:"token_endpoint"`
		IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
		JWKSURI                          string   `json:"jwks_uri"`
	}{
		Issuer:                           o.Issuer(),
		TokenEndpoint:                    tokenEp,
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		JWKSURI:                          keysEp,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// simplified version of what's returned by Azure OIDC keys end
func (o *OIDC) jwksURI(w http.ResponseWriter, r *http.Request) {
	r.Header.Add("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(&jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Certificates: []*x509.Certificate{o.cert},
				Key:          &o.privateKey.PublicKey,
				KeyID:        o.kid,
				Use:          "sig",
			},
		},
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// OIDCServer creates a new OIDC server and creates the cleanup handler
func OIDCServer(tb testing.TB) *OIDC {
	r := require.New(tb)

	var (
		result OIDC
		err    error
	)

	result.privateKey, result.cert, err = generateOIDCCrypto()
	r.NoError(err)

	result.kid = result.privateKey.PublicKey.N.String()

	// Instantiate a signer using RSA with the given private key.
	result.signer, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: result.privateKey}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{"kid": result.kid},
	})
	r.NoError(err)

	var mux http.ServeMux

	mux.HandleFunc("/.well-known/openid-configuration", result.openidConfiguration)
	mux.HandleFunc("/discovery/v2.0/keys", result.jwksURI)

	s := httptest.NewServer(&mux)
	tb.Cleanup(s.Close)

	result.u, err = url.ParseRequestURI(s.URL)
	r.NoError(err)

	return &result
}

func generateOIDCCrypto() (*rsa.PrivateKey, *x509.Certificate, error) {
	reader := rand.Reader

	// Generate a public/private key pair to use for this example.
	privateKey, err := rsa.GenerateKey(reader, 2048)

	if err != nil {
		return nil, nil, fmt.Errorf("privateKey: %w", err)
	}

	serialNumber, err := rand.Int(reader, big.NewInt(100))

	if err != nil {
		return nil, nil, fmt.Errorf("serialNumber: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Example Co"}}, //nolint:misspell
		NotBefore:             Time,
		NotAfter:              Time.Add(2 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)

	if err != nil {
		return nil, nil, fmt.Errorf("x509 cert: %w", err)
	}

	certificate, err := x509.ParseCertificate(derBytes)

	if err != nil {
		return nil, nil, fmt.Errorf("x509 parsing cert: %w", err)
	}

	return privateKey, certificate, nil
}
