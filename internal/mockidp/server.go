// Package mockidp is a minimal OIDC provider for tests. No UI: the /authorize
// endpoint expects a ?user=<sub> query to pick which user to log in as.
package mockidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type User struct {
	Sub    string   `yaml:"sub"    json:"sub"`
	Email  string   `yaml:"email"  json:"email"`
	Groups []string `yaml:"groups" json:"groups"`
}

type Config struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	Users        []User `yaml:"users"`
}

type code struct {
	user       User
	nonce      string
	challenge  string
	method     string
	redirectTo string
	expiresAt  time.Time
}

// Server implements a minimal OIDC IdP. The Issuer field must be set to the
// externally-reachable base URL (used in discovery and the iss claim).
type Server struct {
	Issuer string
	Config Config

	key    *rsa.PrivateKey
	kid    string
	signer jose.Signer

	mu    sync.Mutex
	codes map[string]code
}

func New(issuer string, cfg Config) (*Server, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, fmt.Errorf("client_id and client_secret are required")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	kid := randID(8)
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		return nil, err
	}
	return &Server{
		Issuer: issuer, Config: cfg,
		key: key, kid: kid, signer: signer,
		codes: make(map[string]code),
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /.well-known/jwks.json", s.jwks)
	mux.HandleFunc("GET /authorize", s.authorize)
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	return mux
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{
		"issuer":                                s.Issuer,
		"authorization_endpoint":                s.Issuer + "/authorize",
		"token_endpoint":                        s.Issuer + "/token",
		"jwks_uri":                              s.Issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile", "groups"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
	}
	writeJSON(w, resp)
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	jwk := jose.JSONWebKey{
		Key:       &s.key.PublicKey,
		KeyID:     s.kid,
		Algorithm: "RS256",
		Use:       "sig",
	}
	writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		http.Error(w, "only response_type=code supported", http.StatusBadRequest)
		return
	}
	if q.Get("client_id") != s.Config.ClientID {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	redirect := q.Get("redirect_uri")
	if redirect == "" {
		http.Error(w, "redirect_uri required", http.StatusBadRequest)
		return
	}
	sub := q.Get("user")
	if sub == "" {
		http.Error(w, "append ?user=<sub> to pick a test user", http.StatusBadRequest)
		return
	}
	u, ok := s.findUser(sub)
	if !ok {
		http.Error(w, "unknown user "+sub, http.StatusNotFound)
		return
	}

	c := randID(24)
	s.mu.Lock()
	s.codes[c] = code{
		user:       u,
		nonce:      q.Get("nonce"),
		challenge:  q.Get("code_challenge"),
		method:     q.Get("code_challenge_method"),
		redirectTo: redirect,
		expiresAt:  time.Now().Add(2 * time.Minute),
	}
	s.mu.Unlock()

	dest, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	qv := dest.Query()
	qv.Set("code", c)
	if st := q.Get("state"); st != "" {
		qv.Set("state", st)
	}
	dest.RawQuery = qv.Encode()
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	clientID, clientSecret := authCreds(r)
	if clientID != s.Config.ClientID || clientSecret != s.Config.ClientSecret {
		http.Error(w, "bad client credentials", http.StatusUnauthorized)
		return
	}
	if r.FormValue("grant_type") != "authorization_code" {
		http.Error(w, "only authorization_code grant supported", http.StatusBadRequest)
		return
	}
	codeVal := r.FormValue("code")

	s.mu.Lock()
	c, ok := s.codes[codeVal]
	delete(s.codes, codeVal)
	s.mu.Unlock()
	if !ok {
		http.Error(w, "unknown code", http.StatusBadRequest)
		return
	}
	if time.Now().After(c.expiresAt) {
		http.Error(w, "code expired", http.StatusBadRequest)
		return
	}
	if c.challenge != "" {
		verifier := r.FormValue("code_verifier")
		if verifier == "" {
			http.Error(w, "PKCE verifier required", http.StatusBadRequest)
			return
		}
		got := pkceVerify(verifier, c.method)
		if got != c.challenge {
			http.Error(w, "PKCE mismatch", http.StatusBadRequest)
			return
		}
	}

	now := time.Now()
	claims := map[string]any{
		"iss":    s.Issuer,
		"sub":    c.user.Sub,
		"aud":    s.Config.ClientID,
		"exp":    now.Add(5 * time.Minute).Unix(),
		"iat":    now.Unix(),
		"email":  c.user.Email,
		"groups": c.user.Groups,
	}
	if c.nonce != "" {
		claims["nonce"] = c.nonce
	}
	idToken, err := jwt.Signed(s.signer).Claims(claims).Serialize()
	if err != nil {
		http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{
		"access_token": "opaque-" + randID(8),
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     idToken,
	})
}

func (s *Server) findUser(sub string) (User, bool) {
	for _, u := range s.Config.Users {
		if u.Sub == sub {
			return u, true
		}
	}
	return User{}, false
}

func authCreds(r *http.Request) (id, secret string) {
	if u, p, ok := r.BasicAuth(); ok {
		return u, p
	}
	return r.FormValue("client_id"), r.FormValue("client_secret")
}

func pkceVerify(verifier, method string) string {
	if method == "plain" || method == "" {
		return verifier
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
