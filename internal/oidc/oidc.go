package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/alexedwards/scs/v2"
	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/patric/vpn-manager/internal/config"
	"github.com/patric/vpn-manager/internal/store"
)

const (
	sessionStateKey  = "oidc.state"
	sessionNonceKey  = "oidc.nonce"
	sessionPKCEKey   = "oidc.pkce"
	sessionUserIDKey = "user.id"
	sessionEmailKey  = "user.email"
	sessionGroupsKey = "user.groups"
)

type Handler struct {
	cfg       *config.Config
	store     *store.Store
	session   *scs.SessionManager
	provider  *gooidc.Provider
	verifier  *gooidc.IDTokenVerifier
	oauth2cfg oauth2.Config
}

func New(ctx context.Context, cfg *config.Config, st *store.Store, sm *scs.SessionManager) (*Handler, error) {
	provider, err := gooidc.NewProvider(ctx, cfg.OIDC.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	oauth2cfg := oauth2.Config{
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDCClientSecret(),
		Endpoint:     provider.Endpoint(),
		RedirectURL:  strings.TrimRight(cfg.PublicURL, "/") + "/auth/callback",
		Scopes:       cfg.OIDC.Scopes,
	}
	verifier := provider.Verifier(&gooidc.Config{ClientID: cfg.OIDC.ClientID})
	return &Handler{
		cfg:       cfg,
		store:     st,
		session:   sm,
		provider:  provider,
		verifier:  verifier,
		oauth2cfg: oauth2cfg,
	}, nil
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	state := randToken(24)
	nonce := randToken(24)
	verifier := oauth2.GenerateVerifier()

	h.session.Put(r.Context(), sessionStateKey, state)
	h.session.Put(r.Context(), sessionNonceKey, nonce)
	h.session.Put(r.Context(), sessionPKCEKey, verifier)

	url := h.oauth2cfg.AuthCodeURL(state,
		gooidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	)
	http.Redirect(w, r, url, http.StatusFound)
}

func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wantState := h.session.GetString(ctx, sessionStateKey)
	wantNonce := h.session.GetString(ctx, sessionNonceKey)
	verifier := h.session.GetString(ctx, sessionPKCEKey)
	h.session.Remove(ctx, sessionStateKey)
	h.session.Remove(ctx, sessionNonceKey)
	h.session.Remove(ctx, sessionPKCEKey)

	if got := r.URL.Query().Get("state"); got == "" || got != wantState {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	tok, err := h.oauth2cfg.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in response", http.StatusBadGateway)
		return
	}
	idTok, err := h.verifier.Verify(ctx, rawID)
	if err != nil {
		http.Error(w, "id_token verify: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if idTok.Nonce != wantNonce {
		http.Error(w, "nonce mismatch", http.StatusUnauthorized)
		return
	}

	var claims map[string]any
	if err := idTok.Claims(&claims); err != nil {
		http.Error(w, "id_token claims: "+err.Error(), http.StatusBadGateway)
		return
	}
	sub := idTok.Subject
	email, _ := claims["email"].(string)
	if email == "" {
		email = sub
	}
	groups := extractGroups(claims, h.cfg.OIDC.GroupsClaim)

	user, err := h.store.UpsertUser(ctx, sub, email, groups)
	if err != nil {
		http.Error(w, "store user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.session.Put(ctx, sessionUserIDKey, user.ID)
	h.session.Put(ctx, sessionEmailKey, user.Email)
	gJSON, _ := json.Marshal(user.Groups)
	h.session.Put(ctx, sessionGroupsKey, string(gJSON))

	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	_ = h.session.Destroy(r.Context())
	http.Redirect(w, r, "/", http.StatusFound)
}

// Middleware redirects unauthenticated requests to /auth/login.
func (h *Handler) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.session.GetInt64(r.Context(), sessionUserIDKey) == 0 {
			http.Redirect(w, r, "/auth/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type SessionUser struct {
	ID     int64
	Email  string
	Groups []string
}

func (h *Handler) CurrentUser(r *http.Request) (*SessionUser, bool) {
	id := h.session.GetInt64(r.Context(), sessionUserIDKey)
	if id == 0 {
		return nil, false
	}
	su := &SessionUser{
		ID:    id,
		Email: h.session.GetString(r.Context(), sessionEmailKey),
	}
	if g := h.session.GetString(r.Context(), sessionGroupsKey); g != "" {
		_ = json.Unmarshal([]byte(g), &su.Groups)
	}
	return su, true
}

func extractGroups(claims map[string]any, claim string) []string {
	v, ok := claims[claim]
	if !ok {
		return nil
	}
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, g := range x {
			if s, ok := g.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return x
	case string:
		return []string{x}
	}
	return nil
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
