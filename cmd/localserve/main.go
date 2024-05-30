package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
)

func main() {
	ctx, cacnel := signal.NotifyContext(context.Background(), os.Interrupt)

	defer cacnel()

	if err := run(ctx); err != nil {
		os.Stderr.WriteString(err.Error())
	}
}

func run(ctx context.Context) error {
	p, err := oidc.NewProvider(ctx, "https://login.microsoftonline.com/<app-id>v2.0")

	if err != nil {
		return err
	}

	oauth2Config := oauth2.Config{
		ClientID:     "<client-id>",
		ClientSecret: os.ExpandEnv("OIDC_SECRET"),
		Endpoint:     p.Endpoint(),
		RedirectURL:  "http://localhost:8080/callback",
		Scopes: []string{
			oidc.ScopeOpenID,
			"profile",
			"api://<client-id>/roles",
		},
	}

	var mux http.ServeMux

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, oauth2Config.AuthCodeURL("na"), http.StatusFound)
	})

	mux.HandleFunc("/callback", callback(ctx, oauth2Config, p))

	h := http.Server{
		Addr:    "0.0.0.0:8080",
		Handler: &mux,
	}

	grp, ctx := errgroup.WithContext(ctx)

	grp.Go(func() error {
		if err := h.ListenAndServe(); errors.Is(err, http.ErrServerClosed) {
			println("server stopped")
			return nil
		}
		return err
	})

	grp.Go(func() error {
		<-ctx.Done()
		println("shutdown requested")
		return h.Shutdown(ctx)
	})

	return grp.Wait()
}

func callback(
	ctx context.Context,
	oauth2Config oauth2.Config,
	p *oidc.Provider) http.HandlerFunc {
	v := p.VerifierContext(ctx, &oidc.Config{
		ClientID: oauth2Config.ClientID,
		Now:      time.Now,
	})

	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		w.Header().Add("Content-Type", "application/json")

		oauth2Token, err := oauth2Config.Exchange(ctx, r.URL.Query().Get("code"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Extract the ID Token from OAuth2 token.
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "no token", http.StatusInternalServerError)
			return
		}

		// Parse and verify ID Token payload.
		idToken, err := v.Verify(ctx, rawIDToken)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		idc := map[string]any{}

		if err := idToken.Claims(&idc); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		a, err := jose.ParseSigned(oauth2Token.AccessToken)

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		accessToken := map[string]any{}

		if err := json.Unmarshal(a.UnsafePayloadWithoutVerification(), &accessToken); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		res, err := oauth2.NewClient(ctx, oauth2.StaticTokenSource(oauth2Token)).Get("https://<app-url>/oidc/userinfo")

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		claims := map[string]any{}

		if err := json.NewDecoder(res.Body).Decode(&claims); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// profile, err := p.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))

		// if err != nil {
		// 	http.Error(w, err.Error(), http.StatusInternalServerError)
		// 	return
		// }

		// claims := map[string]any{}

		// if err := profile.Claims(&claims); err != nil {
		// 	http.Error(w, err.Error(), http.StatusInternalServerError)
		// 	return
		// }

		// roles, err := fetchRoles(ctx, idToken.Subject, oauth2Token)

		// if err != nil {
		// 	http.Error(w, err.Error(), http.StatusInternalServerError)
		// 	return
		// }

		if err := json.NewEncoder(w).Encode(map[string]any{
			"id_token": idToken,
			"access":   accessToken,
			"refresh":  oauth2Token.RefreshToken,
			"idc":      idc,
			"profile":  claims,
			// "roles":    roles,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func fetchRoles(ctx context.Context, subject string, token *oauth2.Token) (map[string]any, error) {
	c := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	u := "https://graph.microsoft.com/beta/me/appRoleAssignments"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	res, err := c.Do(req)

	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("incorrect status code: %d, %s", res.StatusCode, b)
	}

	b := map[string]any{}

	if err := json.NewDecoder(res.Body).Decode(&b); err != nil {
		return nil, err
	}

	return b, nil
}
