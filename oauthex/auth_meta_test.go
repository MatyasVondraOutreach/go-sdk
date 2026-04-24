// Copyright 2025 The Go MCP SDK Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package oauthex

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthMetaParse(t *testing.T) {
	// Verify that we parse Google's auth server metadata.
	data, err := os.ReadFile(filepath.FromSlash("testdata/google-auth-meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var a AuthServerMeta
	if err := json.Unmarshal(data, &a); err != nil {
		t.Fatal(err)
	}
	// Spot check.
	if g, w := a.Issuer, "https://accounts.google.com"; g != w {
		t.Errorf("got %q, want %q", g, w)
	}
}

func TestGetAuthServerMetaPKCESupport(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name           string
		hasPKCESupport bool
		wantError      string
	}{
		{
			name:           "server_with_pkce_support",
			hasPKCESupport: true,
		},
		{
			name:           "server_without_pkce_support",
			hasPKCESupport: false,
			wantError:      "does not implement PKCE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start a fake OAuth 2.1 auth server
			wrapper := http.NewServeMux()
			wrapper.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
				u, _ := url.Parse("https://" + r.Host)
				issuer := "https://localhost:" + u.Port()
				metadata := AuthServerMeta{
					Issuer:                            issuer,
					AuthorizationEndpoint:             issuer + "/authorize",
					TokenEndpoint:                     issuer + "/token",
					RegistrationEndpoint:              issuer + "/register",
					JWKSURI:                           issuer + "/.well-known/jwks.json",
					ScopesSupported:                   []string{"openid", "profile", "email"},
					ResponseTypesSupported:            []string{"code"},
					GrantTypesSupported:               []string{"authorization_code"},
					TokenEndpointAuthMethodsSupported: []string{"none"},
				}

				// Add PKCE support based on test case
				if tt.hasPKCESupport {
					metadata.CodeChallengeMethodsSupported = []string{"S256"}
				}
				// If hasPKCESupport is false, CodeChallengeMethodsSupported remains empty

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(metadata)
			})
			ts := httptest.NewTLSServer(wrapper)
			defer ts.Close()

			// The fake server sets issuer to https://localhost:<port>, so compute that issuer.
			u, _ := url.Parse(ts.URL)
			issuer := "https://localhost:" + u.Port()
			metadataURL := issuer + "/.well-known/oauth-authorization-server"

			// The fake server presents a cert for example.com; set ServerName accordingly.
			httpClient := ts.Client()
			if tr, ok := httpClient.Transport.(*http.Transport); ok {
				clone := tr.Clone()
				clone.TLSClientConfig.ServerName = "example.com"
				httpClient.Transport = clone
			}

			meta, err := GetAuthServerMeta(ctx, metadataURL, issuer, httpClient)
			if tt.wantError != "" {
				if err == nil {
					t.Fatal("wanted error but got none")
				}
				if !strings.Contains(err.Error(), tt.wantError) {
					t.Errorf("wanted error to contain %q, but got: %v", tt.wantError, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unwanted error: %v", err)
				}
				if meta == nil {
					t.Fatal("wanted metadata but got nil")
				}
				// Verify PKCE support is present
				if len(meta.CodeChallengeMethodsSupported) == 0 {
					t.Error("wanted PKCE support but CodeChallengeMethodsSupported is empty")
				}
			}
		})
	}
}

func TestGetAuthServerMetaIssuerMismatch(t *testing.T) {
	ctx := context.Background()

	// Start a fake server whose ASM document has a different issuer
	// (simulating a proxy in front of Okta, like ZoomInfo).
	wrapper := http.NewServeMux()
	realIssuer := "https://okta-login.example.com/oauth2/default"
	wrapper.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		u, _ := url.Parse("https://" + r.Host)
		proxyBase := "https://localhost:" + u.Port()
		metadata := AuthServerMeta{
			Issuer:                            realIssuer,
			AuthorizationEndpoint:             proxyBase + "/oauth/authorize",
			TokenEndpoint:                     realIssuer + "/v1/token",
			RegistrationEndpoint:              proxyBase + "/oauth/register",
			JWKSURI:                           realIssuer + "/v1/keys",
			ResponseTypesSupported:            []string{"code"},
			GrantTypesSupported:               []string{"authorization_code"},
			TokenEndpointAuthMethodsSupported: []string{"client_secret_basic"},
			CodeChallengeMethodsSupported:     []string{"S256"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	})
	ts := httptest.NewTLSServer(wrapper)
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	proxyIssuer := "https://localhost:" + u.Port()
	metadataURL := proxyIssuer + "/.well-known/oauth-authorization-server"

	httpClient := ts.Client()
	if tr, ok := httpClient.Transport.(*http.Transport); ok {
		clone := tr.Clone()
		clone.TLSClientConfig.ServerName = "example.com"
		httpClient.Transport = clone
	}

	meta, err := GetAuthServerMeta(ctx, metadataURL, proxyIssuer, httpClient)
	if err == nil {
		t.Fatal("expected IssuerMismatchError, got nil")
	}

	var mismatchErr *IssuerMismatchError
	if !errors.As(err, &mismatchErr) {
		t.Fatalf("expected IssuerMismatchError, got %T: %v", err, err)
	}

	if mismatchErr.Expected != proxyIssuer {
		t.Errorf("Expected = %q, want %q", mismatchErr.Expected, proxyIssuer)
	}
	if mismatchErr.Got != realIssuer {
		t.Errorf("Got = %q, want %q", mismatchErr.Got, realIssuer)
	}
	if mismatchErr.Meta == nil {
		t.Fatal("Meta is nil, want parsed metadata")
	}
	if meta != nil {
		t.Error("return value should be nil on issuer mismatch")
	}

	// Verify the metadata is fully populated despite the mismatch.
	if mismatchErr.Meta.RegistrationEndpoint != proxyIssuer+"/oauth/register" {
		t.Errorf("RegistrationEndpoint = %q, want %q",
			mismatchErr.Meta.RegistrationEndpoint, proxyIssuer+"/oauth/register")
	}
	if mismatchErr.Meta.TokenEndpoint != realIssuer+"/v1/token" {
		t.Errorf("TokenEndpoint = %q, want %q",
			mismatchErr.Meta.TokenEndpoint, realIssuer+"/v1/token")
	}
}
