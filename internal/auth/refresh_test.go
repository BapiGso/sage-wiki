package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestRefreshPKCEToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
		}
		if r.Form.Get("refresh_token") != "rt-old" {
			t.Errorf("refresh_token = %q", r.Form.Get("refresh_token"))
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "at-refreshed",
			"refresh_token": "rt-new",
			"expires_in":    7200,
		})
	}))
	defer server.Close()

	origCfg := Providers["openai"]
	Providers["openai"] = ProviderConfig{
		TokenURL: server.URL,
		ClientID: "test-client",
		FlowType: FlowPKCE,
	}
	defer func() { Providers["openai"] = origCfg }()

	cred := &Credential{
		AccessToken:  "at-old",
		RefreshToken: "rt-old",
		ExpiresAt:    time.Now().Add(-1 * time.Hour).Unix(),
		AccountID:    "acct-123",
		Source:       "login",
	}

	refreshed, err := Refresh("openai", cred)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.AccessToken != "at-refreshed" {
		t.Errorf("AccessToken = %q", refreshed.AccessToken)
	}
	if refreshed.RefreshToken != "rt-new" {
		t.Errorf("RefreshToken = %q", refreshed.RefreshToken)
	}
	if refreshed.AccountID != "acct-123" {
		t.Errorf("AccountID should be preserved: %q", refreshed.AccountID)
	}
	if refreshed.Source != "login" {
		t.Errorf("Source should be preserved: %q", refreshed.Source)
	}
	if refreshed.ExpiresAt <= time.Now().Unix() {
		t.Error("ExpiresAt should be in the future")
	}
}

// TestRefreshPKCETokenJSON pins the Anthropic refresh request shape: when
// TokenRequestFormat == "json" the refresh body must be application/json too,
// otherwise login succeeds but the first refresh (~hours later) fails with the
// same "Invalid request format" and silently logs the user out.
func TestRefreshPKCETokenJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("request body is not valid JSON: %v", err)
		}
		if got, _ := body["grant_type"].(string); got != "refresh_token" {
			t.Errorf("grant_type = %q", got)
		}
		if got, _ := body["refresh_token"].(string); got != "rt-old" {
			t.Errorf("refresh_token = %q", got)
		}
		if got, _ := body["client_id"].(string); got != "anthropic-client" {
			t.Errorf("client_id = %q", got)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "at-refreshed",
			"refresh_token": "rt-new",
			"expires_in":    7200,
		})
	}))
	defer server.Close()

	origCfg := Providers["anthropic"]
	Providers["anthropic"] = ProviderConfig{
		TokenURL:           server.URL,
		ClientID:           "anthropic-client",
		FlowType:           FlowPKCE,
		TokenRequestFormat: "json",
	}
	defer func() { Providers["anthropic"] = origCfg }()

	cred := &Credential{AccessToken: "at-old", RefreshToken: "rt-old", Source: "login"}
	refreshed, err := Refresh("anthropic", cred)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.AccessToken != "at-refreshed" {
		t.Errorf("AccessToken = %q", refreshed.AccessToken)
	}
	if refreshed.RefreshToken != "rt-new" {
		t.Errorf("RefreshToken = %q", refreshed.RefreshToken)
	}
}

func TestRefreshPreservesRefreshTokenWhenNotReturned(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "at-refreshed",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	origCfg := Providers["openai"]
	Providers["openai"] = ProviderConfig{
		TokenURL: server.URL,
		ClientID: "test-client",
		FlowType: FlowPKCE,
	}
	defer func() { Providers["openai"] = origCfg }()

	cred := &Credential{RefreshToken: "rt-original"}
	refreshed, err := Refresh("openai", cred)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.RefreshToken != "rt-original" {
		t.Errorf("RefreshToken = %q, want preserved rt-original", refreshed.RefreshToken)
	}
}

func TestRefreshNoRefreshToken(t *testing.T) {
	cred := &Credential{AccessToken: "at-only"}
	_, err := Refresh("openai", cred)
	if err == nil {
		t.Error("expected error when no refresh token")
	}
}

func TestStoreRefreshAndGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "at-store-refreshed",
			"refresh_token": "rt-new",
			"expires_in":    3600,
		})
	}))
	defer server.Close()

	origCfg := Providers["openai"]
	Providers["openai"] = ProviderConfig{
		TokenURL: server.URL,
		ClientID: "test-client",
		FlowType: FlowPKCE,
	}
	defer func() { Providers["openai"] = origCfg }()

	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "auth.json"))

	store.Put("openai", &Credential{
		AccessToken:  "at-old",
		RefreshToken: "rt-old",
		ExpiresAt:    time.Now().Add(-1 * time.Hour).Unix(),
		Source:       "login",
	})

	refreshed, err := store.RefreshAndGet("openai")
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.AccessToken != "at-store-refreshed" {
		t.Errorf("AccessToken = %q", refreshed.AccessToken)
	}

	// Verify it was persisted
	persisted, _ := store.Get("openai")
	if persisted.AccessToken != "at-store-refreshed" {
		t.Errorf("persisted AccessToken = %q", persisted.AccessToken)
	}
}
