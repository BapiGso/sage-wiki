package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestGenerateVerifier(t *testing.T) {
	v, err := generateVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if len(v) < 43 {
		t.Errorf("verifier too short: %d chars", len(v))
	}
	// Must be base64url without padding
	if _, err := base64.RawURLEncoding.DecodeString(v); err != nil {
		t.Errorf("verifier is not valid base64url: %v", err)
	}

	v2, _ := generateVerifier()
	if v == v2 {
		t.Error("two verifiers should not be identical")
	}
}

func TestGenerateChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := generateChallenge(verifier)

	// Verify it's SHA256 of the verifier, base64url-encoded
	h := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(h[:])
	if challenge != expected {
		t.Errorf("challenge = %q, want %q", challenge, expected)
	}

	// Must be base64url without padding
	if _, err := base64.RawURLEncoding.DecodeString(challenge); err != nil {
		t.Errorf("challenge is not valid base64url: %v", err)
	}
}

func TestGenerateState(t *testing.T) {
	s, err := generateState()
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 32 { // 16 bytes hex-encoded
		t.Errorf("state length = %d, want 32", len(s))
	}

	s2, _ := generateState()
	if s == s2 {
		t.Error("two states should not be identical")
	}
}

func TestCallbackServer(t *testing.T) {
	result := make(chan callbackResult, 1)
	port, shutdown, err := startCallbackServer(0, "/callback", result)
	if err != nil {
		t.Fatal(err)
	}
	defer shutdown()

	// Simulate browser redirect to callback
	callbackURL := fmt.Sprintf("http://localhost:%d/callback?code=test-auth-code&state=test-state", port)
	resp, err := http.Get(callbackURL)
	if err != nil {
		t.Fatalf("callback request failed: %v", err)
	}
	resp.Body.Close()

	select {
	case r := <-result:
		if r.code != "test-auth-code" {
			t.Errorf("code = %q, want %q", r.code, "test-auth-code")
		}
		if r.state != "test-state" {
			t.Errorf("state = %q, want %q", r.state, "test-state")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for callback result")
	}
}

func TestCallbackServerWrongPath(t *testing.T) {
	result := make(chan callbackResult, 1)
	port, shutdown, err := startCallbackServer(0, "/callback", result)
	if err != nil {
		t.Fatal(err)
	}
	defer shutdown()

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/wrong-path?code=x&state=y", port))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}

	select {
	case <-result:
		t.Error("should not receive result on wrong path")
	case <-time.After(100 * time.Millisecond):
		// expected
	}
}

func TestExchangeCodeForTokens(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", ct)
		}

		r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %q", r.Form.Get("grant_type"))
		}
		if r.Form.Get("code") != "auth-code-123" {
			t.Errorf("code = %q", r.Form.Get("code"))
		}
		if r.Form.Get("code_verifier") != "my-verifier" {
			t.Errorf("code_verifier = %q", r.Form.Get("code_verifier"))
		}
		// Defense-in-depth: the OpenAI form body must carry client_id + redirect_uri
		// and must NOT gain `state` (that field is JSON/anthropic-only).
		if r.Form.Get("client_id") != "client-id" {
			t.Errorf("client_id = %q", r.Form.Get("client_id"))
		}
		if r.Form.Get("redirect_uri") != "http://localhost:1234/callback" {
			t.Errorf("redirect_uri = %q", r.Form.Get("redirect_uri"))
		}
		if r.Form.Has("state") {
			t.Errorf("form body must not include state, got %q", r.Form.Get("state"))
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "at-new-token",
			"refresh_token": "rt-new-token",
			"expires_in":    3600,
		})
	}))
	defer server.Close()

	cfg := ProviderConfig{TokenURL: server.URL, ClientID: "client-id"} // default: form
	tok, err := exchangeCodeForTokens(cfg, "auth-code-123", "test-state", "my-verifier", "http://localhost:1234/callback")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "at-new-token" {
		t.Errorf("AccessToken = %q", tok.AccessToken)
	}
	if tok.RefreshToken != "rt-new-token" {
		t.Errorf("RefreshToken = %q", tok.RefreshToken)
	}
	if tok.ExpiresAt <= time.Now().Unix() {
		t.Error("ExpiresAt should be in the future")
	}
}

// TestExchangeCodeForTokensJSON pins the Anthropic token-exchange request shape:
// when TokenRequestFormat == "json", the body must be application/json (a
// form-encoded body is rejected by /v1/oauth/token with 400 "Invalid request
// format") and must echo the PKCE state. This is the reproducing test for the
// VPS login bug.
func TestExchangeCodeForTokensJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("request body is not valid JSON: %v", err)
		}
		for k, want := range map[string]string{
			"grant_type":    "authorization_code",
			"code":          "auth-code-123",
			"state":         "the-state",
			"code_verifier": "my-verifier",
			"client_id":     "anthropic-client",
			"redirect_uri":  "http://localhost:53692/callback",
		} {
			if got, _ := body[k].(string); got != want {
				t.Errorf("body[%q] = %q, want %q", k, got, want)
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "at-json",
			"refresh_token": "rt-json",
			"expires_in":    3600,
		})
	}))
	defer server.Close()

	cfg := ProviderConfig{TokenURL: server.URL, ClientID: "anthropic-client", TokenRequestFormat: "json"}
	tok, err := exchangeCodeForTokens(cfg, "auth-code-123", "the-state", "my-verifier", "http://localhost:53692/callback")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "at-json" {
		t.Errorf("AccessToken = %q", tok.AccessToken)
	}
	if tok.RefreshToken != "rt-json" {
		t.Errorf("RefreshToken = %q", tok.RefreshToken)
	}
}

// TestAnthropicTokenFormatWired guards the production wiring: the synthetic-cfg
// tests above would stay green even if the real anthropic provider lost its
// "json" format, silently reshipping the bug. This asserts the actual config.
func TestAnthropicTokenFormatWired(t *testing.T) {
	if got := Providers["anthropic"].TokenRequestFormat; got != "json" {
		t.Errorf("Providers[\"anthropic\"].TokenRequestFormat = %q, want \"json\"", got)
	}
	if got := Providers["openai"].TokenRequestFormat; got != "" {
		t.Errorf("Providers[\"openai\"].TokenRequestFormat = %q, want \"\" (form)", got)
	}
}

func TestExtractAccountID(t *testing.T) {
	// Build a mock JWT with the OpenAI claim
	payload := map[string]interface{}{
		"sub": "user-123",
		"https://api.openai.com/auth.chatgpt_account_id": "acct-abc-456",
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// JWT format: header.payload.signature
	fakeJWT := "eyJhbGciOiJSUzI1NiJ9." + payloadB64 + ".fake-signature"

	accountID := extractAccountID(fakeJWT, "https://api.openai.com/auth.chatgpt_account_id")
	if accountID != "acct-abc-456" {
		t.Errorf("accountID = %q, want %q", accountID, "acct-abc-456")
	}
}

func TestExtractAccountIDMissingClaim(t *testing.T) {
	payload := map[string]interface{}{"sub": "user-123"}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	fakeJWT := "eyJhbGciOiJSUzI1NiJ9." + payloadB64 + ".fake-signature"

	accountID := extractAccountID(fakeJWT, "https://api.openai.com/auth.chatgpt_account_id")
	if accountID != "" {
		t.Errorf("expected empty accountID, got %q", accountID)
	}
}

func TestExtractAccountIDInvalidJWT(t *testing.T) {
	accountID := extractAccountID("not-a-jwt", "claim")
	if accountID != "" {
		t.Errorf("expected empty accountID for invalid JWT, got %q", accountID)
	}
}

// stubNoBrowser forces openBrowserFn to report "no browser" so login tests
// take a deterministic path and never spawn a real browser.
func stubNoBrowser(t *testing.T) {
	t.Helper()
	orig := openBrowserFn
	openBrowserFn = func(string) error { return fmt.Errorf("stub: no browser in tests") }
	t.Cleanup(func() { openBrowserFn = orig })
}

func TestLoginPKCEFullFlow(t *testing.T) {
	stubNoBrowser(t)
	// Mock token endpoint
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" {
			t.Errorf("unexpected grant_type: %s", r.Form.Get("grant_type"))
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token":  "at-test-login",
			"refresh_token": "rt-test-login",
			"expires_in":    3600,
		})
	}))
	defer tokenServer.Close()

	// Override provider config to point to mock server
	origCfg := Providers["openai"]
	Providers["openai"] = ProviderConfig{
		AuthorizeURL: origCfg.AuthorizeURL,
		TokenURL:     tokenServer.URL,
		ClientID:     origCfg.ClientID,
		RedirectPort: 0, // will be overridden by callback server
		RedirectPath: "/auth/callback",
		Scopes:       origCfg.Scopes,
		FlowType:     FlowPKCE,
	}
	defer func() { Providers["openai"] = origCfg }()

	dir := t.TempDir()
	store := NewStore(dir + "/auth.json")

	var loginSuccess bool
	err := LoginPKCE("openai", store, LoginCallbacks{
		OnManualURL: func(authorizeURL string) string {
			// Parse the authorize URL to get the state parameter
			u, _ := url.Parse(authorizeURL)
			state := u.Query().Get("state")
			// Return a fake redirect URL with the state and a code
			return fmt.Sprintf("http://localhost:9999/auth/callback?code=manual-code&state=%s", state)
		},
		OnSuccess: func(provider string) {
			loginSuccess = true
		},
	})
	if err != nil {
		t.Fatalf("LoginPKCE: %v", err)
	}

	if !loginSuccess {
		t.Error("OnSuccess was not called")
	}

	cred, err := store.Get("openai")
	if err != nil {
		t.Fatalf("Get after login: %v", err)
	}
	if cred.AccessToken != "at-test-login" {
		t.Errorf("AccessToken = %q, want %q", cred.AccessToken, "at-test-login")
	}
}

// TestLoginPKCEPromptShowsURL pins the "always display the link" behavior: the
// authorize URL is surfaced via OnPrompt regardless of whether a browser
// opened, and a pasted redirect URL completes the flow.
func TestLoginPKCEPromptShowsURL(t *testing.T) {
	stubNoBrowser(t)
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "at-prompt", "refresh_token": "rt-prompt", "expires_in": 3600,
		})
	}))
	defer tokenServer.Close()

	origCfg := Providers["openai"]
	Providers["openai"] = ProviderConfig{
		AuthorizeURL: origCfg.AuthorizeURL,
		TokenURL:     tokenServer.URL,
		ClientID:     origCfg.ClientID,
		RedirectPath: "/auth/callback",
		Scopes:       origCfg.Scopes,
		FlowType:     FlowPKCE,
	}
	defer func() { Providers["openai"] = origCfg }()

	dir := t.TempDir()
	store := NewStore(dir + "/auth.json")

	var promptCalled bool
	var promptedURL string
	err := LoginPKCE("openai", store, LoginCallbacks{
		OnPrompt: func(authorizeURL string, browserOpened bool) {
			promptCalled = true
			promptedURL = authorizeURL
		},
		OnManualURL: func(authorizeURL string) string {
			u, _ := url.Parse(authorizeURL)
			state := u.Query().Get("state")
			return fmt.Sprintf("http://localhost:9999/auth/callback?code=manual-code&state=%s", state)
		},
	})
	if err != nil {
		t.Fatalf("LoginPKCE: %v", err)
	}
	if !promptCalled {
		t.Error("OnPrompt was not called — the auth URL must always be shown")
	}
	if u, perr := url.Parse(promptedURL); perr != nil || u.Query().Get("code_challenge") == "" {
		t.Errorf("authorize URL malformed or empty: %q", promptedURL)
	}
}

// TestLoginPKCECallbackServerPath exercises the desktop branch: the local
// callback server (not a pasted URL) completes the flow. OnPrompt simulates the
// browser redirect by extracting the real redirect_uri/state from the authorize
// URL and hitting the callback server.
func TestLoginPKCECallbackServerPath(t *testing.T) {
	stubNoBrowser(t)
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "at-server", "refresh_token": "rt-server", "expires_in": 3600,
		})
	}))
	defer tokenServer.Close()

	origCfg := Providers["openai"]
	Providers["openai"] = ProviderConfig{
		AuthorizeURL: origCfg.AuthorizeURL,
		TokenURL:     tokenServer.URL,
		ClientID:     origCfg.ClientID,
		RedirectPort: 0, // random port chosen by the callback server
		RedirectPath: "/auth/callback",
		Scopes:       origCfg.Scopes,
		FlowType:     FlowPKCE,
	}
	defer func() { Providers["openai"] = origCfg }()

	dir := t.TempDir()
	store := NewStore(dir + "/auth.json")

	// No OnManualURL: only the local callback server can complete the flow.
	done := make(chan error, 1)
	go func() {
		done <- LoginPKCE("openai", store, LoginCallbacks{
			OnPrompt: func(authorizeURL string, browserOpened bool) {
				u, err := url.Parse(authorizeURL)
				if err != nil {
					t.Errorf("parse authorize URL: %v", err)
					return
				}
				redirect := u.Query().Get("redirect_uri")
				state := u.Query().Get("state")
				resp, err := http.Get(fmt.Sprintf("%s?code=server-code&state=%s", redirect, state))
				if err != nil {
					t.Errorf("callback GET: %v", err)
					return
				}
				resp.Body.Close()
			},
		})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("LoginPKCE via callback server: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for LoginPKCE to complete via callback server")
	}

	cred, err := store.Get("openai")
	if err != nil {
		t.Fatalf("Get after login: %v", err)
	}
	if cred.AccessToken != "at-server" {
		t.Errorf("AccessToken = %q, want at-server", cred.AccessToken)
	}
}

func TestLoginPKCEStateMismatch(t *testing.T) {
	stubNoBrowser(t)
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok", "refresh_token": "rt", "expires_in": 3600,
		})
	}))
	defer tokenServer.Close()

	origCfg := Providers["openai"]
	Providers["openai"] = ProviderConfig{
		AuthorizeURL: origCfg.AuthorizeURL,
		TokenURL:     tokenServer.URL,
		ClientID:     origCfg.ClientID,
		RedirectPath: "/auth/callback",
		Scopes:       origCfg.Scopes,
		FlowType:     FlowPKCE,
	}
	defer func() { Providers["openai"] = origCfg }()

	dir := t.TempDir()
	store := NewStore(dir + "/auth.json")

	err := LoginPKCE("openai", store, LoginCallbacks{
		OnManualURL: func(authorizeURL string) string {
			return "http://localhost:9999/callback?code=code&state=wrong-state"
		},
	})
	if err == nil {
		t.Error("expected state mismatch error")
	}
}

func TestLoginPKCEImportOnlyProvider(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir + "/auth.json")
	err := LoginPKCE("gemini", store, LoginCallbacks{})
	if err == nil {
		t.Error("expected error for import-only provider")
	}
}

func TestBuildAuthorizeURL(t *testing.T) {
	cfg := Providers["openai"]
	authURL := buildAuthorizeURL(cfg, "test-challenge", "test-state", 1455)

	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "auth.openai.com" {
		t.Errorf("host = %q", u.Host)
	}
	q := u.Query()
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q", q.Get("response_type"))
	}
	if q.Get("client_id") != cfg.ClientID {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("code_challenge") != "test-challenge" {
		t.Errorf("code_challenge = %q", q.Get("code_challenge"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q", q.Get("code_challenge_method"))
	}
	if q.Get("state") != "test-state" {
		t.Errorf("state = %q", q.Get("state"))
	}
	// Check extra params
	if q.Get("codex_cli_simplified_flow") != "true" {
		t.Errorf("codex_cli_simplified_flow = %q", q.Get("codex_cli_simplified_flow"))
	}
}
