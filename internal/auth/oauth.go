package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func generateVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: generate verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: generate state: %w", err)
	}
	return hex.EncodeToString(b), nil
}

type callbackResult struct {
	code  string
	state string
}

func startCallbackServer(preferredPort int, path string, result chan<- callbackResult) (port int, shutdown func(), err error) {
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		result <- callbackResult{code: code, state: state}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body><h2>Authorization complete.</h2><p>You can close this tab.</p></body></html>")
	})

	addr := fmt.Sprintf("127.0.0.1:%d", preferredPort)
	listener, err := net.Listen("tcp", addr)
	if err != nil && preferredPort != 0 {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		return 0, nil, fmt.Errorf("auth: start callback server: %w", err)
	}

	port = listener.Addr().(*net.TCPAddr).Port
	server := &http.Server{Handler: mux}

	go server.Serve(listener)

	return port, func() { server.Close() }, nil
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// buildTokenRequest serializes token-endpoint parameters as either a
// form-encoded body (standard OAuth 2.0, used by OpenAI) or a JSON body
// (required by Anthropic's /v1/oauth/token — a form body there is rejected with
// 400 invalid_request_error "Invalid request format"). It returns the body
// reader and the matching Content-Type.
func buildTokenRequest(format string, fields map[string]string) (io.Reader, string, error) {
	if format == "json" {
		b, err := json.Marshal(fields)
		if err != nil {
			return nil, "", fmt.Errorf("auth: marshal token request: %w", err)
		}
		return bytes.NewReader(b), "application/json", nil
	}
	data := url.Values{}
	for k, v := range fields {
		data.Set(k, v)
	}
	return strings.NewReader(data.Encode()), "application/x-www-form-urlencoded", nil
}

func exchangeCodeForTokens(cfg ProviderConfig, code, state, verifier, redirectURI string) (*Credential, error) {
	fields := map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"code_verifier": verifier,
		"client_id":     cfg.ClientID,
		"redirect_uri":  redirectURI,
	}
	// Anthropic's token endpoint expects the PKCE `state` echoed in the exchange
	// body (the reference Claude OAuth client sends it). The standard OAuth form
	// flow (OpenAI) omits it, so add `state` only on the JSON path — this keeps
	// the form body byte-for-byte identical to the proven OpenAI request.
	if cfg.TokenRequestFormat == "json" {
		fields["state"] = state
	}

	reqBody, contentType, err := buildTokenRequest(cfg.TokenRequestFormat, fields)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(cfg.TokenURL, contentType, reqBody)
	if err != nil {
		return nil, fmt.Errorf("auth: token exchange: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("auth: read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		truncated := string(body)
		if len(truncated) > 500 {
			truncated = truncated[:500] + "..."
		}
		return nil, fmt.Errorf("auth: token exchange returned %d: %s", resp.StatusCode, truncated)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("auth: parse token response: %w", err)
	}

	expiresAt := time.Now().Unix() + int64(tok.ExpiresIn) - 300
	if tok.ExpiresIn == 0 {
		expiresAt = time.Now().Add(1 * time.Hour).Unix()
	}

	return &Credential{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		ExpiresAt:    expiresAt,
		Source:       "login",
	}, nil
}

func extractAccountID(jwt string, claim string) string {
	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) < 2 {
		return ""
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}

	if v, ok := claims[claim]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func buildAuthorizeURL(cfg ProviderConfig, challenge, state string, port int) string {
	u, _ := url.Parse(cfg.AuthorizeURL)
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", fmt.Sprintf("http://localhost:%d%s", port, cfg.RedirectPath))
	q.Set("scope", strings.Join(cfg.Scopes, " "))
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	for k, v := range cfg.ExtraAuthParams {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// openBrowserFn launches the system browser. Indirected through a variable so
// tests can stub it (and so they never spawn a real browser).
var openBrowserFn = openBrowser

// loginTimeout bounds how long LoginPKCE waits for the authorization to
// complete (via the local callback server or a pasted redirect URL). Generous
// enough for the headless flow: copy the URL, open it on another machine,
// authorize, then paste the redirect URL back.
const loginTimeout = 5 * time.Minute

// LoginCallbacks allows the CLI layer to control UI interactions.
type LoginCallbacks struct {
	// OnPrompt is called once with the authorization URL and whether a browser
	// was launched. The CLI ALWAYS displays the URL so the user can open it
	// manually (e.g. on a headless/remote server where no browser is present).
	OnPrompt func(authorizeURL string, browserOpened bool)
	// OnManualURL blocks reading a pasted redirect URL from the user and
	// returns it (empty string if none). It runs concurrently with the local
	// callback server so either path can complete the flow.
	OnManualURL func(authorizeURL string) string
	OnSuccess   func(provider string)
}

// LoginPKCE performs the full PKCE OAuth flow for a provider.
func LoginPKCE(providerName string, store *Store, cb LoginCallbacks) error {
	cfg, ok := Providers[providerName]
	if !ok {
		return fmt.Errorf("auth: unknown provider %q", providerName)
	}
	if cfg.FlowType != FlowPKCE {
		return fmt.Errorf("auth: provider %q does not support OAuth login (use import instead)", providerName)
	}

	verifier, err := generateVerifier()
	if err != nil {
		return err
	}
	challenge := generateChallenge(verifier)
	state, err := generateState()
	if err != nil {
		return err
	}

	resultCh := make(chan callbackResult, 1)
	port, shutdown, err := startCallbackServer(cfg.RedirectPort, cfg.RedirectPath, resultCh)
	if err != nil {
		return err
	}
	defer shutdown()

	authorizeURL := buildAuthorizeURL(cfg, challenge, state, port)
	redirectURI := fmt.Sprintf("http://localhost:%d%s", port, cfg.RedirectPath)

	// Attempt to open a browser, but never rely on it: openBrowser returns nil
	// as soon as the launcher process starts (e.g. xdg-open on a headless box),
	// which tells us nothing about whether a browser actually appeared. So we
	// always show the URL and accept the redirect via EITHER the local callback
	// server (browser on this machine) OR a manually-pasted redirect URL
	// (browser on another machine — headless/remote server). First one wins.
	browserOpened := openBrowserFn(authorizeURL) == nil

	if cb.OnPrompt != nil {
		cb.OnPrompt(authorizeURL, browserOpened)
	}

	pasteCh := make(chan callbackResult, 1)
	if cb.OnManualURL != nil {
		go func() {
			pasted := strings.TrimSpace(cb.OnManualURL(authorizeURL))
			if pasted == "" {
				return
			}
			parsed, err := url.Parse(pasted)
			if err != nil {
				return
			}
			pasteCh <- callbackResult{
				code:  parsed.Query().Get("code"),
				state: parsed.Query().Get("state"),
			}
		}()
	}

	var cbResult callbackResult
	select {
	case cbResult = <-resultCh:
	case cbResult = <-pasteCh:
	case <-time.After(loginTimeout):
		return fmt.Errorf("auth: authorization timed out (%s)", loginTimeout)
	}

	if cbResult.code == "" {
		return fmt.Errorf("auth: no authorization code received")
	}
	if cbResult.state != state {
		return fmt.Errorf("auth: state mismatch (possible CSRF attack)")
	}

	cred, err := exchangeCodeForTokens(cfg, cbResult.code, cbResult.state, verifier, redirectURI)
	if err != nil {
		return err
	}

	if cfg.AccountIDClaim != "" {
		cred.AccountID = extractAccountID(cred.AccessToken, cfg.AccountIDClaim)
	}

	if err := store.Put(providerName, cred); err != nil {
		return err
	}

	if cb.OnSuccess != nil {
		cb.OnSuccess(providerName)
	}

	return nil
}
