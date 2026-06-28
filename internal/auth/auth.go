package auth

import (
	"fmt"
	"time"
)

type FlowType int

const (
	FlowPKCE       FlowType = iota
	FlowDeviceCode          // reserved for future GitHub Copilot login
	FlowImportOnly
)

type Credential struct {
	Provider     string `json:"-"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
	AccountID    string `json:"account_id,omitempty"`
	Source       string `json:"source"`
}

func (c *Credential) ExpiresWithin(d time.Duration) bool {
	return time.Until(time.Unix(c.ExpiresAt, 0)) < d
}

// Status reports a human-readable validity state for display. A credential with
// no expiry (ExpiresAt == 0, e.g. a directly-supplied token) is reported as
// valid rather than expired — the ExpiresAt == 0 case is checked first.
func (c *Credential) Status() string {
	if c.ExpiresAt == 0 {
		return "valid (no expiry)"
	}
	if c.ExpiresWithin(0) {
		return "expired"
	}
	if c.ExpiresWithin(5 * time.Minute) {
		return "expiring soon"
	}
	return "valid"
}

func (c *Credential) ExtraHeaders() map[string]string {
	switch c.Provider {
	case "openai":
		if c.AccountID != "" {
			return map[string]string{"ChatGPT-Account-ID": c.AccountID}
		}
	case "anthropic":
		// Claude subscription OAuth tokens (sk-ant-oat01-*) are only accepted by
		// the Messages API (/v1/messages) when this beta header is present —
		// Bearer auth alone returns 401. ExtraHeaders is applied solely by the
		// subscription auth transport, so this never affects x-api-key requests.
		return map[string]string{"anthropic-beta": "oauth-2025-04-20"}
	}
	return nil
}

func (c *Credential) String() string {
	masked := "****"
	if len(c.AccessToken) >= 4 {
		masked += c.AccessToken[len(c.AccessToken)-4:]
	} else if len(c.AccessToken) > 0 {
		masked += c.AccessToken
	}
	return fmt.Sprintf("%s:%s", c.Provider, masked)
}

type ProviderConfig struct {
	AuthorizeURL    string
	TokenURL        string
	ClientID        string
	RedirectPort    int
	RedirectPath    string
	Scopes          []string
	ExtraAuthParams map[string]string
	FlowType        FlowType
	ImportPath      string
	AccountIDClaim  string
	// TokenRequestFormat selects how the token endpoint (exchange + refresh)
	// request body is encoded: "" / "form" = application/x-www-form-urlencoded
	// (standard OAuth 2.0, used by OpenAI); "json" = application/json, which
	// Anthropic's /v1/oauth/token requires — a form body there is rejected with
	// HTTP 400 invalid_request_error "Invalid request format".
	TokenRequestFormat string
}
