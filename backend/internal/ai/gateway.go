package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Gateway is the LLM gateway to Anthropic's Messages API. When no API key is
// configured it is unavailable and callers fall back to a deterministic,
// evidence-only summary — so the platform runs offline without an AI provider.
type Gateway struct {
	apiKey string
	model  string
	http   *http.Client
}

// NewGateway builds the gateway. model defaults to a current Claude model.
func NewGateway(apiKey, model string) *Gateway {
	if model == "" {
		model = "claude-sonnet-5"
	}
	// The gateway only ever calls the hardcoded api.anthropic.com host (see Complete), never a
	// tenant-configurable URL, so it is not an SSRF surface. All tenant-URL clients MUST use
	// netsafe.SafeClient (enforced by scripts/check-outbound-http.sh in CI).
	return &Gateway{apiKey: apiKey, model: model, http: &http.Client{Timeout: 30 * time.Second}} // netsafe-exempt: hardcoded api.anthropic.com host
}

// Available reports whether a live LLM is configured.
func (g *Gateway) Available() bool { return g.apiKey != "" }

// Model returns the configured model id (for audit logging).
func (g *Gateway) Model() string {
	if g.apiKey == "" {
		return "offline-fallback"
	}
	return g.model
}

type msgReq struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system"`
	Messages  []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type msgResp struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Complete calls the Messages API with a system prompt and user content.
func (g *Gateway) Complete(ctx context.Context, system, user string) (string, error) {
	body, _ := json.Marshal(msgReq{
		Model: g.model, MaxTokens: 700, System: system,
		Messages: []message{{Role: "user", Content: user}},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", g.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := g.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var out msgResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Error != nil {
		return "", fmt.Errorf("anthropic: %s", out.Error.Message)
	}
	if len(out.Content) == 0 {
		return "", fmt.Errorf("anthropic: empty response")
	}
	// R6: return the first TEXT block, not blindly Content[0] — a response whose first block is a
	// non-text type (thinking/tool_use) would otherwise yield an empty string presented as the answer.
	for _, c := range out.Content {
		if c.Type == "text" && c.Text != "" {
			return c.Text, nil
		}
	}
	return "", fmt.Errorf("anthropic: response contained no text block")
}
