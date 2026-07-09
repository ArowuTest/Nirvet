package ai

// §6.12 #117 A-3 — the openai_compatible Provider (self-hosted sovereign model, or any OpenAI-chat-compatible
// endpoint). The endpoint is guarded by the platform-admin ALLOWLIST, deliberately NOT by netsafe/IsInternalHost:
// a sovereign model legitimately lives on a private address, so blocking internal hosts would break the feature.
// SSRF is instead closed structurally: the resolver validates (scheme,host,port) against the allowlist, then builds
// the request URL from those VALIDATED components (never from a raw admin string), the client appends only the
// fixed /v1/chat/completions path, and redirects are refused — so the request can only ever reach the allowlisted
// host. The allowlist is a DATA-EGRESS / RESIDENCY control (§1903), not just SSRF hardening.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// openaiTimeout bounds every call so a hung sovereign endpoint cannot wedge a summary (reviewer note 3).
const openaiTimeout = 30 * time.Second

// openAICompatibleProvider calls an OpenAI /v1/chat/completions endpoint. endpoint is a normalized origin
// (scheme://host[:port], no path) already validated against the allowlist by the resolver.
type openAICompatibleProvider struct {
	endpoint string // e.g. https://llm.internal:8443  (origin only; path is appended)
	model    string
	apiKey   string // "" = keyless local model (Authorization header omitted)
	http     *http.Client
}

// newOpenAICompatibleProvider builds the provider with a redirect-refusing, bounded-timeout client. hc is injectable
// for tests; a nil hc gets the default hardened client.
func newOpenAICompatibleProvider(endpoint, model, apiKey string, hc *http.Client) *openAICompatibleProvider {
	if hc == nil {
		hc = &http.Client{ // netsafe-exempt: openai_compatible endpoint is gated by the platform-admin allowlist, NOT netsafe — a sovereign model legitimately lives on an internal address (#117 ALLOWLIST-not-block guard)
			Timeout: openaiTimeout,
			// Refuse redirects: a 3xx off the allowlisted host must never be followed (SSRF containment).
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("ai: redirects are not allowed for the model endpoint")
			},
		}
	}
	return &openAICompatibleProvider{endpoint: endpoint, model: model, apiKey: apiKey, http: hc}
}

func (p *openAICompatibleProvider) Available() bool { return true } // a resolved+allowlisted endpoint is usable (keyless ok)

func (p *openAICompatibleProvider) Model() string {
	if p.model == "" {
		return "openai-compatible"
	}
	return p.model
}

type oaiChatReq struct {
	Model     string       `json:"model"`
	MaxTokens int          `json:"max_tokens"`
	Messages  []oaiMessage `json:"messages"`
}

type oaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type oaiChatResp struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Complete posts an OpenAI chat-completions request. The URL is built from the validated origin — the raw admin
// string is never used for the request target.
func (p *openAICompatibleProvider) Complete(ctx context.Context, system, user string) (string, error) {
	body, _ := json.Marshal(oaiChatReq{
		Model:     p.model,
		MaxTokens: 700,
		Messages:  []oaiMessage{{Role: "system", Content: system}, {Role: "user", Content: user}},
	})
	url := p.endpoint + "/v1/chat/completions"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("content-type", "application/json")
	if p.apiKey != "" {
		req.Header.Set("authorization", "Bearer "+p.apiKey)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var out oaiChatResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Error != nil {
		return "", fmt.Errorf("openai_compatible: %s", out.Error.Message)
	}
	for _, c := range out.Choices {
		if c.Message.Content != "" {
			return c.Message.Content, nil
		}
	}
	return "", fmt.Errorf("openai_compatible: response contained no message content")
}
