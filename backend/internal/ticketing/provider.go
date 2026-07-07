package ticketing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Provider creates a ticket in an external ITSM. Implementations are pure HTTP so
// they are mock-testable and portable (ADR-0005: no vendor SDK).
type Provider interface {
	Create(ctx context.Context, conn *Connection, secret string, t Ticket) (*Ref, error)
}

// httpClient is the shared client (short timeout; overridable in tests via the
// package-level newRequest hooks are unnecessary — base URL comes from the conn).
var httpClient = &http.Client{Timeout: 15 * time.Second}

// ProviderFor returns the provider implementation for a connection's kind.
func ProviderFor(provider string) (Provider, error) {
	switch provider {
	case ProviderServiceNow:
		return serviceNow{}, nil
	case ProviderJira:
		return jira{}, nil
	default:
		return nil, fmt.Errorf("unknown ticketing provider: %s", provider)
	}
}

// --- ServiceNow (Table API: POST /api/now/table/incident, basic auth) ---

type serviceNow struct{}

func (serviceNow) Create(ctx context.Context, conn *Connection, secret string, t Ticket) (*Ref, error) {
	body, _ := json.Marshal(map[string]string{
		"short_description": t.Title,
		"description":       t.Description,
		"urgency":           snUrgency(t.Severity),
		"impact":            snUrgency(t.Severity),
	})
	u := strings.TrimSuffix(conn.BaseURL, "/") + "/api/now/table/incident"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(conn.AuthUser, secret)
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("servicenow: status %d", resp.StatusCode)
	}
	var out struct {
		Result struct {
			SysID  string `json:"sys_id"`
			Number string `json:"number"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Result.Number == "" {
		return nil, fmt.Errorf("servicenow: no ticket number in response")
	}
	return &Ref{
		ID:  out.Result.Number,
		URL: strings.TrimSuffix(conn.BaseURL, "/") + "/nav_to.do?uri=incident.do?sys_id=" + out.Result.SysID,
	}, nil
}

// snUrgency maps canonical severity to ServiceNow urgency/impact (1 high .. 3 low).
func snUrgency(sev string) string {
	switch sev {
	case "critical", "high":
		return "1"
	case "medium":
		return "2"
	default:
		return "3"
	}
}

// --- Jira (REST v3: POST /rest/api/3/issue, email + API-token basic auth) ---

type jira struct{}

func (jira) Create(ctx context.Context, conn *Connection, secret string, t Ticket) (*Ref, error) {
	projectKey, _ := conn.Config["project_key"].(string)
	if projectKey == "" {
		return nil, fmt.Errorf("jira: config.project_key is required")
	}
	payload := map[string]any{
		"fields": map[string]any{
			"project":     map[string]string{"key": projectKey},
			"summary":     t.Title,
			"description": t.Description,
			"issuetype":   map[string]string{"name": "Incident"},
			"priority":    map[string]string{"name": jiraPriority(t.Severity)},
		},
	}
	body, _ := json.Marshal(payload)
	u := strings.TrimSuffix(conn.BaseURL, "/") + "/rest/api/3/issue"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(conn.AuthUser, secret) // email + API token
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("jira: status %d", resp.StatusCode)
	}
	var out struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if out.Key == "" {
		return nil, fmt.Errorf("jira: no issue key in response")
	}
	return &Ref{ID: out.Key, URL: strings.TrimSuffix(conn.BaseURL, "/") + "/browse/" + out.Key}, nil
}

// jiraPriority maps canonical severity to a Jira priority name.
func jiraPriority(sev string) string {
	switch sev {
	case "critical":
		return "Highest"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	default:
		return "Lowest"
	}
}
