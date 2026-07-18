package connector

// §6.11 response — Palo Alto (PAN-OS) network-block Actioner (block_ip ⇄ unblock_ip). First NETWORK-containment
// vendor: a fleet-wide perimeter block (fleet_wide=true, mig 0135) so the FleetWide gate refuses auto-run under any
// authority mode — a human always approves. Mechanism = User-ID registered-IP tagging (no config commit), reversible
// by unregistering. Own-vs-foreign attribution mirrors the verified CS IOC pattern (correlator, prior_action_id
// reverse): each block carries a per-run correlator TAG; the reverse unregisters EXACTLY the ip + our correlator, so
// a foreign quarantine of the same IP is never touched. Synchronous ⇒ Confirm=nil.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ArowuTest/nirvet/internal/soar"
)

// paloAltoCorrTagPrefix + a hash of the stable correlator (run_id:step_index) is the per-run attribution tag. A
// registered-IP carrying it is one WE created (reverse may undo); the same IP quarantined WITHOUT it is foreign.
const paloAltoCorrTagPrefix = "nirvet-corr-"

// PaloAltoActioner builds the network-block Actioners. base/apiKey injectable for tests; prod leaves them empty so
// the mgmt host + API key come from the tenant's vault-decrypted Credentials bundle, http nil→SafeClient.
type PaloAltoActioner struct {
	base   string
	apiKey string
	http   *http.Client
}

// NewPaloAltoActioner builds the factory. Empty base/apiKey ⇒ read per-call from the tenant creds bundle.
func NewPaloAltoActioner(base, apiKey string, hc *http.Client) *PaloAltoActioner {
	return &PaloAltoActioner{base: base, apiKey: apiKey, http: hc}
}

// Actioners returns block_ip ⇄ unblock_ip. Both Class-High, reversible with the symmetric inverse, PreCheck
// (resume-safe), synchronous (Confirm=nil). unblock_ip is registry-only (not a catalog step), mirroring cs_allow_hash.
func (a *PaloAltoActioner) Actioners() []soar.Actioner {
	return []soar.Actioner{
		{
			ConnectorKey: string(KindPaloAlto), Action: "block_ip",
			PreCheck: true, Reversible: true, Inverse: "unblock_ip",
			Fn: func(ctx context.Context, creds []byte, target string, params map[string]any) (string, map[string]any, error) {
				return a.blockIP(ctx, creds, target, params)
			},
		},
		{
			ConnectorKey: string(KindPaloAlto), Action: "unblock_ip",
			PreCheck: true, Reversible: true, Inverse: "block_ip",
			Fn: func(ctx context.Context, creds []byte, target string, params map[string]any) (string, map[string]any, error) {
				return a.unblockIP(ctx, creds, target, params)
			},
		},
	}
}

// blockIP registers the target IP with the quarantine tag + a per-run correlator tag. Terminal-state PreCheck: if the
// IP already carries the quarantine tag, it is goal-met (changed=false) — and attributed OURS only if it also carries
// THIS run's correlator (a crash-resume), else FOREIGN (a block we did not create → reverse must never undo it).
// action_id encodes "ip|corrTag" so ReverseRun can forward exactly what the reverse needs to unregister (O-3).
func (a *PaloAltoActioner) blockIP(ctx context.Context, creds []byte, target string, params map[string]any) (string, map[string]any, error) {
	client, err := a.clientOnly(creds)
	if err != nil {
		return "", nil, err
	}
	ip, err := ipTarget(target)
	if err != nil {
		return "", nil, err
	}
	corr, _ := params[soar.ActionCorrelatorParam].(string)
	ct := corrTag(corr)
	tags, found, err := client.registeredTags(ctx, ip)
	if err != nil {
		return "", nil, err
	}
	if found && hasTag(tags, client.tag) {
		if corr != "" && hasTag(tags, ct) {
			// Ours (crash-resume of THIS step): already blocked. changed=false, but ours → reverse may undo.
			return "already:" + ip, panOurs(ip, ct, false), nil
		}
		// Quarantined but not by this step → FOREIGN. Fail-safe: changed=false so the reverse (gated on changed=true)
		// never unregisters a block we cannot prove we created.
		return "already:" + ip, panForeign(ip), nil
	}
	if err := client.register(ctx, ip, []string{client.tag, ct}); err != nil {
		return "", map[string]any{"changed": false, "ip": ip}, err
	}
	return ip, panOurs(ip, ct, true), nil
}

// unblockIP removes the block — the reverse. O-3: unregister EXACTLY the ip + correlator tag our block created, keyed
// on prior_action_id ("ip|corrTag", forwarded by ReverseRun from prior_state.action_id). Removing the quarantine tag
// is what actually unblocks; the correlator tag is removed alongside so no residue remains. On a DIRECT (non-reverse)
// invocation with no prior id, it removes the quarantine tag by target IP. Already-absent is changed=false, not error.
//
// Shared-tag note: PAN-OS tags are a set, so removing the quarantine tag unblocks for any co-owner too. This is
// bounded by the changed=true reverse gate + the FOREIGN PreCheck skip above — we only ever reverse a block whose
// PreCheck attributed it as ours (or that this run created), never a foreign pre-existing quarantine.
func (a *PaloAltoActioner) unblockIP(ctx context.Context, creds []byte, target string, params map[string]any) (string, map[string]any, error) {
	client, err := a.clientOnly(creds)
	if err != nil {
		return "", nil, err
	}
	if pid, _ := params["prior_action_id"].(string); pid != "" {
		ip, ct := splitHandle(pid)
		if ip == "" {
			return "", nil, fmt.Errorf("palo alto: malformed prior_action_id %q", pid)
		}
		remove := []string{client.tag}
		if ct != "" {
			remove = append(remove, ct)
		}
		if err := client.unregister(ctx, ip, remove); err != nil {
			return "", map[string]any{"changed": false, "ip": ip}, err
		}
		return ip, map[string]any{"changed": true, "ip": ip, "action_id": ip + "|" + ct}, nil
	}
	// Direct invocation (not a reverse): remove the quarantine tag if present.
	ip, err := ipTarget(target)
	if err != nil {
		return "", nil, err
	}
	tags, found, err := client.registeredTags(ctx, ip)
	if err != nil {
		return "", nil, err
	}
	if !found || !hasTag(tags, client.tag) {
		return "absent", map[string]any{"changed": false, "ip": ip}, nil
	}
	if err := client.unregister(ctx, ip, []string{client.tag}); err != nil {
		return "", map[string]any{"changed": false, "ip": ip}, err
	}
	return ip, map[string]any{"changed": true, "ip": ip, "action_id": ip}, nil
}

func (a *PaloAltoActioner) clientOnly(creds []byte) (*paloAltoClient, error) {
	var cb Credentials
	if err := json.Unmarshal(creds, &cb); err != nil {
		return nil, fmt.Errorf("palo alto: bad credentials bundle: %w", err)
	}
	base := a.base
	if base == "" {
		base = cb.PaloAltoBaseURL
	}
	key := a.apiKey
	if key == "" {
		key = cb.PaloAltoAPIKey
	}
	return newPaloAltoClient(base, key, cb.PaloAltoTag, a.http)
}

// corrTag derives the per-run correlator tag from the stable correlator (run_id:step_index).
func corrTag(correlator string) string {
	sum := sha256.Sum256([]byte(correlator))
	return paloAltoCorrTagPrefix + hex.EncodeToString(sum[:6]) // 12 hex chars — well within PAN-OS tag length
}

// splitHandle parses an "ip|corrTag" action_id back into its parts (corrTag may be empty).
func splitHandle(h string) (ip, corrTag string) {
	if i := strings.IndexByte(h, '|'); i >= 0 {
		return strings.TrimSpace(h[:i]), strings.TrimSpace(h[i+1:])
	}
	return strings.TrimSpace(h), ""
}

// panOurs/panForeign build priorState. action_id encodes ip|corrTag in the ours paths (the reverse key) and the bare
// ip in the foreign path (we won't reverse it). changed drives whether ReverseRun may undo the effect.
func panOurs(ip, corrTag string, changed bool) map[string]any {
	return map[string]any{"changed": changed, "ip": ip, "corr_tag": corrTag, "action_id": ip + "|" + corrTag}
}
func panForeign(ip string) map[string]any {
	return map[string]any{"changed": false, "ip": ip, "action_id": ip}
}
