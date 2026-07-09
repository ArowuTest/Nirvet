// Package soarwire holds shared wiring for the SOAR containment path used by both cmd/api and cmd/worker — the
// failed/stalled/withheld-containment alerter that surfaces to the SOC triage queue.
package soarwire

import (
	"context"
	"strings"

	"github.com/ArowuTest/nirvet/internal/alert"
	"github.com/ArowuTest/nirvet/internal/notify"
	"github.com/google/uuid"
)

// ContainmentAlerter surfaces a failed / stalled / protected-withheld containment as BOTH an internal triage
// alert (alert.RaisePlatform) AND a durable HIGH outbox notification (owner decision). Implements
// soar.ContainmentAlerter structurally. Idempotent per execution: the notification fires only when the alert is
// NEWLY raised (RaisePlatform dedupes on the key), so re-observing across ticks does not spam.
type ContainmentAlerter struct {
	alerts *alert.Service
	outbox *notify.OutboxRepository
}

// NewContainmentAlerter builds the adapter.
func NewContainmentAlerter(alerts *alert.Service, outbox *notify.OutboxRepository) ContainmentAlerter {
	return ContainmentAlerter{alerts: alerts, outbox: outbox}
}

// ContainmentFailed implements soar.ContainmentAlerter.
func (a ContainmentAlerter) ContainmentFailed(ctx context.Context, tenantID, executionID uuid.UUID, actionKey, target, status string, stalled bool) error {
	label := "failed"
	switch {
	case stalled:
		label = "stalled"
	case strings.HasPrefix(status, "withheld"):
		label = "withheld (protected target)"
	}
	dedupe := "soar-containment-" + strings.ReplaceAll(label, " ", "-") + ":" + executionID.String()
	title := "SOAR containment " + label + ": " + actionKey + " on " + target + " (" + status + ")"
	inserted, err := a.alerts.RaisePlatform(ctx, tenantID, dedupe, title, "high", target, "soar-reconciler")
	if err != nil {
		return err
	}
	if inserted {
		_ = a.outbox.Enqueue(ctx, tenantID, "log", "soc", title,
			"A SOAR containment action needs attention — the endpoint/identity may NOT be contained as intended. "+
				"action="+actionKey+" target="+target+" status="+status+" execution="+executionID.String())
	}
	return nil
}
