# Runbook — Certificate Rotation (overlap validity — no gap)

Satisfies `build/GATE_HA_DR_SOVEREIGN_RUNBOOKS.md` §2b (cert-rotation half). Separated from KEY_ROTATION.md for the
auditor's runbook set; the safety invariant is the same family (no availability gap).

## Safety invariant (what a wrong rotation destroys)
**The new certificate MUST be live before the old one expires — overlapping validity windows, never a gap.** A gap =
TLS failures = the SOC is unreachable exactly when analysts need it. Rotation is additive-then-cutover, never
delete-then-create.

## Scope
TLS serving certs (ingress), mTLS client certs (agent/collector → API), and any SAML/OIDC signing certs used by SSO.

## Procedure (overlap-then-cutover)
1. **Issue the new cert** alongside the current one (cert-manager auto-renewal, or operator-supplied). Both are valid
   simultaneously.
2. **Distribute / trust** the new cert (update truststores for mTLS; publish new SSO metadata with BOTH signing certs
   accepted during overlap).
3. **Cut traffic over** to the new cert.
4. **Retire the old cert only after** the cutover is confirmed and no client still presents/expects the old one. For
   SSO signing, keep the old cert in the accepted set until all IdP/SP metadata has refreshed.
5. **Rollback**: because the old cert is retained through step 4, rollback = keep serving the old cert; no outage.

## Secrets
Private keys are referenced by their Secret/HSM location, never printed or pasted (§2f). cert-manager stores keys in
Kubernetes Secrets by reference.

## Accreditation mapping
Overlap-validity rotation with no availability gap satisfies the cryptographic-key/certificate lifecycle control;
pairs with KEY_ROTATION.md (KEK) for the full key-management story.
