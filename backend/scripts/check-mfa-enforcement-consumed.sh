#!/usr/bin/env bash
#
# check-mfa-enforcement-consumed.sh — CI teeth against the mfa.enforce recurrence (S1 force-MFA).
#
# The J5 lesson: `mfa.enforce` was a platform flag that DECLARED MFA enforcement but had NO consumer — a control
# that claims to enforce while nothing reads it is false assurance, so it was deleted. This fence makes the same
# regression impossible for S1: it asserts the require_mfa / mfa_required_roles policy + the operator floor are
# ACTUALLY READ by the session-mint chokepoint — a live consumer, not a stored-but-unread flag.
#
# Structural (grep over the mint path), matching the sibling check-*.sh fences. Run from backend/.
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

# 1. MintSession (the single mint chokepoint) must call the enforcement consumer. If a refactor drops this call,
#    every login path stops enforcing MFA silently — exactly the mfa.enforce failure. Fail the build.
if ! grep -q 'mfaEnrollmentRequired' internal/iam/session_generation.go; then
  echo "MFA-ENFORCE VIOLATION: MintSession (internal/iam/session_generation.go) does not call mfaEnrollmentRequired." >&2
  echo "The force-MFA policy would be declared but never enforced (the deleted mfa.enforce failure). Restore the" >&2
  echo "enforcement call at the mint chokepoint so every login/SSO/refresh path enforces MFA." >&2
  fail=1
fi

# 2. The consumer must genuinely READ the policy + the operator floor (not a stub that ignores them). Assert the
#    actual column/table reads exist, so the consumer can't be hollowed out while keeping the call.
for token in 'require_mfa' 'mfa_required_roles' 'mfa_enforcement_floor'; do
  if ! grep -q "$token" internal/iam/mfaenforce.go; then
    echo "MFA-ENFORCE VIOLATION: the enforcement consumer (internal/iam/mfaenforce.go) does not read '$token'." >&2
    echo "The policy/floor must be consumed, not just stored — an unread column is the mfa.enforce trap." >&2
    fail=1
  fi
done

# 3. The enroll/activate escape hatch must NOT be the whole story — enforcement must be able to REFUSE. Assert the
#    consumer returns the enrollment-required sentinel (so a full session can actually be blocked).
if ! grep -q 'ErrMFAEnrollmentRequired' internal/iam/session_generation.go; then
  echo "MFA-ENFORCE VIOLATION: MintSession must be able to REFUSE a full session (errMFAEnrollmentRequired)." >&2
  echo "Without the refusal path the check is decorative — it would compute 'required' and then mint anyway." >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
echo "check-mfa-enforcement-consumed: OK — force-MFA policy + operator floor are read by the MintSession chokepoint, which can refuse."
