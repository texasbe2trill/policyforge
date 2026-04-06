#!/usr/bin/env bash
set -euo pipefail

# PolicyForge CLI Demo Script
# Runs through core evaluation scenarios, approval workflow, and drift detection.

if command -v jq >/dev/null 2>&1; then
  PRETTY_JSON=(jq .)
else
  PRETTY_JSON=(cat)
  echo "Warning: jq not found; showing raw JSON output. Install with: brew install jq" >&2
fi

POLICY="./configs/policy.yaml"
BIN="go run ./cmd/policyforge"

section() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  $1"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
}

pretty_json() {
  "${PRETTY_JSON[@]}"
}

# ── Clean artifacts for a fresh run ─────────────────────────────────────────
rm -f artifacts/audit.jsonl artifacts/approvals.json artifacts/sessions.json
rm -rf artifacts/evidence artifacts/drift

# ── Version ─────────────────────────────────────────────────────────────────
section "Version"
$BIN --version

# ── Scenario 1: Allow ───────────────────────────────────────────────────────
section "Scenario 1: Allow — viewer reads staging resource"
$BIN --policy "$POLICY" \
  --subject alice --role viewer \
  --resource staging/payment-service --action read \
  --tier read_only | pretty_json

# ── Scenario 2: Deny ───────────────────────────────────────────────────────
section "Scenario 2: Deny — viewer attempts restart"
$BIN --policy "$POLICY" \
  --subject alice --role viewer \
  --resource staging/payment-service --action restart \
  --tier read_only | pretty_json || true

# ── Scenario 3: Require Approval ───────────────────────────────────────────
section "Scenario 3: Require Approval — operator restarts prod"
$BIN --policy "$POLICY" \
  --subject chris --role operator \
  --resource prod/payment-service --action restart \
  --tier supervised_write | pretty_json || true

# ── Scenario 4: Auto-Approve ──────────────────────────────────────────────
section "Scenario 4: Auto-Approve"
$BIN --policy "$POLICY" \
  --subject chris --role operator \
  --resource prod/payment-service --action restart \
  --tier supervised_write \
  --auto-approve | pretty_json

# ── Scenario 5: Agent Envelope — Allow ─────────────────────────────────────
section "Scenario 5: Agent Envelope — remediation-bot restarts staging"
$BIN --policy "$POLICY" \
  --subject bot --role operator \
  --resource staging/payment-service --action restart \
  --tier read_only \
  --agent remediation-bot | pretty_json

# ── Scenario 6: Agent Envelope — Deny ─────────────────────────────────────
section "Scenario 6: Agent Envelope — remediation-bot denied on prod"
$BIN --policy "$POLICY" \
  --subject bot --role operator \
  --resource prod/payment-service --action read \
  --tier read_only \
  --agent remediation-bot | pretty_json || true

# ── Approval Workflow ──────────────────────────────────────────────────────
section "Approval Workflow"
echo "Submitting request that requires approval..."
$BIN --policy "$POLICY" \
  --subject chris --role operator \
  --resource prod/payment-service --action restart \
  --tier supervised_write || true

echo ""
echo "Listing pending approvals..."
$BIN --list-approvals | pretty_json

# ── Drift Detection ───────────────────────────────────────────────────────
section "Drift Detection"
$BIN --policy "$POLICY" --drift-check | pretty_json

# ── Audit Log ─────────────────────────────────────────────────────────────
section "Audit Log (last 3 entries)"
tail -n 3 artifacts/audit.jsonl | pretty_json

section "Demo complete"
echo "Artifacts written to artifacts/"
echo "Evidence bundles: $(ls artifacts/evidence/*.json 2>/dev/null | wc -l | tr -d ' ') files"
