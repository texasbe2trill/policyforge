#!/usr/bin/env bash
set -euo pipefail

# PolicyForge CLI Demo Script
# Runs through core evaluation scenarios, approval workflow, and drift detection.

POLICY="./configs/policy.yaml"
BIN="go run ./cmd/policyforge"

section() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  $1"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
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
  --tier read_only | jq .

# ── Scenario 2: Deny ───────────────────────────────────────────────────────
section "Scenario 2: Deny — viewer attempts restart"
$BIN --policy "$POLICY" \
  --subject alice --role viewer \
  --resource staging/payment-service --action restart \
  --tier read_only | jq . || true

# ── Scenario 3: Require Approval ───────────────────────────────────────────
section "Scenario 3: Require Approval — operator restarts prod"
$BIN --policy "$POLICY" \
  --subject chris --role operator \
  --resource prod/payment-service --action restart \
  --tier supervised_write | jq . || true

# ── Scenario 4: Auto-Approve ──────────────────────────────────────────────
section "Scenario 4: Auto-Approve"
$BIN --policy "$POLICY" \
  --subject chris --role operator \
  --resource prod/payment-service --action restart \
  --tier supervised_write \
  --auto-approve | jq .

# ── Scenario 5: Agent Envelope — Allow ─────────────────────────────────────
section "Scenario 5: Agent Envelope — remediation-bot restarts staging"
$BIN --policy "$POLICY" \
  --subject bot --role operator \
  --resource staging/payment-service --action restart \
  --tier read_only \
  --agent remediation-bot | jq .

# ── Scenario 6: Agent Envelope — Deny ─────────────────────────────────────
section "Scenario 6: Agent Envelope — remediation-bot denied on prod"
$BIN --policy "$POLICY" \
  --subject bot --role operator \
  --resource prod/payment-service --action read \
  --tier read_only \
  --agent remediation-bot | jq . || true

# ── Approval Workflow ──────────────────────────────────────────────────────
section "Approval Workflow"
echo "Submitting request that requires approval..."
$BIN --policy "$POLICY" \
  --subject chris --role operator \
  --resource prod/payment-service --action restart \
  --tier supervised_write || true

echo ""
echo "Listing pending approvals..."
$BIN --list-approvals | jq .

# ── Drift Detection ───────────────────────────────────────────────────────
section "Drift Detection"
$BIN --policy "$POLICY" --drift-check | jq .

# ── Audit Log ─────────────────────────────────────────────────────────────
section "Audit Log (last 3 entries)"
tail -n 3 artifacts/audit.jsonl | jq .

section "Demo complete"
echo "Artifacts written to artifacts/"
echo "Evidence bundles: $(ls artifacts/evidence/*.json 2>/dev/null | wc -l | tr -d ' ') files"
