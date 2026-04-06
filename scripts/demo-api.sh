#!/usr/bin/env bash
set -euo pipefail

# PolicyForge API Demo Script
# Starts the API server, runs evaluation scenarios, then shuts down.

if command -v jq >/dev/null 2>&1; then
  PRETTY_JSON=(jq .)
else
  PRETTY_JSON=(cat)
  echo "Warning: jq not found; showing raw JSON output. Install with: brew install jq" >&2
fi

POLICY="./configs/policy.yaml"
TOKENS="./configs/tokens.yaml"
ADDR="127.0.0.1:18080"
API_URL="http://${ADDR}"

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

# ── Build and start server ──────────────────────────────────────────────────
section "Starting API server"
go build -o /tmp/policyforge-api-demo ./cmd/policyforge-api
/tmp/policyforge-api-demo --policy "$POLICY" --tokens "$TOKENS" --addr "$ADDR" &
API_PID=$!
cleanup() {
  if kill -0 "$API_PID" >/dev/null 2>&1; then
    kill "$API_PID" >/dev/null 2>&1 || true
    wait "$API_PID" >/dev/null 2>&1 || true
  fi
  rm -f /tmp/policyforge-api-demo
}
trap cleanup EXIT

# Wait for server to be ready
for i in $(seq 1 30); do
  if curl -sf "${API_URL}/health" > /dev/null 2>&1; then
    echo "Server ready on ${ADDR}"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "Server failed to start" >&2
    exit 1
  fi
  sleep 0.2
done

# ── Health check ───────────────────────────────────────────────────────────
section "Health Check"
curl -sf "${API_URL}/health" | pretty_json

# ── Unauthenticated request (should fail) ─────────────────────────────────
section "Unauthenticated Request (401 expected)"
curl -sf -w "\nHTTP %{http_code}\n" "${API_URL}/evaluate" \
  -H "Content-Type: application/json" \
  -d '{"resource":"staging/payment-service","action":"read","requested_tier":"read_only"}' \
  || true

# ── Authenticated allow ───────────────────────────────────────────────────
section "Authenticated Allow — admin reads staging"
curl -sf "${API_URL}/evaluate" \
  -H "Authorization: Bearer dev-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"resource":"staging/payment-service","action":"read","requested_tier":"read_only"}' \
  | pretty_json

# ── Authenticated require_approval ────────────────────────────────────────
section "Require Approval — operator restarts prod"
curl -sf "${API_URL}/evaluate" \
  -H "Authorization: Bearer operator-token" \
  -H "Content-Type: application/json" \
  -d '{"resource":"prod/payment-service","action":"restart","requested_tier":"supervised_write"}' \
  | pretty_json

# ── Auto-approve via query param ──────────────────────────────────────────
section "Auto-Approve via Query Param"
curl -sf "${API_URL}/evaluate?auto_approve=true" \
  -H "Authorization: Bearer operator-token" \
  -H "Content-Type: application/json" \
  -d '{"resource":"prod/payment-service","action":"restart","requested_tier":"supervised_write"}' \
  | pretty_json

# ── Agent envelope ────────────────────────────────────────────────────────
section "Agent Envelope — remediation-bot via token"
curl -sf "${API_URL}/evaluate" \
  -H "Authorization: Bearer agent-remediation-token" \
  -H "Content-Type: application/json" \
  -d '{"resource":"staging/payment-service","action":"restart","requested_tier":"read_only"}' \
  | pretty_json

# ── Session list ──────────────────────────────────────────────────────────
section "Session List (admin only)"
curl -sf "${API_URL}/sessions" \
  -H "Authorization: Bearer dev-admin-token" \
  | pretty_json

# ── Done ──────────────────────────────────────────────────────────────────
section "Demo complete"
echo "Server PID: ${API_PID}"
echo "Artifacts written to artifacts/"
echo "Shutting down..."
