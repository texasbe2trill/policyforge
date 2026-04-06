package service

import (
	"strings"
	"testing"
	"time"

	"github.com/texasbe2trill/policyforge/internal/config"
	"github.com/texasbe2trill/policyforge/internal/policy"
	"github.com/texasbe2trill/policyforge/internal/types"
)

func newTestEngine(t *testing.T) *policy.Engine {
	t.Helper()
	p, err := config.LoadPolicy("../../configs/policy.yaml")
	if err != nil {
		t.Fatalf("failed to load policy: %v", err)
	}
	return policy.New(p)
}

func TestEvaluate_AgentTTLExceeded(t *testing.T) {
	eng := newTestEngine(t)

	// Session issued 31 minutes ago — exceeds the 30-minute TTL for remediation-bot.
	issuedAt := time.Now().UTC().Add(-31 * time.Minute).Format(time.RFC3339)

	req := types.DecisionRequest{
		Subject:       "policyforge-agent",
		Role:          "operator",
		Agent:         "remediation-bot",
		Resource:      "prod/payment-service",
		Action:        "restart",
		RequestedTier: types.SupervisedWrite,
	}
	opts := EvalOpts{
		SessionIssuedAt: issuedAt,
		AuthAgent:       "remediation-bot",
	}

	result, err := Evaluate(eng, req, opts)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if result.Decision.Decision != types.DecisionDeny {
		t.Errorf("expected deny for expired agent TTL, got %s", result.Decision.Decision)
	}
	if len(result.Decision.Reasons) == 0 || !strings.Contains(result.Decision.Reasons[0], "exceeded TTL") {
		t.Errorf("unexpected reasons: %v", result.Decision.Reasons)
	}
}

func TestEvaluate_AgentTTLWithinLimit(t *testing.T) {
	eng := newTestEngine(t)

	// Session issued 5 minutes ago — well within 30-minute TTL.
	issuedAt := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)

	req := types.DecisionRequest{
		Subject:       "policyforge-agent",
		Role:          "operator",
		Agent:         "remediation-bot",
		Resource:      "prod/payment-service",
		Action:        "restart",
		RequestedTier: types.SupervisedWrite,
	}
	opts := EvalOpts{
		SessionIssuedAt: issuedAt,
		AuthAgent:       "remediation-bot",
	}

	result, err := Evaluate(eng, req, opts)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	// Should reach engine evaluation (not denied by TTL check).
	if result.Decision.Decision == types.DecisionDeny && len(result.Decision.Reasons) > 0 &&
		strings.Contains(result.Decision.Reasons[0], "exceeded TTL") {
		t.Error("should not have denied due to TTL when session is fresh")
	}
}

func TestEvaluate_IdentityOverride(t *testing.T) {
	eng := newTestEngine(t)

	req := types.DecisionRequest{
		Subject:       "impostor",
		Role:          "viewer",
		Resource:      "staging/payment-service",
		Action:        "read",
		RequestedTier: types.ReadOnly,
	}
	// Override with admin identity.
	opts := EvalOpts{
		AuthSubject: "chris",
		AuthRole:    "admin",
	}

	result, err := Evaluate(eng, req, opts)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if result.Decision.EvaluatedRole != "admin" {
		t.Errorf("EvaluatedRole = %s, want admin", result.Decision.EvaluatedRole)
	}
	if result.Decision.Decision != types.DecisionAllow {
		t.Errorf("admin read staging should allow, got %s", result.Decision.Decision)
	}
}
