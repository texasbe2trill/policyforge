package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/texasbe2trill/policyforge/internal/config"
	"github.com/texasbe2trill/policyforge/internal/policy"
	"github.com/texasbe2trill/policyforge/internal/types"
)

func newTestEngine(t *testing.T) *policy.Engine {
	t.Helper()
	p, err := config.LoadPolicy("../../configs/policy.yaml")
	if err != nil {
		t.Fatalf("failed to load test policy: %v", err)
	}
	return policy.New(p)
}

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	healthHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestEvaluateHandler_Allow(t *testing.T) {
	eng := newTestEngine(t)

	body, _ := json.Marshal(types.DecisionRequest{
		Subject:       "alex",
		Role:          "viewer",
		Resource:      "staging/payment-service",
		Action:        "read",
		RequestedTier: types.ReadOnly,
	})

	req := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	evaluateHandler(eng)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp types.Decision
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Decision != types.DecisionAllow {
		t.Errorf("expected allow, got %s (reasons: %v)", resp.Decision, resp.Reasons)
	}
}

func TestEvaluateHandler_Deny(t *testing.T) {
	eng := newTestEngine(t)

	body, _ := json.Marshal(types.DecisionRequest{
		Subject:       "pat",
		Role:          "viewer",
		Resource:      "staging/payment-service",
		Action:        "restart",
		RequestedTier: types.ReadOnly,
	})

	req := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	evaluateHandler(eng)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp types.Decision
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Decision != types.DecisionDeny {
		t.Errorf("expected deny, got %s", resp.Decision)
	}
}

func TestEvaluateHandler_RequireApproval_AutoApprove(t *testing.T) {
	eng := newTestEngine(t)

	body, _ := json.Marshal(types.DecisionRequest{
		Subject:       "chris",
		Role:          "operator",
		Resource:      "prod/payment-service",
		Action:        "restart",
		RequestedTier: types.SupervisedWrite,
	})

	req := httptest.NewRequest(http.MethodPost, "/evaluate?auto_approve=true", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	evaluateHandler(eng)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp types.Decision
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Decision != types.DecisionAllow {
		t.Errorf("expected allow (auto-approved), got %s", resp.Decision)
	}
}

func TestEvaluateHandler_InvalidBody(t *testing.T) {
	eng := newTestEngine(t)

	req := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewBufferString("not json"))
	rr := httptest.NewRecorder()

	evaluateHandler(eng)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestEvaluateHandler_MissingFields(t *testing.T) {
	eng := newTestEngine(t)

	body, _ := json.Marshal(map[string]string{"subject": "chris"})
	req := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	evaluateHandler(eng)(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}
