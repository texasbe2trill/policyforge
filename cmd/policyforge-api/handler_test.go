package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/texasbe2trill/policyforge/internal/auth"
	"github.com/texasbe2trill/policyforge/internal/config"
	"github.com/texasbe2trill/policyforge/internal/policy"
	"github.com/texasbe2trill/policyforge/internal/session"
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

// useSessionTemp redirects the session store to an isolated temp file.
func useSessionTemp(t *testing.T) {
	t.Helper()
	orig := session.StorePath()
	session.SetStorePath(t.TempDir() + "/sessions.json")
	t.Cleanup(func() { session.SetStorePath(orig) })
}

// newTestTokenStore builds an in-memory token store without touching disk.
func newTestTokenStore(entries ...auth.TokenEntry) *auth.TokenStore {
	return auth.NewTokenStoreFromEntries(entries)
}

// TestAPIAuth_ValidBearer verifies a valid bearer token reaches the handler.
func TestAPIAuth_ValidBearer(t *testing.T) {
	useSessionTemp(t)
	eng := newTestEngine(t)

	ts := newTestTokenStore(auth.TokenEntry{
		Token: "dev-admin-token", Subject: "chris", Role: "admin", AuthType: "local_token",
	})

	body, _ := json.Marshal(types.DecisionRequest{
		// Body fields will be overridden by auth context — provide minimal valid JSON.
		Resource:      "staging/payment-service",
		Action:        "read",
		RequestedTier: types.ReadOnly,
	})
	req := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer dev-admin-token")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	auth.Middleware(ts, http.HandlerFunc(evaluateHandler(eng))).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestAPIAuth_InvalidToken verifies an unknown token returns 401.
func TestAPIAuth_InvalidToken(t *testing.T) {
	useSessionTemp(t)
	eng := newTestEngine(t)
	ts := newTestTokenStore()

	req := httptest.NewRequest(http.MethodPost, "/evaluate", nil)
	req.Header.Set("Authorization", "Bearer garbage")
	rr := httptest.NewRecorder()

	auth.Middleware(ts, http.HandlerFunc(evaluateHandler(eng))).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestAPIAuth_IdentityOverride verifies that the authenticated role overrides the body role.
func TestAPIAuth_IdentityOverride(t *testing.T) {
	eng := newTestEngine(t)

	// Inject an identity directly into context (simulating successful auth).
	id := auth.Identity{Subject: "chris", Role: "admin", AuthType: "local_token"}
	body, _ := json.Marshal(types.DecisionRequest{
		Subject:       "impostor", // should be overridden
		Role:          "viewer",   // should be overridden with "admin"
		Resource:      "staging/payment-service",
		Action:        "read",
		RequestedTier: types.ReadOnly,
	})
	req := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(body))
	req = req.WithContext(auth.WithIdentity(context.Background(), id))

	rr := httptest.NewRecorder()
	evaluateHandler(eng)(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp types.Decision
	_ = json.NewDecoder(rr.Body).Decode(&resp)
	// Admin can read staging — should allow.
	if resp.Decision != types.DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}
	// EvaluatedRole should reflect the overridden admin role, not body's viewer.
	if resp.EvaluatedRole != "admin" {
		t.Errorf("EvaluatedRole = %s, want admin", resp.EvaluatedRole)
	}
}

// TestAdminOnly_Forbidden verifies non-admin role gets 403.
func TestAdminOnly_Forbidden(t *testing.T) {
	id := auth.Identity{Subject: "bob", Role: "viewer", AuthType: "local_token"}
	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	req = req.WithContext(auth.WithIdentity(context.Background(), id))
	rr := httptest.NewRecorder()

	adminOnly(sessionsListHandler)(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

// TestAdminOnly_SessionsList verifies admin can list sessions.
func TestAdminOnly_SessionsList(t *testing.T) {
	useSessionTemp(t)
	id := auth.Identity{Subject: "chris", Role: "admin", AuthType: "local_token"}
	req := httptest.NewRequest(http.MethodGet, "/sessions", nil)
	req = req.WithContext(auth.WithIdentity(context.Background(), id))
	rr := httptest.NewRecorder()

	adminOnly(sessionsListHandler)(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}
