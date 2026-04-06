package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/texasbe2trill/policyforge/internal/session"
)

// newTestStore builds a TokenStore directly without touching the filesystem.
func newTestStore(entries ...TokenEntry) *TokenStore {
	ts := &TokenStore{lookup: make(map[string]TokenEntry, len(entries))}
	for _, e := range entries {
		ts.lookup[e.Token] = e
	}
	return ts
}

// okHandler is a trivial next-handler that records which identity it received.
func okHandler(t *testing.T, wantSubject string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := GetIdentity(r.Context())
		if !ok {
			t.Error("expected identity in context, got none")
		}
		if id.Subject != wantSubject {
			t.Errorf("subject = %s, want %s", id.Subject, wantSubject)
		}
		w.WriteHeader(http.StatusOK)
	})
}

// useSessionTemp redirects the session store to an isolated temp file.
func useSessionTemp(t *testing.T) {
	t.Helper()
	orig := session.StorePath()
	session.SetStorePath(t.TempDir() + "/sessions.json")
	t.Cleanup(func() { session.SetStorePath(orig) })
}

func TestMiddleware_ValidToken(t *testing.T) {
	useSessionTemp(t)
	ts := newTestStore(TokenEntry{Token: "tok-1", Subject: "alice", Role: "operator", AuthType: "local_token"})
	handler := Middleware(ts, okHandler(t, "alice"))
	req := httptest.NewRequest(http.MethodPost, "/evaluate", nil)
	req.Header.Set("Authorization", "Bearer tok-1")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestMiddleware_InvalidToken(t *testing.T) {
	useSessionTemp(t)
	ts := newTestStore()
	handler := Middleware(ts, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called for invalid token")
	}))
	req := httptest.NewRequest(http.MethodPost, "/evaluate", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	var body map[string]string
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body["error"] == "" {
		t.Error("expected error field in response")
	}
}

func TestMiddleware_MissingToken(t *testing.T) {
	useSessionTemp(t)
	ts := newTestStore()
	handler := Middleware(ts, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	req := httptest.NewRequest(http.MethodPost, "/evaluate", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestMiddleware_DebugOIDC_Enabled(t *testing.T) {
	useSessionTemp(t)
	t.Setenv(DebugOIDCEnvVar, "true")
	ts := newTestStore()
	handler := Middleware(ts, okHandler(t, "chris"))
	req := httptest.NewRequest(http.MethodPost, "/evaluate", nil)
	req.Header.Set("X-Debug-OIDC-Subject", "chris")
	req.Header.Set("X-Debug-OIDC-Role", "admin")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestMiddleware_DebugOIDC_Disabled(t *testing.T) {
	useSessionTemp(t)
	// Ensure the env var is absent; t.Setenv restores the original value on cleanup.
	t.Setenv(DebugOIDCEnvVar, "")
	ts := newTestStore()
	handler := Middleware(ts, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called when OIDC debug is disabled")
	}))
	req := httptest.NewRequest(http.MethodPost, "/evaluate", nil)
	req.Header.Set("X-Debug-OIDC-Subject", "chris")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

func TestMiddleware_CreatesSession(t *testing.T) {
	useSessionTemp(t)
	ts := newTestStore(TokenEntry{Token: "tok-2", Subject: "bob", Role: "admin", AuthType: "local_token"})
	var capturedID Identity
	handler := Middleware(ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := GetIdentity(r.Context())
		capturedID = id
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/evaluate", bytes.NewReader(nil))
	req.Header.Set("Authorization", "Bearer tok-2")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if capturedID.SessionID == "" {
		t.Error("expected a session ID to be created and attached to identity")
	}
	if capturedID.SessionIssuedAt == "" {
		t.Error("expected SessionIssuedAt to be set")
	}
}

func TestMiddleware_RevokedSessionDenied(t *testing.T) {
	useSessionTemp(t)
	ts := newTestStore(TokenEntry{Token: "tok-3", Subject: "grace", Role: "viewer", AuthType: "local_token"})

	// First request — creates a session.
	var firstID string
	capture := Middleware(ts, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := GetIdentity(r.Context())
		firstID = id.SessionID
		w.WriteHeader(http.StatusOK)
	}))
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.Header.Set("Authorization", "Bearer tok-3")
	capture.ServeHTTP(httptest.NewRecorder(), req1)

	// Revoke that session.
	if err := session.Revoke(firstID); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	// Second request with the same token — should be denied because the session is revoked.
	handler := Middleware(ts, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("handler should not be called for revoked session")
	}))
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", "Bearer tok-3")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req2)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked session, got %d", rr.Code)
	}
}
