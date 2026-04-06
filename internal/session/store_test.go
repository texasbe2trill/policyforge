package session

import (
	"testing"
	"time"
)

func useTemp(t *testing.T) {
	t.Helper()
	orig := StorePath()
	SetStorePath(t.TempDir() + "/sessions.json")
	t.Cleanup(func() { SetStorePath(orig) })
}

func TestCreateAndList(t *testing.T) {
	useTemp(t)

	sess, err := Create("alice", "operator", "", AuthTypeLocalToken, 60*time.Minute)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if sess.SessionID == "" {
		t.Error("expected non-empty session ID")
	}
	if sess.Status != SessionActive {
		t.Errorf("expected active, got %s", sess.Status)
	}

	all, err := List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 session, got %d", len(all))
	}
}

func TestValidate_Active(t *testing.T) {
	useTemp(t)

	sess, _ := Create("bob", "admin", "", AuthTypeLocalToken, 60*time.Minute)
	got, err := Validate(sess.SessionID)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if got.SessionID != sess.SessionID {
		t.Errorf("wrong session ID returned")
	}
}

func TestRevoke(t *testing.T) {
	useTemp(t)

	sess, _ := Create("carol", "viewer", "", AuthTypeLocalToken, 60*time.Minute)
	if err := Revoke(sess.SessionID); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	_, err := Validate(sess.SessionID)
	if err == nil {
		t.Error("expected error for revoked session")
	}
}

func TestValidate_Expired(t *testing.T) {
	useTemp(t)

	// Negative TTL ensures the session is already expired at creation time.
	sess, _ := Create("dave", "viewer", "", AuthTypeLocalToken, -1*time.Second)
	_, err := Validate(sess.SessionID)
	if err == nil {
		t.Error("expected error for expired session")
	}
}

func TestFindActive_ReturnsExisting(t *testing.T) {
	useTemp(t)

	first, _ := Create("eve", "operator", "", AuthTypeLocalToken, 60*time.Minute)
	found, err := FindActive("eve", AuthTypeLocalToken)
	if err != nil {
		t.Fatalf("FindActive failed: %v", err)
	}
	if found == nil {
		t.Fatal("expected to find existing session")
	}
	if found.SessionID != first.SessionID {
		t.Errorf("expected session %s, got %s", first.SessionID, found.SessionID)
	}
}

func TestFindActive_RevokedReturnsError(t *testing.T) {
	useTemp(t)

	sess, _ := Create("frank", "viewer", "", AuthTypeLocalToken, 60*time.Minute)
	_ = Revoke(sess.SessionID)

	_, err := FindActive("frank", AuthTypeLocalToken)
	if err == nil {
		t.Error("expected error for revoked session during FindActive")
	}
}

func TestFindActive_EmptyStore(t *testing.T) {
	useTemp(t)

	found, err := FindActive("nobody", AuthTypeLocalToken)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found != nil {
		t.Error("expected nil for unknown subject")
	}
}

func TestFindActive_ExpiredSkipped(t *testing.T) {
	useTemp(t)

	// Negative TTL creates an already-expired session.
	_, _ = Create("henry", "viewer", "", AuthTypeLocalToken, -1*time.Second)
	found, err := FindActive("henry", AuthTypeLocalToken)
	if err != nil {
		t.Fatalf("expected nil error for expired session, got %v", err)
	}
	if found != nil {
		t.Error("expected nil: expired session should not be reused")
	}
}
