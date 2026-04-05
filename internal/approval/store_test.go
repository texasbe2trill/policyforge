package approval

import (
	"testing"
	"time"
)

// useTemp redirects the store to a temp file for the duration of a test.
func useTemp(t *testing.T) {
	t.Helper()
	orig := storePath
	storePath = t.TempDir() + "/approvals.json"
	t.Cleanup(func() { storePath = orig })
}

func TestCreateAndList(t *testing.T) {
	useTemp(t)

	rec := Record{
		ApprovalID:    NewID(),
		RequestID:     "req-001",
		Status:        StatusPending,
		Subject:       "alice",
		Role:          "operator",
		Resource:      "prod/payment-service",
		Action:        "restart",
		RequestedTier: "supervised_write",
		Reasons:       []string{"approval: resource requires approval"},
		RequestedAt:   time.Now().UTC().Format(time.RFC3339),
	}

	if err := Create(rec); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	records, err := List()
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Status != StatusPending {
		t.Errorf("expected pending, got %s", records[0].Status)
	}
}

func TestApprove(t *testing.T) {
	useTemp(t)

	id := NewID()
	rec := Record{
		ApprovalID:  id,
		RequestID:   "req-002",
		Status:      StatusPending,
		Subject:     "bob",
		Role:        "operator",
		Resource:    "prod/api-gateway",
		Action:      "scale",
		RequestedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := Create(rec); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := Approve(id, "manager", "looks good"); err != nil {
		t.Fatalf("Approve failed: %v", err)
	}

	records, _ := List()
	if records[0].Status != StatusApproved {
		t.Errorf("expected approved, got %s", records[0].Status)
	}
	if records[0].DecidedBy != "manager" {
		t.Errorf("expected decided_by=manager, got %s", records[0].DecidedBy)
	}
	if records[0].DecisionNote != "looks good" {
		t.Errorf("expected note 'looks good', got %s", records[0].DecisionNote)
	}
	if records[0].DecidedAt == "" {
		t.Error("DecidedAt should be set after approval")
	}
}

func TestReject(t *testing.T) {
	useTemp(t)

	id := NewID()
	rec := Record{
		ApprovalID:  id,
		RequestID:   "req-003",
		Status:      StatusPending,
		Subject:     "carol",
		Role:        "operator",
		Resource:    "prod/payment-service",
		Action:      "write",
		RequestedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := Create(rec); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := Reject(id, "security-team", "policy violation"); err != nil {
		t.Fatalf("Reject failed: %v", err)
	}

	records, _ := List()
	if records[0].Status != StatusRejected {
		t.Errorf("expected rejected, got %s", records[0].Status)
	}
}

func TestApproveNotFound(t *testing.T) {
	useTemp(t)

	err := Approve("nonexistent-id", "someone", "note")
	if err == nil {
		t.Error("expected error for nonexistent approval ID")
	}
}

func TestListEmpty(t *testing.T) {
	useTemp(t)

	records, err := List()
	if err != nil {
		t.Fatalf("List failed on empty store: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("expected 0 records, got %d", len(records))
	}
}
