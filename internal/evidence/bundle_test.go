package evidence

import (
	"os"
	"strings"
	"testing"

	"github.com/texasbe2trill/policyforge/internal/types"
)

func TestGenerateWritesBundle(t *testing.T) {
	dir := t.TempDir()
	orig := evidenceDir
	origIdx := indexFile
	evidenceDir = dir
	indexFile = dir + "/index.csv"
	defer func() {
		evidenceDir = orig
		indexFile = origIdx
	}()

	decision := types.Decision{
		Decision:        types.DecisionAllow,
		Reasons:         []string{"allow: all policy checks passed"},
		Timestamp:       "2026-04-05T00:00:00Z",
		RequestID:       "req-test-1",
		MatchedResource: "staging/payment-service",
		EvaluatedRole:   "viewer",
	}
	req := types.DecisionRequest{
		Subject:       "alice",
		Role:          "viewer",
		Resource:      "staging/payment-service",
		Action:        "read",
		RequestedTier: types.ReadOnly,
	}
	opts := Options{
		PolicyVersion:   "v0.1.0",
		AuditRecordHash: "abc123",
	}

	bundle, err := Generate(decision, req, []string{"PCI-DSS-7.2"}, opts)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if bundle.BundleID == "" {
		t.Error("BundleID should not be empty")
	}
	if bundle.PolicyVersion != "v0.1.0" {
		t.Errorf("PolicyVersion = %s, want v0.1.0", bundle.PolicyVersion)
	}
	if bundle.AuditRecordHash != "abc123" {
		t.Errorf("AuditRecordHash = %s, want abc123", bundle.AuditRecordHash)
	}
	if bundle.EvidenceType != "policy_decision" {
		t.Errorf("EvidenceType = %s, want policy_decision", bundle.EvidenceType)
	}

	// JSON file should exist.
	path := dir + "/" + bundle.BundleID + ".json"
	if _, err := os.Stat(path); err != nil {
		t.Errorf("bundle JSON file not created: %v", err)
	}

	// CSV index should have a header and a data row.
	csvData, err := os.ReadFile(dir + "/index.csv")
	if err != nil {
		t.Fatalf("index.csv not created: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(csvData)), "\n")
	if len(lines) < 2 {
		t.Errorf("expected header + 1 data row in index.csv, got %d lines", len(lines))
	}
}

func TestGenerateWithApprovalMetadata(t *testing.T) {
	dir := t.TempDir()
	orig := evidenceDir
	origIdx := indexFile
	evidenceDir = dir
	indexFile = dir + "/index.csv"
	defer func() {
		evidenceDir = orig
		indexFile = origIdx
	}()

	decision := types.Decision{
		Decision:  types.DecisionRequireApproval,
		Reasons:   []string{"approval: resource requires approval"},
		Timestamp: "2026-04-05T00:00:00Z",
		RequestID: "req-test-2",
	}
	req := types.DecisionRequest{
		Subject:       "chris",
		Role:          "operator",
		Resource:      "prod/payment-service",
		Action:        "restart",
		RequestedTier: types.SupervisedWrite,
	}
	opts := Options{
		ApprovalStatus: "pending",
		ApprovalID:     "apr-test-42",
	}

	bundle, err := Generate(decision, req, []string{"PCI-DSS-7.2"}, opts)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if bundle.ApprovalStatus != "pending" {
		t.Errorf("ApprovalStatus = %s, want pending", bundle.ApprovalStatus)
	}
	if bundle.ApprovalID != "apr-test-42" {
		t.Errorf("ApprovalID = %s, want apr-test-42", bundle.ApprovalID)
	}
}
