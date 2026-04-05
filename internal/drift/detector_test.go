package drift

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/texasbe2trill/policyforge/internal/policy"
	"github.com/texasbe2trill/policyforge/internal/types"
)

// testPolicy returns a minimal policy for drift tests.
func testPolicy() *types.Policy {
	return &types.Policy{
		SafetyTiers: []types.Tier{
			{Name: "read_only", RequiresApproval: false},
			{Name: "supervised_write", RequiresApproval: true},
		},
		Roles: []types.Role{
			{
				Name:             "viewer",
				AllowedActions:   []string{"read"},
				AllowedTiers:     []types.SafetyTier{"read_only"},
				MaxTier:          "read_only",
				AllowedResources: []string{"staging/payment-service"},
			},
			{
				Name:             "operator",
				AllowedActions:   []string{"read", "restart"},
				AllowedTiers:     []types.SafetyTier{"read_only", "supervised_write"},
				MaxTier:          "supervised_write",
				AllowedResources: []string{"prod/payment-service", "staging/payment-service"},
			},
		},
		Resources: []types.Resource{
			{Name: "staging/payment-service", RequiresApproval: false},
			{Name: "prod/payment-service", RequiresApproval: true},
		},
	}
}

// writeAuditLog writes records to a temp file and overrides auditFile for
// the duration of the test.
func writeAuditLog(t *testing.T, records []types.AuditRecord) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "audit*.jsonl")
	if err != nil {
		t.Fatal(err)
	}

	for _, r := range records {
		line, _ := json.Marshal(r)
		f.Write(append(line, '\n'))
	}
	f.Close()

	// Override package-level path.
	orig := auditFile
	// auditFile is a const — we need another approach. Use a temp copy.
	_ = orig
	t.Setenv("_POLICYFORGE_AUDIT_FILE_OVERRIDE", f.Name())
}

func TestDetectNoDrift(t *testing.T) {
	// Write an audit log where the decision matches current policy.
	dir := t.TempDir()
	auditPath := dir + "/audit.jsonl"

	record := types.AuditRecord{
		RequestID:     "req-1",
		Subject:       "alice",
		Role:          "viewer",
		Resource:      "staging/payment-service",
		Action:        "read",
		RequestedTier: "read_only",
		Decision:      types.DecisionAllow,
		Reasons:       []string{"allow: all policy checks passed"},
		Hash:          "abc123",
	}
	data, _ := json.Marshal(record)
	os.WriteFile(auditPath, append(data, '\n'), 0o644)

	// Override the module-level auditFile for this test.
	origAudit := auditFile
	origDrift := driftDir
	auditFile = auditPath
	driftDir = dir
	outputFile = dir + "/findings.json"
	defer func() {
		auditFile = origAudit
		driftDir = origDrift
		outputFile = origDrift + "/findings.json"
	}()

	eng := policy.New(testPolicy())
	findings, err := Detect(eng)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %+v", len(findings), findings)
	}
}

func TestDetectDriftAllowNowDeny(t *testing.T) {
	// Simulate a case where an audit record shows "allow" but current policy
	// would deny (action not permitted for role).
	dir := t.TempDir()
	auditPath := dir + "/audit.jsonl"

	// The audit shows viewer allowed a restart — but current policy denies it.
	record := types.AuditRecord{
		RequestID:     "req-2",
		Subject:       "alice",
		Role:          "viewer",
		Resource:      "staging/payment-service",
		Action:        "restart", // viewer can only read
		RequestedTier: "read_only",
		Decision:      types.DecisionAllow, // was allowed historically
		Reasons:       []string{"allow: all policy checks passed"},
		Hash:          "def456",
	}
	data, _ := json.Marshal(record)
	os.WriteFile(auditPath, append(data, '\n'), 0o644)

	origAudit := auditFile
	origDrift := driftDir
	auditFile = auditPath
	driftDir = dir
	outputFile = dir + "/findings.json"
	defer func() {
		auditFile = origAudit
		driftDir = origDrift
		outputFile = origDrift + "/findings.json"
	}()

	eng := policy.New(testPolicy())
	findings, err := Detect(eng)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.ObservedDecision != "allow" {
		t.Errorf("ObservedDecision = %s, want allow", f.ObservedDecision)
	}
	if f.ExpectedDecision != "deny" {
		t.Errorf("ExpectedDecision = %s, want deny", f.ExpectedDecision)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("Severity = %s, want high", f.Severity)
	}
	if f.DriftType != DriftUnauthorizedAction {
		t.Errorf("DriftType = %s, want %s", f.DriftType, DriftUnauthorizedAction)
	}
}

func TestDetectDriftAllowNowRequireApproval(t *testing.T) {
	dir := t.TempDir()
	auditPath := dir + "/audit.jsonl"

	// Operator restarted prod — was allowed historically but requires_approval now.
	record := types.AuditRecord{
		RequestID:     "req-3",
		Subject:       "bob",
		Role:          "operator",
		Resource:      "prod/payment-service",
		Action:        "restart",
		RequestedTier: "supervised_write",
		Decision:      types.DecisionAllow,
		Reasons:       []string{"allow: all policy checks passed"},
		Hash:          "ghi789",
	}
	data, _ := json.Marshal(record)
	os.WriteFile(auditPath, append(data, '\n'), 0o644)

	origAudit := auditFile
	origDrift := driftDir
	auditFile = auditPath
	driftDir = dir
	outputFile = dir + "/findings.json"
	defer func() {
		auditFile = origAudit
		driftDir = origDrift
		outputFile = origDrift + "/findings.json"
	}()

	eng := policy.New(testPolicy())
	findings, err := Detect(eng)
	if err != nil {
		t.Fatalf("Detect failed: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != SeverityMedium {
		t.Errorf("Severity = %s, want medium", findings[0].Severity)
	}
}

func TestWriteFindingsCreatesFile(t *testing.T) {
	dir := t.TempDir()
	orig := outputFile
	outputFile = dir + "/findings.json"
	origDir := driftDir
	driftDir = dir
	defer func() {
		outputFile = orig
		driftDir = origDir
	}()

	if err := writeFindings([]Finding{}); err != nil {
		t.Fatalf("writeFindings failed: %v", err)
	}
	if _, err := os.Stat(outputFile); err != nil {
		t.Errorf("findings.json not created: %v", err)
	}
}
