package drift

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/texasbe2trill/policyforge/internal/policy"
	"github.com/texasbe2trill/policyforge/internal/types"
)

var (
	auditFile  = "artifacts/audit.jsonl"
	driftDir   = "artifacts/drift"
	outputFile = "artifacts/drift/findings.json"
)

// Detect loads audit records, re-evaluates each against the current policy,
// and returns any findings where the current policy would produce a different
// (stricter) outcome than what was observed.
func Detect(eng *policy.Engine) ([]Finding, error) {
	records, err := loadAuditRecords()
	if err != nil {
		return nil, err
	}

	var findings []Finding
	for _, record := range records {
		req := types.DecisionRequest{
			Subject:       record.Subject,
			Role:          record.Role,
			Resource:      record.Resource,
			Action:        record.Action,
			RequestedTier: types.SafetyTier(record.RequestedTier),
			Agent:         record.Agent,
		}

		current := eng.Evaluate(&req)

		observed := string(record.Decision)
		expected := string(current.Decision)

		if observed == expected {
			continue
		}

		finding := Finding{
			FindingID:        newFindingID(),
			Timestamp:        time.Now().UTC().Format(time.RFC3339),
			RequestID:        record.RequestID,
			Subject:          record.Subject,
			Agent:            record.Agent,
			Role:             record.Role,
			Resource:         record.Resource,
			Action:           record.Action,
			RequestedTier:    record.RequestedTier,
			ObservedDecision: observed,
			ExpectedDecision: expected,
		}

		// Classify severity and drift type.
		switch {
		case observed == "allow" && expected == "deny":
			finding.Severity = SeverityHigh
			finding.DriftType = classifyDenyDrift(current.Reasons)
			finding.Message = fmt.Sprintf(
				"request was allowed but current policy would deny: %s",
				current.Reasons[0],
			)
		case observed == "allow" && expected == "require_approval":
			finding.Severity = SeverityMedium
			finding.DriftType = DriftDecisionMismatch
			finding.Message = "request was allowed but current policy requires approval"
		default:
			finding.Severity = SeverityLow
			finding.DriftType = DriftDecisionMismatch
			finding.Message = fmt.Sprintf(
				"observed=%s, current policy expects=%s",
				observed, expected,
			)
		}

		findings = append(findings, finding)
	}

	if err := writeFindings(findings); err != nil {
		return nil, err
	}

	return findings, nil
}

func loadAuditRecords() ([]types.AuditRecord, error) {
	f, err := os.Open(auditFile)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	defer f.Close()

	var records []types.AuditRecord
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var r types.AuditRecord
		if err := json.Unmarshal(line, &r); err != nil {
			continue // skip malformed lines
		}
		records = append(records, r)
	}
	return records, scanner.Err()
}

func writeFindings(findings []Finding) error {
	if err := os.MkdirAll(driftDir, 0o755); err != nil {
		return fmt.Errorf("failed to create drift directory: %w", err)
	}

	if findings == nil {
		findings = []Finding{}
	}

	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal findings: %w", err)
	}

	path := filepath.Join(driftDir, "findings.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("failed to write findings: %w", err)
	}
	return nil
}

func newFindingID() string {
	return fmt.Sprintf("drift-%d", time.Now().UTC().UnixNano())
}

// classifyDenyDrift maps engine denial reasons to specific drift types.
func classifyDenyDrift(reasons []string) DriftType {
	if len(reasons) == 0 {
		return DriftDecisionMismatch
	}
	r := reasons[0]
	switch {
	case strings.Contains(r, "action"):
		return DriftUnauthorizedAction
	case strings.Contains(r, "resource"):
		return DriftUnauthorizedResourceAccess
	case strings.Contains(r, "tier"):
		return DriftTierExceeded
	case strings.Contains(r, "agent"):
		return DriftAgentEnvelopeViolation
	default:
		return DriftDecisionMismatch
	}
}
