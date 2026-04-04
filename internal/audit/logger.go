package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/texasbe2trill/policyforge/internal/types"
)

const (
	auditDir  = "artifacts"
	auditFile = "audit.jsonl"
)

// LogDecision appends a single decision record to the audit JSONL file.
func LogDecision(result types.Decision, request types.DecisionRequest) error {
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		return fmt.Errorf("failed to create audit directory: %w", err)
	}

	path := filepath.Join(auditDir, auditFile)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open audit log file: %w", err)
	}
	defer file.Close()

	record := types.AuditRecord{
		RequestID: result.RequestID,
		Timestamp: result.Timestamp,
		Subject:   request.Subject,
		Role:      request.Role,
		Resource:  request.Resource,
		Action:    request.Action,
		Decision:  result.Decision,
		Reasons:   result.Reasons,
	}

	line, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal audit record: %w", err)
	}

	if _, err := file.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("failed to append audit record: %w", err)
	}

	return nil
}
