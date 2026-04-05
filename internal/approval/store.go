package approval

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// storePath is the path to the approval store file. It is a variable (not a
// const) so tests can override it with a temp path.
var storePath = "artifacts/approvals.json"

// Create persists a new approval record with status=pending.
func Create(record Record) error {
	records, err := load()
	if err != nil {
		return err
	}
	records = append(records, record)
	return save(records)
}

// List returns all approval records.
func List() ([]Record, error) {
	return load()
}

// Approve marks an approval record as approved.
func Approve(approvalID, decidedBy, note string) error {
	return updateStatus(approvalID, StatusApproved, decidedBy, note)
}

// Reject marks an approval record as rejected.
func Reject(approvalID, decidedBy, note string) error {
	return updateStatus(approvalID, StatusRejected, decidedBy, note)
}

// NewID generates a unique approval ID.
func NewID() string {
	return fmt.Sprintf("apr-%d", time.Now().UTC().UnixNano())
}

func updateStatus(approvalID string, status Status, decidedBy, note string) error {
	records, err := load()
	if err != nil {
		return err
	}

	found := false
	for i, r := range records {
		if r.ApprovalID == approvalID {
			records[i].Status = status
			records[i].DecidedAt = time.Now().UTC().Format(time.RFC3339)
			records[i].DecidedBy = decidedBy
			records[i].DecisionNote = note
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("approval '%s' not found", approvalID)
	}

	return save(records)
}

func load() ([]Record, error) {
	data, err := os.ReadFile(storePath)
	if os.IsNotExist(err) {
		return []Record{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read approvals store: %w", err)
	}

	var records []Record
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("failed to parse approvals store: %w", err)
	}
	return records, nil
}

func save(records []Record) error {
	if err := os.MkdirAll(filepath.Dir(storePath), 0o755); err != nil {
		return fmt.Errorf("failed to create store directory: %w", err)
	}

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal approvals: %w", err)
	}

	tmp := storePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("failed to write approvals store: %w", err)
	}
	if err := os.Rename(tmp, storePath); err != nil {
		return fmt.Errorf("failed to commit approvals store: %w", err)
	}
	return nil
}
