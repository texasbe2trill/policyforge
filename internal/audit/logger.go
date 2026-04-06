package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/texasbe2trill/policyforge/internal/types"
)

const (
	auditDir  = "artifacts"
	auditFile = "audit.jsonl"
)

// Meta carries optional session/auth metadata to attach to the audit record.
type Meta struct {
	SessionID string
	AuthType  string
}

// LogDecision appends a single tamper-evident decision record to the audit JSONL file.
// Each record contains a SHA-256 hash of its key fields and the hash of the previous
// record, forming a simple chain that makes undetected modification difficult.
// It returns the hash of the newly written record so callers can embed it in
// evidence bundles.
func LogDecision(result types.Decision, request types.DecisionRequest, meta Meta) (string, string, error) {
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		return "", "", fmt.Errorf("failed to create audit directory: %w", err)
	}

	path := filepath.Join(auditDir, auditFile)

	record := types.AuditRecord{
		RequestID:     result.RequestID,
		Timestamp:     result.Timestamp,
		Subject:       request.Subject,
		Role:          request.Role,
		Resource:      request.Resource,
		Action:        request.Action,
		RequestedTier: string(request.RequestedTier),
		Agent:         request.Agent,
		Decision:      result.Decision,
		Reasons:       result.Reasons,
		SessionID:     meta.SessionID,
		AuthType:      meta.AuthType,
		PreviousHash:  lastAuditHash(path),
	}
	record.Hash = computeHash(record)

	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return "", "", fmt.Errorf("failed to open audit log file: %w", err)
	}
	defer file.Close()

	line, err := json.Marshal(record)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal audit record: %w", err)
	}

	if _, err := file.Write(append(line, '\n')); err != nil {
		return "", "", fmt.Errorf("failed to append audit record: %w", err)
	}

	return record.Hash, record.PreviousHash, nil
}

// computeHash returns the hex-encoded SHA-256 of the record's key fields joined
// with "|" as a separator.
func computeHash(r types.AuditRecord) string {
	input := strings.Join([]string{
		r.RequestID,
		r.Timestamp,
		string(r.Decision),
		r.Subject,
		r.Role,
		r.Resource,
		r.Action,
	}, "|")
	digest := sha256.Sum256([]byte(input))
	return hex.EncodeToString(digest[:])
}

// lastAuditHash reads the last line of the audit file and returns its hash field.
// Returns an empty string if the file does not exist or has no records yet.
func lastAuditHash(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return ""
	}

	// Read up to the last 4 KB to find the final line without loading the whole file.
	const readSize = 4096
	size := fi.Size()
	offset := size - readSize
	if offset < 0 {
		offset = 0
	}

	buf := make([]byte, size-offset)
	if _, err := f.ReadAt(buf, offset); err != nil {
		return ""
	}

	// Find the last non-empty line.
	lines := bytes.Split(bytes.TrimRight(buf, "\n"), []byte("\n"))
	var lastLine []byte
	for i := len(lines) - 1; i >= 0; i-- {
		if len(lines[i]) > 0 {
			lastLine = lines[i]
			break
		}
	}
	if len(lastLine) == 0 {
		return ""
	}

	var record struct {
		Hash string `json:"hash"`
	}
	if err := json.Unmarshal(lastLine, &record); err != nil {
		return ""
	}
	return record.Hash
}
