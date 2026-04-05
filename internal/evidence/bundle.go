package evidence

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/texasbe2trill/policyforge/internal/types"
)

var (
	evidenceDir = "artifacts/evidence"
	indexFile   = "artifacts/evidence/index.csv"
)

// Options carries optional metadata that enriches a bundle beyond the core decision.
type Options struct {
	Agent             string
	ApprovalStatus    string
	ApprovalID        string
	PolicyVersion     string
	AuditRecordHash   string
	PreviousAuditHash string
}

// EvidenceBundle is a compliance-ready record of a single policy evaluation.
type EvidenceBundle struct {
	BundleID          string             `json:"bundle_id"`
	RequestID         string             `json:"request_id"`
	Timestamp         string             `json:"timestamp"`
	Decision          types.DecisionType `json:"decision"`
	Subject           string             `json:"subject"`
	Agent             string             `json:"agent,omitempty"`
	Role              string             `json:"role"`
	Resource          string             `json:"resource"`
	Action            string             `json:"action"`
	RequestedTier     string             `json:"requested_tier"`
	Reasons           []string           `json:"reasons"`
	Controls          []string           `json:"controls"`
	ApprovalStatus    string             `json:"approval_status,omitempty"`
	ApprovalID        string             `json:"approval_id,omitempty"`
	PolicyVersion     string             `json:"policy_version,omitempty"`
	EvidenceType      string             `json:"evidence_type"`
	AuditRecordHash   string             `json:"audit_record_hash,omitempty"`
	PreviousAuditHash string             `json:"previous_audit_hash,omitempty"`
}

// Generate builds an evidence bundle, persists it to
// artifacts/evidence/<bundle_id>.json, appends a row to index.csv, and
// returns the bundle.
func Generate(result types.Decision, request types.DecisionRequest, controls []string, opts Options) (*EvidenceBundle, error) {
	bundle := &EvidenceBundle{
		BundleID:          newBundleID(),
		RequestID:         result.RequestID,
		Timestamp:         result.Timestamp,
		Decision:          result.Decision,
		Subject:           request.Subject,
		Agent:             request.Agent,
		Role:              request.Role,
		Resource:          request.Resource,
		Action:            request.Action,
		RequestedTier:     string(request.RequestedTier),
		Reasons:           result.Reasons,
		Controls:          controls,
		ApprovalStatus:    opts.ApprovalStatus,
		ApprovalID:        opts.ApprovalID,
		PolicyVersion:     opts.PolicyVersion,
		EvidenceType:      "policy_decision",
		AuditRecordHash:   opts.AuditRecordHash,
		PreviousAuditHash: opts.PreviousAuditHash,
	}

	if err := save(bundle); err != nil {
		return nil, err
	}
	if err := appendIndex(bundle); err != nil {
		return nil, err
	}
	return bundle, nil
}

func newBundleID() string {
	n, err := rand.Int(rand.Reader, big.NewInt(99999))
	if err != nil {
		n = big.NewInt(int64(time.Now().UTC().Nanosecond() % 99999))
	}
	return fmt.Sprintf("ev_%d_%05d", time.Now().UTC().UnixNano(), n.Int64())
}

func save(bundle *EvidenceBundle) error {
	if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
		return fmt.Errorf("failed to create evidence directory: %w", err)
	}

	path := filepath.Join(evidenceDir, bundle.BundleID+".json")
	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal evidence bundle: %w", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("failed to write evidence bundle: %w", err)
	}

	return nil
}

// appendIndex adds a summary row to artifacts/evidence/index.csv.
// The header is written only when the file is first created.
func appendIndex(b *EvidenceBundle) error {
	if err := os.MkdirAll(evidenceDir, 0o755); err != nil {
		return fmt.Errorf("failed to create evidence directory: %w", err)
	}

	needsHeader := false
	if _, err := os.Stat(indexFile); os.IsNotExist(err) {
		needsHeader = true
	}

	f, err := os.OpenFile(indexFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("failed to open evidence index: %w", err)
	}
	defer f.Close()

	if needsHeader {
		if _, err := fmt.Fprintln(f, "bundle_id,request_id,timestamp,decision,subject,role,resource,action,controls,approval_status,approval_id"); err != nil {
			return fmt.Errorf("failed to write index header: %w", err)
		}
	}

	row := strings.Join([]string{
		b.BundleID,
		b.RequestID,
		b.Timestamp,
		string(b.Decision),
		b.Subject,
		b.Role,
		b.Resource,
		b.Action,
		strings.Join(b.Controls, ";"),
		b.ApprovalStatus,
		b.ApprovalID,
	}, ",")

	if _, err := fmt.Fprintln(f, row); err != nil {
		return fmt.Errorf("failed to write index row: %w", err)
	}
	return nil
}
