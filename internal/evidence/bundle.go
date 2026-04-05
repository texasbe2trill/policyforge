package evidence

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/texasbe2trill/policyforge/internal/types"
)

const evidenceDir = "artifacts/evidence"

// EvidenceBundle is a compliance-ready record of a single policy evaluation.
type EvidenceBundle struct {
	BundleID      string             `json:"bundle_id"`
	RequestID     string             `json:"request_id"`
	Timestamp     string             `json:"timestamp"`
	Decision      types.DecisionType `json:"decision"`
	Subject       string             `json:"subject"`
	Role          string             `json:"role"`
	Resource      string             `json:"resource"`
	Action        string             `json:"action"`
	RequestedTier string             `json:"requested_tier"`
	Reasons       []string           `json:"reasons"`
	Controls      []string           `json:"controls"`
}

// Generate builds an evidence bundle from a decision and its request, persists
// it to artifacts/evidence/<bundle_id>.json, and returns the bundle.
func Generate(result types.Decision, request types.DecisionRequest, controls []string) (*EvidenceBundle, error) {
	bundle := &EvidenceBundle{
		BundleID:      newBundleID(),
		RequestID:     result.RequestID,
		Timestamp:     result.Timestamp,
		Decision:      result.Decision,
		Subject:       request.Subject,
		Role:          request.Role,
		Resource:      request.Resource,
		Action:        request.Action,
		RequestedTier: string(request.RequestedTier),
		Reasons:       result.Reasons,
		Controls:      controls,
	}

	if err := save(bundle); err != nil {
		return nil, err
	}
	return bundle, nil
}

func newBundleID() string {
	n, err := rand.Int(rand.Reader, big.NewInt(99999))
	if err != nil {
		// Fallback: use nanosecond modulo — still unique enough for this context.
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
