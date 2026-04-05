package service

import (
	"fmt"
	"time"

	"github.com/texasbe2trill/policyforge/internal/audit"
	"github.com/texasbe2trill/policyforge/internal/compliance"
	"github.com/texasbe2trill/policyforge/internal/evidence"
	"github.com/texasbe2trill/policyforge/internal/policy"
	"github.com/texasbe2trill/policyforge/internal/types"
)

// Result holds every output produced by a single policy evaluation.
type Result struct {
	Decision         *types.Decision
	Bundle           *evidence.EvidenceBundle
	RequiredApproval bool // true when the raw engine decision was require_approval
}

// Evaluate runs the full evaluation pipeline for a single request:
//
//  1. Engine decision
//  2. Metadata enrichment (timestamp, request ID, matched resource, evaluated role)
//  3. Optional auto-approve
//  4. Audit log (with hash chain)
//  5. Compliance control mapping
//  6. Evidence bundle generation
//
// Both the CLI and the REST API call this function so their outputs are identical.
func Evaluate(eng *policy.Engine, req types.DecisionRequest, autoApprove bool) (*Result, error) {
	decision := eng.Evaluate(&req)

	requiredApproval := decision.Decision == types.DecisionRequireApproval
	if requiredApproval && autoApprove {
		decision.Decision = types.DecisionAllow
		decision.Reasons = append(decision.Reasons, "auto-approved via CLI flag")
	}

	decision.Timestamp = time.Now().UTC().Format(time.RFC3339)
	decision.RequestID = fmt.Sprintf("req-%d", time.Now().UTC().UnixNano())
	decision.MatchedResource = req.Resource
	decision.EvaluatedRole = req.Role

	if err := audit.LogDecision(*decision, req); err != nil {
		return nil, fmt.Errorf("failed to write audit log: %w", err)
	}

	controls := compliance.MapControls(req, decision.Decision)
	bundle, err := evidence.Generate(*decision, req, controls)
	if err != nil {
		return nil, fmt.Errorf("failed to generate evidence bundle: %w", err)
	}

	return &Result{
		Decision:         decision,
		Bundle:           bundle,
		RequiredApproval: requiredApproval,
	}, nil
}
