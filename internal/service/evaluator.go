package service

import (
	"fmt"
	"time"

	"github.com/texasbe2trill/policyforge/internal/approval"
	"github.com/texasbe2trill/policyforge/internal/audit"
	"github.com/texasbe2trill/policyforge/internal/compliance"
	"github.com/texasbe2trill/policyforge/internal/evidence"
	"github.com/texasbe2trill/policyforge/internal/policy"
	"github.com/texasbe2trill/policyforge/internal/types"
)

const policyVersion = "v0.1.0"

// Result holds every output produced by a single policy evaluation.
type Result struct {
	Decision         *types.Decision
	Bundle           *evidence.EvidenceBundle
	ApprovalRecord   *approval.Record
	RequiredApproval bool // true when the raw engine decision was require_approval
}

// Evaluate runs the full evaluation pipeline for a single request:
//
//  1. Engine decision
//  2. Metadata enrichment (timestamp, request ID, matched resource, evaluated role)
//  3. Optional auto-approve
//  4. Persist approval record if needed
//  5. Audit log (with hash chain)
//  6. Compliance control mapping
//  7. Evidence bundle generation (with approval + audit metadata)
//
// Both the CLI and the REST API call this function so their outputs are identical.
func Evaluate(eng *policy.Engine, req types.DecisionRequest, autoApprove bool) (*Result, error) {
	decision := eng.Evaluate(&req)

	requiredApproval := decision.Decision == types.DecisionRequireApproval

	decision.Timestamp = time.Now().UTC().Format(time.RFC3339)
	decision.RequestID = fmt.Sprintf("req-%d", time.Now().UTC().UnixNano())
	decision.MatchedResource = req.Resource
	decision.EvaluatedRole = req.Role

	// Persist approval record before potentially rewriting the decision.
	var approvalRec *approval.Record
	if requiredApproval {
		rec := approval.Record{
			ApprovalID:    approval.NewID(),
			RequestID:     decision.RequestID,
			Status:        approval.StatusPending,
			Subject:       req.Subject,
			Role:          req.Role,
			Agent:         req.Agent,
			Resource:      req.Resource,
			Action:        req.Action,
			RequestedTier: string(req.RequestedTier),
			Reasons:       decision.Reasons,
			RequestedAt:   decision.Timestamp,
		}
		if autoApprove {
			rec.Status = approval.StatusApproved
			rec.DecidedAt = decision.Timestamp
			rec.DecidedBy = "cli-auto-approve"
		}
		if err := approval.Create(rec); err != nil {
			return nil, fmt.Errorf("failed to persist approval record: %w", err)
		}
		approvalRec = &rec
	}

	if requiredApproval && autoApprove {
		decision.Decision = types.DecisionAllow
		decision.Reasons = append(decision.Reasons, "auto-approved via CLI flag")
	}

	auditHash, prevHash, err := audit.LogDecision(*decision, req)
	if err != nil {
		return nil, fmt.Errorf("failed to write audit log: %w", err)
	}

	controls := compliance.MapControls(req, decision.Decision)

	opts := evidence.Options{
		PolicyVersion:     policyVersion,
		AuditRecordHash:   auditHash,
		PreviousAuditHash: prevHash,
	}
	if approvalRec != nil {
		opts.ApprovalStatus = string(approvalRec.Status)
		opts.ApprovalID = approvalRec.ApprovalID
	}

	bundle, err := evidence.Generate(*decision, req, controls, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to generate evidence bundle: %w", err)
	}

	return &Result{
		Decision:         decision,
		Bundle:           bundle,
		ApprovalRecord:   approvalRec,
		RequiredApproval: requiredApproval,
	}, nil
}
