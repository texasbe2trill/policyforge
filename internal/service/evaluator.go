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
//  1. Override identity from auth context when opts carries one
//  2. Agent session TTL check (if session metadata is present)
//  3. Engine decision
//  4. Metadata enrichment (timestamp, request ID, matched resource, evaluated role)
//  5. Optional auto-approve
//  6. Persist approval record if needed
//  7. Audit log (with hash chain, session metadata)
//  8. Compliance control mapping
//  9. Evidence bundle generation (with approval + audit + session metadata)
//
// Both the CLI and the REST API call this function so their outputs are identical.
func Evaluate(eng *policy.Engine, req types.DecisionRequest, opts EvalOpts) (*Result, error) {
	// 1. Override identity from authenticated context (API path only).
	if opts.AuthSubject != "" {
		req.Subject = opts.AuthSubject
	}
	if opts.AuthRole != "" {
		req.Role = opts.AuthRole
	}
	if opts.AuthAgent != "" {
		req.Agent = opts.AuthAgent
	}

	// 2. Engine decision — or TTL-deny if the agent session has exceeded its window.
	// The TTL-deny flows through the full pipeline so it is audited and bundled.
	var decision *types.Decision
	if req.Agent != "" && opts.SessionIssuedAt != "" && eng.AgentTTLExceeded(req.Agent, opts.SessionIssuedAt) {
		decision = &types.Decision{
			Decision: types.DecisionDeny,
			Reasons:  []string{fmt.Sprintf("deny: agent session for '%s' exceeded TTL", req.Agent)},
		}
	} else {
		decision = eng.Evaluate(&req)
	}
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
		if opts.AutoApprove {
			rec.Status = approval.StatusApproved
			rec.DecidedAt = decision.Timestamp
			rec.DecidedBy = "cli-auto-approve"
		}
		if err := approval.Create(rec); err != nil {
			return nil, fmt.Errorf("failed to persist approval record: %w", err)
		}
		approvalRec = &rec
	}

	if requiredApproval && opts.AutoApprove {
		decision.Decision = types.DecisionAllow
		decision.Reasons = append(decision.Reasons, "auto-approved via CLI flag")
	}

	auditHash, prevHash, err := audit.LogDecision(*decision, req, audit.Meta{
		SessionID: opts.SessionID,
		AuthType:  opts.AuthType,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to write audit log: %w", err)
	}

	controls := compliance.MapControls(req, decision.Decision)

	evOpts := evidence.Options{
		PolicyVersion:     policyVersion,
		AuditRecordHash:   auditHash,
		PreviousAuditHash: prevHash,
		SessionID:         opts.SessionID,
		AuthType:          opts.AuthType,
	}
	if approvalRec != nil {
		evOpts.ApprovalStatus = string(approvalRec.Status)
		evOpts.ApprovalID = approvalRec.ApprovalID
	}

	bundle, err := evidence.Generate(*decision, req, controls, evOpts)
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
