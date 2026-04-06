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
	"github.com/texasbe2trill/policyforge/internal/version"
)

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
	req = applyIdentityOverrides(req, opts)
	decision := evaluateDecision(eng, req, opts)
	requiredApproval := decision.Decision == types.DecisionRequireApproval

	enrichDecision(decision, req)

	approvalRec, err := persistApprovalRecord(req, decision, opts, requiredApproval)
	if err != nil {
		return nil, err
	}

	applyAutoApprove(decision, opts, requiredApproval)

	auditHash, prevHash, err := audit.LogDecision(*decision, req, audit.Meta{
		SessionID: opts.SessionID,
		AuthType:  opts.AuthType,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to write audit log: %w", err)
	}

	controls := compliance.MapControls(req, decision.Decision)

	evOpts := evidence.Options{
		PolicyVersion:     version.Version,
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

func applyIdentityOverrides(req types.DecisionRequest, opts EvalOpts) types.DecisionRequest {
	if opts.AuthSubject != "" {
		req.Subject = opts.AuthSubject
	}
	if opts.AuthRole != "" {
		req.Role = opts.AuthRole
	}
	if opts.AuthAgent != "" {
		req.Agent = opts.AuthAgent
	}
	return req
}

func evaluateDecision(eng *policy.Engine, req types.DecisionRequest, opts EvalOpts) *types.Decision {
	if req.Agent != "" && opts.SessionIssuedAt != "" && eng.AgentTTLExceeded(req.Agent, opts.SessionIssuedAt) {
		return &types.Decision{
			Decision: types.DecisionDeny,
			Reasons:  []string{fmt.Sprintf("deny: agent session for '%s' exceeded TTL", req.Agent)},
		}
	}
	return eng.Evaluate(&req)
}

func enrichDecision(decision *types.Decision, req types.DecisionRequest) {
	decision.Timestamp = time.Now().UTC().Format(time.RFC3339)
	decision.RequestID = fmt.Sprintf("req-%d", time.Now().UTC().UnixNano())
	decision.MatchedResource = req.Resource
	decision.EvaluatedRole = req.Role
}

func persistApprovalRecord(req types.DecisionRequest, decision *types.Decision, opts EvalOpts, requiredApproval bool) (*approval.Record, error) {
	if !requiredApproval {
		return nil, nil
	}

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
		applyApprovalResolutionDefaults(&rec, decision.Timestamp, opts)
	}
	if err := approval.Create(rec); err != nil {
		return nil, fmt.Errorf("failed to persist approval record: %w", err)
	}
	return &rec, nil
}

func applyApprovalResolutionDefaults(rec *approval.Record, decidedAt string, opts EvalOpts) {
	rec.Status = approval.StatusApproved
	rec.DecidedAt = decidedAt
	rec.DecidedBy = opts.AutoApproveActor
	if rec.DecidedBy == "" {
		rec.DecidedBy = "auto-approve"
	}
}

func applyAutoApprove(decision *types.Decision, opts EvalOpts, requiredApproval bool) {
	if !requiredApproval || !opts.AutoApprove {
		return
	}
	decision.Decision = types.DecisionAllow
	reason := opts.AutoApproveReason
	if reason == "" {
		reason = "auto-approved"
	}
	decision.Reasons = append(decision.Reasons, reason)
}
