package service

// EvalOpts carries per-request options for Evaluate.
//
// CLI callers set AutoApprove only; identity fields are taken from the request.
// API callers additionally fill the Auth* fields so the evaluator can override
// request body identity with the verified auth context.
type EvalOpts struct {
	// AutoApprove rewrites require_approval to allow (CLI convenience).
	AutoApprove bool

	// Auth context — non-empty values override identity fields in DecisionRequest.
	SessionID   string
	AuthType    string
	AuthSubject string
	AuthRole    string
	AuthAgent   string
	// SessionIssuedAt (RFC3339) enables agent session TTL enforcement.
	SessionIssuedAt string
}
