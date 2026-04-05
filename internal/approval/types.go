package approval

// Status represents the lifecycle state of an approval request.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
)

// Record persists the full context of an approval request and its resolution.
type Record struct {
	ApprovalID    string   `json:"approval_id"`
	RequestID     string   `json:"request_id"`
	Status        Status   `json:"status"`
	Subject       string   `json:"subject"`
	Role          string   `json:"role"`
	Agent         string   `json:"agent,omitempty"`
	Resource      string   `json:"resource"`
	Action        string   `json:"action"`
	RequestedTier string   `json:"requested_tier"`
	Reasons       []string `json:"reasons"`
	RequestedAt   string   `json:"requested_at"`
	DecidedAt     string   `json:"decided_at,omitempty"`
	DecidedBy     string   `json:"decided_by,omitempty"`
	DecisionNote  string   `json:"decision_note,omitempty"`
}
