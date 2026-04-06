package types

// SafetyTier represents the level of automation allowed for an action.
type SafetyTier string

// DecisionType represents an evaluation outcome.
type DecisionType string

const (
	ReadOnly        SafetyTier = "read_only"
	SupervisedWrite SafetyTier = "supervised_write"
	AutonomousWrite SafetyTier = "autonomous_write"

	DecisionAllow           DecisionType = "allow"
	DecisionDeny            DecisionType = "deny"
	DecisionRequireApproval DecisionType = "require_approval"
)

// Role represents a user role with specific capabilities.
type Role struct {
	Name             string       `yaml:"name"`
	AllowedActions   []string     `yaml:"allowed_actions"`
	AllowedTiers     []SafetyTier `yaml:"allowed_tiers"`
	MaxTier          SafetyTier   `yaml:"max_tier"`
	AllowedResources []string     `yaml:"allowed_resources"`
}

// Resource represents an infrastructure resource with access policies.
type Resource struct {
	Name             string `yaml:"name"`
	RequiresApproval bool   `yaml:"requires_approval"`
}

// Tier represents a safety tier with its approval requirements.
type Tier struct {
	Name             string `yaml:"name"`
	RequiresApproval bool   `yaml:"requires_approval"`
}

// AgentEnvelope constrains what an automated agent (bot, AI, pipeline) may do
// within a session, independent of RBAC. Both must pass for a decision to succeed.
type AgentEnvelope struct {
	Name             string     `yaml:"name"`
	AllowedResources []string   `yaml:"allowed_resources"`
	AllowedActions   []string   `yaml:"allowed_actions"`
	MaxTier          SafetyTier `yaml:"max_tier"`
	SessionTTL       int        `yaml:"session_ttl_minutes"`
}

// Policy defines the complete policy configuration.
type Policy struct {
	SafetyTiers    []Tier          `yaml:"safety_tiers"`
	Roles          []Role          `yaml:"roles"`
	Resources      []Resource      `yaml:"resources"`
	AgentEnvelopes []AgentEnvelope `yaml:"agent_envelopes"`
}

// DecisionRequest represents a request to evaluate against policy.
type DecisionRequest struct {
	Subject       string     `json:"subject"`
	Role          string     `json:"role"`
	Resource      string     `json:"resource"`
	Action        string     `json:"action"`
	RequestedTier SafetyTier `json:"requested_tier"`
	Agent         string     `json:"agent,omitempty"`
}

// Decision represents the result of a policy evaluation.
type Decision struct {
	Decision        DecisionType `json:"decision"`
	Reasons         []string     `json:"reasons"`
	Timestamp       string       `json:"timestamp"`
	RequestID       string       `json:"request_id"`
	MatchedResource string       `json:"matched_resource"`
	EvaluatedRole   string       `json:"evaluated_role"`
}

// AuditRecord is the JSONL payload persisted to audit logs.
// Hash is a SHA-256 digest of the record's key fields, providing tamper detection.
// PreviousHash chains each record to the one before it.
type AuditRecord struct {
	RequestID     string       `json:"request_id"`
	Timestamp     string       `json:"timestamp"`
	Subject       string       `json:"subject"`
	Role          string       `json:"role"`
	Resource      string       `json:"resource"`
	Action        string       `json:"action"`
	RequestedTier string       `json:"requested_tier"`
	Agent         string       `json:"agent,omitempty"`
	Decision      DecisionType `json:"decision"`
	Reasons       []string     `json:"reasons"`
	SessionID     string       `json:"session_id,omitempty"`
	AuthType      string       `json:"auth_type,omitempty"`
	Hash          string       `json:"hash"`
	PreviousHash  string       `json:"previous_hash,omitempty"`
}
