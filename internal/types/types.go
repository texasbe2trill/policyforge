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

// Policy defines the complete policy configuration.
type Policy struct {
	SafetyTiers []Tier     `yaml:"safety_tiers"`
	Roles       []Role     `yaml:"roles"`
	Resources   []Resource `yaml:"resources"`
}

// DecisionRequest represents a request to evaluate against policy.
type DecisionRequest struct {
	Subject       string     `json:"subject"`
	Role          string     `json:"role"`
	Resource      string     `json:"resource"`
	Action        string     `json:"action"`
	RequestedTier SafetyTier `json:"requested_tier"`
}

// Decision represents the result of a policy evaluation.
type Decision struct {
	Decision DecisionType `json:"decision"`
	Reasons  []string     `json:"reasons"`
}
