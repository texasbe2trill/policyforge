package drift

// DriftType categorises the kind of policy violation detected.
type DriftType string

// Severity indicates how critical a finding is.
type Severity string

const (
	DriftDecisionMismatch           DriftType = "decision_mismatch"
	DriftUnauthorizedResourceAccess DriftType = "unauthorized_resource_access"
	DriftUnauthorizedAction         DriftType = "unauthorized_action"
	DriftAgentEnvelopeViolation     DriftType = "agent_envelope_violation"
	DriftTierExceeded               DriftType = "tier_exceeded"

	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

// Finding represents a single drift detection result.
type Finding struct {
	FindingID        string    `json:"finding_id"`
	Timestamp        string    `json:"timestamp"`
	RequestID        string    `json:"request_id"`
	Subject          string    `json:"subject"`
	Agent            string    `json:"agent,omitempty"`
	Role             string    `json:"role"`
	Resource         string    `json:"resource"`
	Action           string    `json:"action"`
	RequestedTier    string    `json:"requested_tier"`
	ObservedDecision string    `json:"observed_decision"`
	ExpectedDecision string    `json:"expected_decision"`
	Severity         Severity  `json:"severity"`
	DriftType        DriftType `json:"drift_type"`
	Message          string    `json:"message"`
}
