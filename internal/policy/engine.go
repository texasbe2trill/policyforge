package policy

import (
	"fmt"
	"time"

	"github.com/texasbe2trill/policyforge/internal/types"
)

// Engine evaluates policy decisions.
type Engine struct {
	policy *types.Policy
}

// New creates a new policy engine with the given policy.
func New(policy *types.Policy) *Engine {
	return &Engine{policy: policy}
}

// Evaluate applies the policy to a decision request and returns a decision.
func (e *Engine) Evaluate(req *types.DecisionRequest) *types.Decision {
	decision := &types.Decision{
		Reasons: []string{},
	}

	if e == nil || e.policy == nil {
		decision.Decision = types.DecisionDeny
		decision.Reasons = append(decision.Reasons, "invalid policy: engine is not initialized")
		return decision
	}

	if req == nil {
		decision.Decision = types.DecisionDeny
		decision.Reasons = append(decision.Reasons, "invalid request: request payload is required")
		return decision
	}

	// Check 1: Role exists
	role := e.findRole(req.Role)
	if role == nil {
		decision.Decision = types.DecisionDeny
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("deny: role '%s' was not found", req.Role))
		return decision
	}

	// Check 2: Action is allowed for role
	if !e.actionAllowedForRole(req.Action, role) {
		decision.Decision = types.DecisionDeny
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("deny: action '%s' is not allowed for role '%s'", req.Action, req.Role))
		return decision
	}

	// Check 3: Resource exists
	resource := e.findResource(req.Resource)
	if resource == nil {
		decision.Decision = types.DecisionDeny
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("deny: resource '%s' was not found", req.Resource))
		return decision
	}

	// Check 4: Role is allowed for resource
	if !e.resourceAllowedForRole(req.Resource, role) {
		decision.Decision = types.DecisionDeny
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("deny: role '%s' is not allowed to access resource '%s'", req.Role, req.Resource))
		return decision
	}

	// Check 5: Requested tier exists
	tier := e.findTier(req.RequestedTier)
	if tier == nil {
		decision.Decision = types.DecisionDeny
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("deny: requested tier '%s' was not found", req.RequestedTier))
		return decision
	}

	// Check 6: Requested tier is allowed for role
	if !e.tierAllowedForRole(req.RequestedTier, role) {
		decision.Decision = types.DecisionDeny
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("deny: requested tier '%s' is not allowed for role '%s'", req.RequestedTier, req.Role))
		return decision
	}

	if e.exceedsMaxTier(req.RequestedTier, role.MaxTier) {
		decision.Decision = types.DecisionRequireApproval
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("approval: requested tier '%s' exceeds role '%s' max tier '%s'", req.RequestedTier, req.Role, role.MaxTier))
		return decision
	}

	// Check 7: Agent envelope — hard deny/approval checks run before softgates so
	// that an agent restriction always takes precedence over a resource approval.
	if agentDecision := e.evaluateAgentEnvelope(req); agentDecision != nil {
		return agentDecision
	}

	// Check 8: Approval requirements
	if resource.RequiresApproval || tier.RequiresApproval {
		decision.Decision = types.DecisionRequireApproval
		reasons := []string{}
		if resource.RequiresApproval {
			reasons = append(reasons, fmt.Sprintf("approval: resource '%s' requires approval", req.Resource))
		}
		if tier.RequiresApproval {
			reasons = append(reasons, fmt.Sprintf("approval: tier '%s' requires approval", req.RequestedTier))
		}
		decision.Reasons = reasons
		return decision
	}

	// All checks passed
	decision.Decision = types.DecisionAllow
	decision.Reasons = append(decision.Reasons, "allow: all policy checks passed")
	return decision
}

// evaluateAgentEnvelope runs agent-specific checks after RBAC has passed.
// Returns a non-nil decision only when a check fails.
func (e *Engine) evaluateAgentEnvelope(req *types.DecisionRequest) *types.Decision {
	if req.Agent == "" {
		return nil
	}

	envelope := e.findAgentEnvelope(req.Agent)
	if envelope == nil {
		return denyDecision(fmt.Sprintf("deny: agent '%s' was not found in policy", req.Agent))
	}

	if !agentResourceAllowed(req.Resource, envelope) {
		return denyDecision(fmt.Sprintf("deny: agent '%s' is not allowed to access resource '%s'", req.Agent, req.Resource))
	}

	if !agentActionAllowed(req.Action, envelope) {
		return denyDecision(fmt.Sprintf("deny: agent '%s' cannot perform action '%s'", req.Agent, req.Action))
	}

	if e.exceedsMaxTier(req.RequestedTier, envelope.MaxTier) {
		d := &types.Decision{
			Decision: types.DecisionRequireApproval,
			Reasons:  []string{fmt.Sprintf("approval: agent '%s' requested tier '%s' exceeds envelope max tier '%s'", req.Agent, req.RequestedTier, envelope.MaxTier)},
		}
		return d
	}

	return nil
}

func denyDecision(reason string) *types.Decision {
	return &types.Decision{
		Decision: types.DecisionDeny,
		Reasons:  []string{reason},
	}
}

func (e *Engine) exceedsMaxTier(requested types.SafetyTier, max types.SafetyTier) bool {
	requestedRank, okRequested := tierRank(requested)
	maxRank, okMax := tierRank(max)
	if !okRequested || !okMax {
		return false
	}
	return requestedRank > maxRank
}

func tierRank(t types.SafetyTier) (int, bool) {
	switch t {
	case types.ReadOnly:
		return 1, true
	case types.SupervisedWrite:
		return 2, true
	case types.AutonomousWrite:
		return 3, true
	default:
		return 0, false
	}
}

// findRole returns the role with the matching name, or nil if not found.
func (e *Engine) findRole(name string) *types.Role {
	for i := range e.policy.Roles {
		if e.policy.Roles[i].Name == name {
			return &e.policy.Roles[i]
		}
	}
	return nil
}

// findResource returns the resource with the matching name, or nil if not found.
func (e *Engine) findResource(name string) *types.Resource {
	for i := range e.policy.Resources {
		if e.policy.Resources[i].Name == name {
			return &e.policy.Resources[i]
		}
	}
	return nil
}

// findTier returns the tier with the matching name, or nil if not found.
func (e *Engine) findTier(name types.SafetyTier) *types.Tier {
	for i := range e.policy.SafetyTiers {
		if types.SafetyTier(e.policy.SafetyTiers[i].Name) == name {
			return &e.policy.SafetyTiers[i]
		}
	}
	return nil
}

// actionAllowedForRole checks if the action is in the role's allowed actions.
func (e *Engine) actionAllowedForRole(action string, role *types.Role) bool {
	for _, a := range role.AllowedActions {
		if a == action {
			return true
		}
	}
	return false
}

// resourceAllowedForRole checks if the resource is in the role's allowed resources.
func (e *Engine) resourceAllowedForRole(resource string, role *types.Role) bool {
	for _, r := range role.AllowedResources {
		if r == resource {
			return true
		}
	}
	return false
}

// tierAllowedForRole checks if the tier is in the role's allowed tiers.
func (e *Engine) tierAllowedForRole(tier types.SafetyTier, role *types.Role) bool {
	for _, t := range role.AllowedTiers {
		if t == tier {
			return true
		}
	}
	return false
}

// findAgentEnvelope returns the envelope with the matching name, or nil.
func (e *Engine) findAgentEnvelope(name string) *types.AgentEnvelope {
	for i := range e.policy.AgentEnvelopes {
		if e.policy.AgentEnvelopes[i].Name == name {
			return &e.policy.AgentEnvelopes[i]
		}
	}
	return nil
}

// AgentTTLExceeded reports whether the named agent's session has outlived its
// configured session_ttl_minutes. Returns false if the agent has no envelope,
// the envelope has no TTL, or issuedAtStr cannot be parsed.
func (e *Engine) AgentTTLExceeded(agentName, issuedAtStr string) bool {
	envelope := e.findAgentEnvelope(agentName)
	if envelope == nil || envelope.SessionTTL == 0 {
		return false
	}
	issuedAt, err := time.Parse(time.RFC3339, issuedAtStr)
	if err != nil {
		return false
	}
	return time.Since(issuedAt) > time.Duration(envelope.SessionTTL)*time.Minute
}

// agentResourceAllowed checks whether the resource matches any pattern in the
// envelope's allowed_resources list. Patterns ending with "/*" are treated as
// prefix wildcards (e.g. "staging/*" matches "staging/payment-service").
func agentResourceAllowed(resource string, envelope *types.AgentEnvelope) bool {
	for _, pattern := range envelope.AllowedResources {
		if pattern == resource {
			return true
		}
		if len(pattern) > 1 && pattern[len(pattern)-2:] == "/*" {
			prefix := pattern[:len(pattern)-1] // "staging/"
			if len(resource) >= len(prefix) && resource[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}

// agentActionAllowed checks if the action is in the envelope's allowed actions.
func agentActionAllowed(action string, envelope *types.AgentEnvelope) bool {
	for _, a := range envelope.AllowedActions {
		if a == action {
			return true
		}
	}
	return false
}
