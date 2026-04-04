package policy

import (
	"fmt"

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
		decision.Reasons = append(decision.Reasons, "policy is not initialized")
		return decision
	}

	if req == nil {
		decision.Decision = types.DecisionDeny
		decision.Reasons = append(decision.Reasons, "request is required")
		return decision
	}

	// Check 1: Role exists
	role := e.findRole(req.Role)
	if role == nil {
		decision.Decision = types.DecisionDeny
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("role '%s' does not exist", req.Role))
		return decision
	}

	// Check 2: Action is allowed for role
	if !e.actionAllowedForRole(req.Action, role) {
		decision.Decision = types.DecisionDeny
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("action '%s' is not allowed for role '%s'", req.Action, req.Role))
		return decision
	}

	// Check 3: Resource exists
	resource := e.findResource(req.Resource)
	if resource == nil {
		decision.Decision = types.DecisionDeny
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("resource '%s' does not exist", req.Resource))
		return decision
	}

	// Check 4: Role is allowed for resource
	if !e.resourceAllowedForRole(req.Resource, role) {
		decision.Decision = types.DecisionDeny
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("role '%s' is not allowed for resource '%s'", req.Role, req.Resource))
		return decision
	}

	// Check 5: Requested tier exists
	tier := e.findTier(req.RequestedTier)
	if tier == nil {
		decision.Decision = types.DecisionDeny
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("tier '%s' does not exist", req.RequestedTier))
		return decision
	}

	// Check 6: Requested tier is allowed for role
	if !e.tierAllowedForRole(req.RequestedTier, role) {
		decision.Decision = types.DecisionDeny
		decision.Reasons = append(decision.Reasons, fmt.Sprintf("tier '%s' is not allowed for role '%s'", req.RequestedTier, req.Role))
		return decision
	}

	// Check 7: Approval requirements
	if resource.RequiresApproval || tier.RequiresApproval {
		decision.Decision = types.DecisionRequireApproval
		reasons := []string{}
		if resource.RequiresApproval {
			reasons = append(reasons, fmt.Sprintf("resource '%s' requires approval", req.Resource))
		}
		if tier.RequiresApproval {
			reasons = append(reasons, fmt.Sprintf("tier '%s' requires approval", req.RequestedTier))
		}
		decision.Reasons = reasons
		return decision
	}

	// All checks passed
	decision.Decision = types.DecisionAllow
	decision.Reasons = append(decision.Reasons, "all policy checks passed")
	return decision
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
