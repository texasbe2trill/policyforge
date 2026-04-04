package policy

import (
	"testing"

	"github.com/texasbe2trill/policyforge/internal/types"
)

func TestEngineEvaluate(t *testing.T) {
	// Build a test policy
	policy := &types.Policy{
		SafetyTiers: []types.Tier{
			{Name: "read_only", RequiresApproval: false},
			{Name: "supervised_write", RequiresApproval: true},
			{Name: "autonomous_write", RequiresApproval: false},
		},
		Roles: []types.Role{
			{
				Name:             "admin",
				AllowedActions:   []string{"read", "write", "restart"},
				AllowedTiers:     []types.SafetyTier{"read_only", "supervised_write", "autonomous_write"},
				AllowedResources: []string{"prod/service", "staging/service"},
			},
			{
				Name:             "operator",
				AllowedActions:   []string{"read", "restart"},
				AllowedTiers:     []types.SafetyTier{"read_only", "supervised_write"},
				AllowedResources: []string{"prod/service", "staging/service"},
			},
			{
				Name:             "auditor",
				AllowedActions:   []string{"read"},
				AllowedTiers:     []types.SafetyTier{"read_only"},
				AllowedResources: []string{"prod/service"},
			},
		},
		Resources: []types.Resource{
			{Name: "prod/service", RequiresApproval: true},
			{Name: "staging/service", RequiresApproval: false},
		},
	}

	engine := New(policy)

	tests := []struct {
		name             string
		request          *types.DecisionRequest
		expectedDecision types.DecisionType
		expectedReasons  int
	}{
		{
			name: "allow: operator reads staging service",
			request: &types.DecisionRequest{
				Subject:       "alice",
				Role:          "operator",
				Resource:      "staging/service",
				Action:        "read",
				RequestedTier: "read_only",
			},
			expectedDecision: types.DecisionAllow,
			expectedReasons:  1, // "all policy checks passed"
		},
		{
			name: "deny: role does not exist",
			request: &types.DecisionRequest{
				Subject:       "bob",
				Role:          "nonexistent",
				Resource:      "prod/service",
				Action:        "read",
				RequestedTier: "read_only",
			},
			expectedDecision: types.DecisionDeny,
			expectedReasons:  1,
		},
		{
			name: "deny: action not allowed for role",
			request: &types.DecisionRequest{
				Subject:       "alice",
				Role:          "auditor",
				Resource:      "prod/service",
				Action:        "restart",
				RequestedTier: "read_only",
			},
			expectedDecision: types.DecisionDeny,
			expectedReasons:  1,
		},
		{
			name: "deny: resource does not exist",
			request: &types.DecisionRequest{
				Subject:       "alice",
				Role:          "operator",
				Resource:      "prod/nonexistent",
				Action:        "read",
				RequestedTier: "read_only",
			},
			expectedDecision: types.DecisionDeny,
			expectedReasons:  1,
		},
		{
			name: "deny: role not allowed for resource",
			request: &types.DecisionRequest{
				Subject:       "carol",
				Role:          "auditor",
				Resource:      "staging/service",
				Action:        "read",
				RequestedTier: "read_only",
			},
			expectedDecision: types.DecisionDeny,
			expectedReasons:  1,
		},
		{
			name: "deny: tier does not exist",
			request: &types.DecisionRequest{
				Subject:       "alice",
				Role:          "operator",
				Resource:      "staging/service",
				Action:        "read",
				RequestedTier: "invalid_tier",
			},
			expectedDecision: types.DecisionDeny,
			expectedReasons:  1,
		},
		{
			name: "deny: tier not allowed for role",
			request: &types.DecisionRequest{
				Subject:       "alice",
				Role:          "auditor",
				Resource:      "prod/service",
				Action:        "read",
				RequestedTier: "autonomous_write",
			},
			expectedDecision: types.DecisionDeny,
			expectedReasons:  1,
		},
		{
			name: "require_approval: tier requires approval",
			request: &types.DecisionRequest{
				Subject:       "alice",
				Role:          "operator",
				Resource:      "staging/service",
				Action:        "restart",
				RequestedTier: "supervised_write",
			},
			expectedDecision: types.DecisionRequireApproval,
			expectedReasons:  1,
		},
		{
			name: "require_approval: resource requires approval",
			request: &types.DecisionRequest{
				Subject:       "alice",
				Role:          "admin",
				Resource:      "prod/service",
				Action:        "read",
				RequestedTier: "read_only",
			},
			expectedDecision: types.DecisionRequireApproval,
			expectedReasons:  1,
		},
		{
			name: "require_approval: both resource and tier require approval",
			request: &types.DecisionRequest{
				Subject:       "alice",
				Role:          "admin",
				Resource:      "prod/service",
				Action:        "restart",
				RequestedTier: "supervised_write",
			},
			expectedDecision: types.DecisionRequireApproval,
			expectedReasons:  2,
		},
		{
			name:             "deny: nil request",
			request:          nil,
			expectedDecision: types.DecisionDeny,
			expectedReasons:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := engine.Evaluate(tt.request)

			if decision.Decision != tt.expectedDecision {
				t.Errorf("expected decision %q, got %q", tt.expectedDecision, decision.Decision)
			}

			if len(decision.Reasons) != tt.expectedReasons {
				t.Errorf("expected %d reasons, got %d: %v", tt.expectedReasons, len(decision.Reasons), decision.Reasons)
			}
		})
	}
}
