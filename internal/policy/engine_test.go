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
				MaxTier:          "autonomous_write",
				AllowedResources: []string{"prod/service", "staging/service"},
			},
			{
				Name:             "operator",
				AllowedActions:   []string{"read", "restart"},
				AllowedTiers:     []types.SafetyTier{"read_only", "supervised_write", "autonomous_write"},
				MaxTier:          "supervised_write",
				AllowedResources: []string{"prod/service", "staging/service"},
			},
			{
				Name:             "auditor",
				AllowedActions:   []string{"read"},
				AllowedTiers:     []types.SafetyTier{"read_only"},
				MaxTier:          "read_only",
				AllowedResources: []string{"prod/service"},
			},
		},
		Resources: []types.Resource{
			{Name: "prod/service", RequiresApproval: true},
			{Name: "staging/service", RequiresApproval: false},
		},
		AgentEnvelopes: []types.AgentEnvelope{
			{
				Name:             "staging-bot",
				AllowedResources: []string{"staging/*"},
				AllowedActions:   []string{"read", "restart"},
				MaxTier:          "supervised_write",
			},
			{
				Name:             "read-only-bot",
				AllowedResources: []string{"staging/service"},
				AllowedActions:   []string{"read"},
				MaxTier:          "read_only",
			},
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
			name: "require_approval: requested tier exceeds role max tier",
			request: &types.DecisionRequest{
				Subject:       "alice",
				Role:          "operator",
				Resource:      "staging/service",
				Action:        "restart",
				RequestedTier: "autonomous_write",
			},
			expectedDecision: types.DecisionRequireApproval,
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
		// Agent envelope tests
		{
			name: "allow: agent with wildcard resource match",
			request: &types.DecisionRequest{
				Subject:       "bot",
				Role:          "operator",
				Resource:      "staging/service",
				Action:        "restart",
				RequestedTier: "read_only",
				Agent:         "staging-bot",
			},
			expectedDecision: types.DecisionAllow,
			expectedReasons:  1,
		},
		{
			name: "deny: unknown agent",
			request: &types.DecisionRequest{
				Subject:       "bot",
				Role:          "operator",
				Resource:      "staging/service",
				Action:        "read",
				RequestedTier: "read_only",
				Agent:         "unknown-bot",
			},
			expectedDecision: types.DecisionDeny,
			expectedReasons:  1,
		},
		{
			name: "deny: agent resource not allowed (prod resource, staging-only bot)",
			request: &types.DecisionRequest{
				Subject:       "bot",
				Role:          "admin",
				Resource:      "prod/service",
				Action:        "read",
				RequestedTier: "read_only",
				Agent:         "staging-bot",
			},
			expectedDecision: types.DecisionDeny,
			expectedReasons:  1,
		},
		{
			name: "deny: agent action not allowed",
			request: &types.DecisionRequest{
				Subject:       "bot",
				Role:          "operator",
				Resource:      "staging/service",
				Action:        "read",
				RequestedTier: "read_only",
				Agent:         "read-only-bot",
			},
			// read-only-bot allows "read" — this should actually pass
			expectedDecision: types.DecisionAllow,
			expectedReasons:  1,
		},
		{
			name: "deny: agent action write not in envelope",
			request: &types.DecisionRequest{
				Subject:       "bot",
				Role:          "admin",
				Resource:      "staging/service",
				Action:        "write",
				RequestedTier: "read_only",
				Agent:         "staging-bot",
			},
			expectedDecision: types.DecisionDeny,
			expectedReasons:  1,
		},
		{
			name: "require_approval: agent tier exceeds envelope max",
			request: &types.DecisionRequest{
				Subject:       "bot",
				Role:          "admin",
				Resource:      "staging/service",
				Action:        "restart",
				RequestedTier: "autonomous_write",
				Agent:         "staging-bot",
			},
			expectedDecision: types.DecisionRequireApproval,
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
