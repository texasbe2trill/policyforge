package config

import (
	"fmt"
	"os"

	"github.com/texasbe2trill/policyforge/internal/types"
	"gopkg.in/yaml.v3"
)

// LoadPolicy reads and parses a policy YAML file.
func LoadPolicy(filePath string) (*types.Policy, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var policy types.Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	if len(policy.SafetyTiers) == 0 {
		return nil, fmt.Errorf("invalid policy: at least one safety_tier is required")
	}
	tierNames := make(map[string]bool)
	for i, tier := range policy.SafetyTiers {
		if tier.Name == "" {
			return nil, fmt.Errorf("invalid policy: safety_tier at index %d is missing a name", i)
		}
		if tierNames[tier.Name] {
			return nil, fmt.Errorf("invalid policy: duplicate safety_tier name found: '%s'", tier.Name)
		}
		tierNames[tier.Name] = true
	}

	if len(policy.Roles) == 0 {
		return nil, fmt.Errorf("invalid policy: at least one role is required")
	}
	roleNames := make(map[string]bool)
	for i, role := range policy.Roles {
		if role.Name == "" {
			return nil, fmt.Errorf("invalid policy: role at index %d is missing a name", i)
		}
		if roleNames[role.Name] {
			return nil, fmt.Errorf("invalid policy: duplicate role name found: '%s'", role.Name)
		}
		if role.MaxTier == "" {
			return nil, fmt.Errorf("invalid policy: role '%s' must define max_tier", role.Name)
		}
		roleNames[role.Name] = true
	}

	if len(policy.Resources) == 0 {
		return nil, fmt.Errorf("invalid policy: at least one resource is required")
	}
	resourceNames := make(map[string]bool)
	for i, resource := range policy.Resources {
		if resource.Name == "" {
			return nil, fmt.Errorf("invalid policy: resource at index %d is missing a name", i)
		}
		if resourceNames[resource.Name] {
			return nil, fmt.Errorf("invalid policy: duplicate resource name found: '%s'", resource.Name)
		}
		resourceNames[resource.Name] = true
	}

	return &policy, nil
}
