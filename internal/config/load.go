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
	if len(policy.Roles) == 0 {
		return nil, fmt.Errorf("invalid policy: at least one role is required")
	}
	if len(policy.Resources) == 0 {
		return nil, fmt.Errorf("invalid policy: at least one resource is required")
	}

	return &policy, nil
}
