package compliance

import (
	"strings"

	"github.com/texasbe2trill/policyforge/internal/types"
)

// MapControls returns the compliance control identifiers that apply to a given
// request and its resulting decision. Controls are deduplicated and ordered
// deterministically.
func MapControls(req types.DecisionRequest, decision types.DecisionType) []string {
	seen := map[string]bool{}
	var controls []string

	add := func(c string) {
		if !seen[c] {
			seen[c] = true
			controls = append(controls, c)
		}
	}

	// Production resources fall under PCI-DSS access control requirements.
	if strings.Contains(req.Resource, "prod") {
		add("PCI-DSS-7.2")
	}

	// Mutating actions are subject to PCI-DSS audit event requirements.
	switch req.Action {
	case "restart", "write", "scale":
		add("PCI-DSS-10.2")
	}

	// Any denied request must be recorded under the security enforcement control.
	if decision == types.DecisionDeny {
		add("SECURITY-ENFORCEMENT")
	}

	return controls
}
