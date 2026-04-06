package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/texasbe2trill/policyforge/internal/approval"
	"github.com/texasbe2trill/policyforge/internal/config"
	"github.com/texasbe2trill/policyforge/internal/drift"
	"github.com/texasbe2trill/policyforge/internal/policy"
	"github.com/texasbe2trill/policyforge/internal/service"
	"github.com/texasbe2trill/policyforge/internal/session"
	"github.com/texasbe2trill/policyforge/internal/types"
	"github.com/texasbe2trill/policyforge/internal/version"
)

func main() {
	policyFile := flag.String("policy", "configs/policy.yaml", "path to policy YAML file")
	inputFile := flag.String("input", "", "path to a JSON request file")
	subject := flag.String("subject", "", "subject making the request")
	role := flag.String("role", "", "role assigned to the subject")
	resource := flag.String("resource", "", "resource being accessed")
	action := flag.String("action", "", "action being performed")
	tier := flag.String("tier", "", "requested safety tier")
	autoApprove := flag.Bool("auto-approve", false, "convert require_approval to allow")
	agent := flag.String("agent", "", "agent envelope name to apply")
	driftCheck := flag.Bool("drift-check", false, "scan the audit log for policy drift and exit")
	listApprovals := flag.Bool("list-approvals", false, "list approval records and exit")
	approveID := flag.String("approve-id", "", "approve a pending request by approval ID")
	rejectID := flag.String("reject-id", "", "reject a pending request by approval ID")
	decidedBy := flag.String("decided-by", "", "name of the person making an approval decision")
	decisionNote := flag.String("decision-note", "", "optional note for an approval decision")
	listSessions := flag.Bool("list-sessions", false, "list all sessions and exit")
	revokeSessionID := flag.String("revoke-session-id", "", "revoke the specified session and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	switch {
	case *showVersion:
		fmt.Println("policyforge " + version.Version)
		return
	case *listApprovals:
		mustPrintJSONResult(approval.List())
		return
	case *approveID != "":
		handleApprove(*approveID, *decidedBy, *decisionNote)
		return
	case *rejectID != "":
		handleReject(*rejectID, *decidedBy, *decisionNote)
		return
	case *listSessions:
		mustPrintJSONResult(session.List())
		return
	case *revokeSessionID != "":
		handleRevokeSession(*revokeSessionID)
		return
	case *driftCheck:
		handleDriftCheck(*policyFile)
		return
	}

	req, err := loadRequest(*inputFile, *subject, *role, *resource, *action, *tier, *agent)
	if err != nil {
		log.Fatalf("invalid CLI request: %v", err)
	}

	eng := mustLoadEngine(*policyFile)
	result, err := service.Evaluate(eng, req, service.EvalOpts{
		AutoApprove:       *autoApprove,
		AutoApproveReason: "auto-approved via CLI flag",
		AutoApproveActor:  "cli-auto-approve",
	})
	if err != nil {
		log.Fatalf("evaluation failed: %v", err)
	}

	if result.Decision.Decision == types.DecisionRequireApproval && result.ApprovalRecord != nil {
		fmt.Fprintf(os.Stderr, "Approval required -- approval ID: %s\n", result.ApprovalRecord.ApprovalID)
	}
	printJSON(result.Decision)
}

func handleApprove(id, decidedBy, note string) {
	if decidedBy == "" {
		log.Fatalf("--decided-by is required with --approve-id")
	}
	if err := approval.Approve(id, decidedBy, note); err != nil {
		log.Fatalf("failed to approve request: %v", err)
	}
	printJSON(map[string]string{"approved": id, "decided_by": decidedBy})
}

func handleReject(id, decidedBy, note string) {
	if decidedBy == "" {
		log.Fatalf("--decided-by is required with --reject-id")
	}
	if err := approval.Reject(id, decidedBy, note); err != nil {
		log.Fatalf("failed to reject request: %v", err)
	}
	printJSON(map[string]string{"rejected": id, "decided_by": decidedBy})
}

func handleRevokeSession(id string) {
	if err := session.Revoke(id); err != nil {
		log.Fatalf("failed to revoke session: %v", err)
	}
	printJSON(map[string]string{"revoked": id})
}

func handleDriftCheck(policyFile string) {
	eng := mustLoadEngine(policyFile)
	findings, err := drift.Detect(eng)
	if err != nil {
		log.Fatalf("failed to detect drift: %v", err)
	}
	if len(findings) == 0 {
		printJSON(map[string]any{"findings": []drift.Finding{}, "summary": "no drift detected"})
		return
	}
	printJSON(findings)
}

func loadRequest(inputFile, subject, role, resource, action, tier, agent string) (types.DecisionRequest, error) {
	if inputFile != "" {
		return config.LoadRequest(inputFile)
	}

	req := types.DecisionRequest{
		Subject:       subject,
		Role:          role,
		Resource:      resource,
		Action:        action,
		RequestedTier: types.SafetyTier(tier),
		Agent:         agent,
	}
	if err := config.ValidateRequest(req); err != nil {
		return types.DecisionRequest{}, err
	}
	return req, nil
}

func mustLoadEngine(policyFile string) *policy.Engine {
	p, err := config.LoadPolicy(policyFile)
	if err != nil {
		log.Fatalf("failed to load policy: %v", err)
	}
	return policy.New(p)
}

func mustPrintJSONResult[T any](value T, err error) {
	if err != nil {
		log.Fatalf("command failed: %v", err)
	}
	printJSON(value)
}

func printJSON[T any](value T) {
	data, marshalErr := json.MarshalIndent(value, "", "  ")
	if marshalErr != nil {
		log.Fatalf("failed to encode JSON: %v", marshalErr)
	}
	fmt.Println(string(data))
}