package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/texasbe2trill/policyforge/internal/auth"
	"github.com/texasbe2trill/policyforge/internal/config"
	"github.com/texasbe2trill/policyforge/internal/policy"
	"github.com/texasbe2trill/policyforge/internal/service"
	"github.com/texasbe2trill/policyforge/internal/session"
	"github.com/texasbe2trill/policyforge/internal/types"
)

func main() {
	policyFile := flag.String("policy", "configs/policy.yaml", "path to policy YAML file")
	tokensFile := flag.String("tokens", "", "path to tokens YAML file (enables auth when set)")
	addr := flag.String("addr", ":8080", "TCP address to listen on")
	flag.Parse()

	p, err := config.LoadPolicy(*policyFile)
	if err != nil {
		log.Fatalf("failed to load policy: %v", err)
	}
	eng := policy.New(p)

	// Build token store if a tokens file was provided.
	var ts *auth.TokenStore
	if *tokensFile != "" {
		ts, err = auth.LoadTokens(*tokensFile)
		if err != nil {
			log.Fatalf("failed to load token config: %v", err)
		}
		log.Printf("auth: loaded tokens from %s", *tokensFile)
	} else {
		log.Printf("auth: no --tokens file provided; API is unauthenticated")
	}

	protected := func(h http.Handler) http.Handler {
		if ts == nil {
			return h // no auth configured
		}
		return auth.Middleware(ts, h)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.Handle("POST /evaluate", protected(http.HandlerFunc(evaluateHandler(eng))))
	mux.Handle("GET /sessions", protected(http.HandlerFunc(adminOnly(sessionsListHandler))))
	mux.Handle("POST /sessions/revoke", protected(http.HandlerFunc(adminOnly(sessionsRevokeHandler))))

	srv := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	log.Printf("policyforge-api listening on %s", *addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, `{"status":"ok"}`)
}

func evaluateHandler(eng *policy.Engine) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req types.DecisionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Build eval opts; override identity from auth context when present.
		opts := service.EvalOpts{
			AutoApprove: r.URL.Query().Get("auto_approve") == "true",
		}
		if id, ok := auth.GetIdentity(r.Context()); ok {
			opts.SessionID = id.SessionID
			opts.AuthType = id.AuthType
			opts.AuthSubject = id.Subject
			opts.AuthRole = id.Role
			opts.AuthAgent = id.Agent
			opts.SessionIssuedAt = id.SessionIssuedAt
			// Apply all identity overrides to req before validation.
			// Agent is always overridden (even to empty) so body can't inject an
			// agent name for a non-agent token.
			if id.Subject != "" {
				req.Subject = id.Subject
			}
			if id.Role != "" {
				req.Role = id.Role
			}
			req.Agent = id.Agent
		}

		if err := config.ValidateRequest(req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		result, err := service.Evaluate(eng, req, opts)
		if err != nil {
			log.Printf("evaluation error: %v", err)
			writeError(w, http.StatusInternalServerError, "evaluation failed")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(result.Decision); err != nil {
			log.Printf("encode error: %v", err)
		}
	}
}

func sessionsListHandler(w http.ResponseWriter, _ *http.Request) {
	sessions, err := session.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list sessions")
		return
	}
	if sessions == nil {
		sessions = []session.Session{}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(sessions); err != nil {
		log.Printf("encode error: %v", err)
	}
}

func sessionsRevokeHandler(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.SessionID == "" {
		writeError(w, http.StatusBadRequest, "session_id is required")
		return
	}
	if err := session.Revoke(body.SessionID); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"revoked":%q}`+"\n", body.SessionID)
}

// adminOnly is a role guard that wraps handlers requiring the "admin" role.
func adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := auth.GetIdentity(r.Context())
		if !ok || id.Role != "admin" {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		next(w, r)
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, "{\"error\":%q}\n", msg)
}
