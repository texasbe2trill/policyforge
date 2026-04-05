package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/texasbe2trill/policyforge/internal/config"
	"github.com/texasbe2trill/policyforge/internal/policy"
	"github.com/texasbe2trill/policyforge/internal/service"
	"github.com/texasbe2trill/policyforge/internal/types"
)

func main() {
	policyFile := flag.String("policy", "configs/policy.yaml", "path to policy YAML file")
	addr := flag.String("addr", ":8080", "TCP address to listen on")
	flag.Parse()

	p, err := config.LoadPolicy(*policyFile)
	if err != nil {
		log.Fatalf("failed to load policy: %v", err)
	}
	eng := policy.New(p)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("POST /evaluate", evaluateHandler(eng))

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

		if err := config.ValidateRequest(req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		autoApprove := r.URL.Query().Get("auto_approve") == "true"

		result, err := service.Evaluate(eng, req, autoApprove)
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

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}
