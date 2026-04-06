package auth

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/texasbe2trill/policyforge/internal/session"
)

// DebugOIDCEnvVar is the environment variable that enables the OIDC stub path.
// Never enable in production.
const DebugOIDCEnvVar = "POLICYFORGE_ENABLE_DEBUG_OIDC"

// Middleware authenticates requests before passing them to next.
//
// Authentication order:
//  1. Bearer token (always checked)
//  2. OIDC stub via X-Debug-OIDC-Subject (only when POLICYFORGE_ENABLE_DEBUG_OIDC=true)
//
// On success the authenticated Identity is attached to the request context.
// On failure a 401 JSON response is returned immediately.
func Middleware(ts *TokenStore, next http.Handler) http.Handler {
	debugOIDC := os.Getenv(DebugOIDCEnvVar) == "true"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := authenticate(r, ts, debugOIDC)
		if err != nil {
			writeAuthError(w, err.Error())
			return
		}
		r = r.WithContext(WithIdentity(r.Context(), *id))
		next.ServeHTTP(w, r)
	})
}

func authenticate(r *http.Request, ts *TokenStore, debugOIDC bool) (*Identity, error) {
	// 1. Bearer token.
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		if !strings.HasPrefix(authHeader, "Bearer ") {
			return nil, fmt.Errorf("authorization header must use Bearer scheme")
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		entry, ok := ts.Lookup(token)
		if !ok {
			return nil, fmt.Errorf("invalid or unknown token")
		}
		return resolveSession(entry)
	}

	// 2. Debug OIDC stub — only when explicitly enabled via env var.
	if debugOIDC {
		if subject := r.Header.Get("X-Debug-OIDC-Subject"); subject != "" {
			role := r.Header.Get("X-Debug-OIDC-Role")
			if role == "" {
				role = "viewer"
			}
			entry := TokenEntry{
				Subject:  subject,
				Role:     role,
				AuthType: string(session.AuthTypeOIDCStub),
			}
			return resolveSession(entry)
		}
	}

	return nil, fmt.Errorf("authentication required: provide a Bearer token")
}

// resolveSession looks for an existing active session for the identity; creates
// one if none exists. Returns an error if the most recent session is revoked or
// expired (the caller will receive a 401).
func resolveSession(entry TokenEntry) (*Identity, error) {
	authType := session.AuthType(entry.AuthType)
	ttl := session.DefaultUserTTL
	if authType == session.AuthTypeAgentToken || entry.Agent != "" {
		authType = session.AuthTypeAgentToken
		ttl = session.DefaultAgentTTL
	}

	// Reuse an existing active session rather than creating one per request.
	existing, err := session.FindActive(entry.Subject, authType)
	if err != nil {
		// Session revoked or explicitly expired — deny.
		return nil, fmt.Errorf("access denied: %s", err)
	}

	var sess *session.Session
	if existing != nil {
		sess = existing
	} else {
		sess, err = session.Create(entry.Subject, entry.Role, entry.Agent, authType, ttl)
		if err != nil {
			// Non-fatal: log but continue without a persisted session.
			log.Printf("auth: failed to create session for %s: %v", entry.Subject, err)
		}
	}

	id := &Identity{
		Subject:  entry.Subject,
		Role:     entry.Role,
		Agent:    entry.Agent,
		AuthType: string(authType),
	}
	if sess != nil {
		id.SessionID = sess.SessionID
		id.SessionIssuedAt = sess.IssuedAt
	}
	return id, nil
}

func writeAuthError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", "Bearer")
	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintf(w, "{\"error\":%q}\n", msg)
}
