Output artifacts/demo-auth.gif

Set Shell "zsh"
Set FontSize 13
Set FontFamily "CaskaydiaCove Nerd Font"
Set Width 1500
Set Height 750
Set Theme "Dracula"
Set Padding 28
Set TypingSpeed 50ms
Set PlaybackSpeed 1.0
Set CursorBlink false

Hide
Type 'cd /Users/chriscampbell/GitHub/policyforge'
Enter
Sleep 200ms
Type 'export PATH="/opt/homebrew/bin:$PATH"'
Enter
Sleep 200ms
Type "export PS1='$ '"
Enter
Sleep 200ms
# Clean slate.
Type 'rm -f artifacts/sessions.json && kill $(lsof -ti:8080) 2>/dev/null; true'
Enter
Sleep 500ms
# Pre-write JSON payloads to temp files — avoids quote-escaping in visible Type commands.
Type "cat << 'EOF' > /tmp/pf-req-prod.json"
Enter
Type '{"resource":"prod/payment-service","action":"restart","requested_tier":"supervised_write"}'
Enter
Type 'EOF'
Enter
Sleep 200ms
Type "cat << 'EOF' > /tmp/pf-req-staging.json"
Enter
Type '{"resource":"staging/payment-service","action":"read","requested_tier":"read_only"}'
Enter
Type 'EOF'
Enter
Sleep 200ms
# Start the API with bearer-token auth; suppress startup log noise.
Type 'go run ./cmd/policyforge-api --policy configs/policy.yaml --tokens configs/tokens.yaml &>/dev/null &'
Enter
Sleep 4s
Type 'clear && printf "\033[1;36m PolicyForge \033[0m\033[0;37m— identity & sessions\033[0m\n\n"'
Enter
Sleep 200ms
Show
Sleep 1.5s

# -- Bearer token
Hide
Type 'clear && printf "\033[1;32m-- Bearer token \033[0m  identity comes from the token, not the request body\n\n"'
Enter
Sleep 200ms
Show
Type "curl -s -X POST http://localhost:8080/evaluate -H 'Authorization: Bearer dev-admin-token' -H 'Content-Type: application/json' --data @/tmp/pf-req-prod.json | jq ."
Enter
Sleep 6s

# -- No token -> 401
Hide
Type 'clear && printf "\033[1;31m-- No token -> 401 \033[0m  all endpoints protected when --tokens is configured\n\n"'
Enter
Sleep 200ms
Show
Type "curl -s -X POST http://localhost:8080/evaluate -H 'Content-Type: application/json' --data @/tmp/pf-req-staging.json | jq ."
Enter
Sleep 3s

# -- List sessions
Hide
Type 'clear && printf "\033[1;34m-- List sessions \033[0m  session created for dev-admin-token on first request\n\n"'
Enter
Sleep 200ms
Show
Type 'go run ./cmd/policyforge --list-sessions | jq .'
Enter
Sleep 6s

# -- Revoke -> same token now returns 401
Hide
Type "SESSION_ID=$(go run ./cmd/policyforge --list-sessions | jq -r '.[0].session_id')"
Enter
Sleep 6s
Type 'clear && printf "\033[1;31m-- Revoke session \033[0m  same token returns 401 after revocation\n\n"'
Enter
Sleep 200ms
Show
Type 'go run ./cmd/policyforge --revoke-session-id "$SESSION_ID" | jq .'
Enter
Sleep 4s
Type "curl -s -X POST http://localhost:8080/evaluate -H 'Authorization: Bearer dev-admin-token' -H 'Content-Type: application/json' --data @/tmp/pf-req-staging.json | jq ."
Enter
Sleep 4s

# -- Debug OIDC
Hide
Type 'kill $(lsof -ti:8080) 2>/dev/null; sleep 2'
Enter
Sleep 3s
Type 'POLICYFORGE_ENABLE_DEBUG_OIDC=true go run ./cmd/policyforge-api --policy configs/policy.yaml --tokens configs/tokens.yaml &>/dev/null &'
Enter
Sleep 4s
Type 'clear && printf "\033[1;35m-- Debug OIDC \033[0m  X-Debug-OIDC headers (local dev only, never in production)\n\n"'
Enter
Sleep 200ms
Show
Type "curl -s -X POST http://localhost:8080/evaluate -H 'X-Debug-OIDC-Subject: chris' -H 'X-Debug-OIDC-Role: admin' -H 'Content-Type: application/json' --data @/tmp/pf-req-prod.json | jq ."
Enter
Sleep 6s

Hide
Type 'kill $(lsof -ti:8080) 2>/dev/null; true'
Enter
Sleep 1s
Type 'clear'
Enter
Sleep 200ms
Show
Sleep 1.5s
