Output artifacts/demo-approvals.gif

Set Shell "zsh"
Set FontSize 15
Set FontFamily "CaskaydiaCove Nerd Font"
Set Width 1100
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
# Clean approvals, evidence, and drift dirs; seed one historical "allow"
# that current policy would deny (viewer allowed to restart — now denied).
Type 'rm -f artifacts/approvals.json && rm -rf artifacts/evidence artifacts/drift'
Enter
Sleep 200ms
Type "cat << 'EOF' > artifacts/audit.jsonl"
Enter
Sleep 100ms
Type '{"request_id":"req-hist-001","timestamp":"2026-01-15T10:22:00Z","subject":"alice","role":"viewer","resource":"staging/payment-service","action":"restart","requested_tier":"read_only","decision":"allow","reasons":["allowed by previous policy"],"hash":"a1b2c3d4"}'
Enter
Sleep 100ms
Type 'EOF'
Enter
Sleep 300ms
Type 'clear && printf "\033[1;36m PolicyForge \033[0m\033[0;37m— approval workflow + drift detection\033[0m\n\n"'
Enter
Sleep 200ms
Show
Sleep 1.5s

Hide
Type 'clear && printf "\033[1;33m── require_approval \033[0m  operator restarts prod/payment-service\n\n"'
Enter
Sleep 200ms
Show
Type 'go run ./cmd/policyforge --policy configs/policy.yaml --subject chris --role operator --resource prod/payment-service --action restart --tier supervised_write'
Enter
Sleep 8s

Hide
Type "APPROVAL_ID=$(go run ./cmd/policyforge --list-approvals | jq -r '.[0].approval_id')"
Enter
Sleep 5s
Type 'clear && printf "\033[1;34m── list approvals \033[0m  inspect the pending queue\n\n"'
Enter
Sleep 200ms
Show
Type 'go run ./cmd/policyforge --list-approvals | jq .'
Enter
Sleep 5s

Hide
Type 'clear && printf "\033[1;32m── approve \033[0m  decide the pending request\n\n"'
Enter
Sleep 200ms
Show
Type 'go run ./cmd/policyforge --approve-id "$APPROVAL_ID" --decided-by chris --decision-note "approved for emergency maintenance"'
Enter
Sleep 5s

Hide
Type 'clear && printf "\033[1;31m── drift check \033[0m  one historical allow now violates current policy\n\n"'
Enter
Sleep 200ms
Show
Type 'go run ./cmd/policyforge --policy configs/policy.yaml --drift-check 2>/dev/null | jq .'
Enter
Sleep 8s

Sleep 1.5s
