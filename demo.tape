Output artifacts/demo.gif

Set Shell "zsh"
Set FontSize 15
Set FontFamily "CaskaydiaCove Nerd Font"
Set Width 1100
Set Height 700
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
Type 'clear && printf "\033[1;36m PolicyForge \033[0m\033[0;37m— policy enforcement for infra workflows\033[0m\n\n"'
Enter
Sleep 200ms
Show
Sleep 1.5s

Hide
Type 'clear && printf "\033[1;32m── allow \033[0m  viewer reads staging/payment-service\n\n"'
Enter
Sleep 200ms
Show
Type 'go run ./cmd/policyforge --policy configs/policy.yaml --input examples/request-allow.json'
Enter
Sleep 5s

Hide
Type 'clear && printf "\033[1;31m── deny \033[0m  viewer attempts restart (action not permitted)\n\n"'
Enter
Sleep 200ms
Show
Type 'go run ./cmd/policyforge --policy configs/policy.yaml --input examples/request-deny-action.json'
Enter
Sleep 4s

Hide
Type 'clear && printf "\033[1;33m── require_approval \033[0m  operator restarts prod — auto-approved\n\n"'
Enter
Sleep 200ms
Show
Type 'go run ./cmd/policyforge --policy configs/policy.yaml --input examples/request-require-approval.json --auto-approve'
Enter
Sleep 5s

Hide
Type 'clear && printf "\033[1;35m── agent deny \033[0m  remediation-bot outside its staging envelope\n\n"'
Enter
Sleep 200ms
Show
Type 'go run ./cmd/policyforge --policy configs/policy.yaml --subject bot --role operator --resource prod/payment-service --action read --tier read_only --agent remediation-bot'
Enter
Sleep 5s

Hide
Type 'clear && printf "\033[1;34m── audit log \033[0m  tamper-evident hash chain\n\n"'
Enter
Sleep 200ms
Show
Type "tail -n 1 artifacts/audit.jsonl | jq '{decision,hash,previous_hash}'"
Enter
Sleep 2.5s

Hide
Type 'BUNDLE=$(ls -t artifacts/evidence/ | head -1)'
Enter
Sleep 200ms
Type 'clear && printf "\033[1;34m── evidence bundle \033[0m  compliance artifact\n\n"'
Enter
Sleep 200ms
Show
Type "cat artifacts/evidence/$BUNDLE | jq '{bundle_id,decision,controls}'"
Enter
Sleep 3s

Sleep 1.5s
