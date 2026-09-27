#!/usr/bin/env bash
# Run one buildathon task with personal Claude Code plugins disabled.
# Usage: run-one.sh <outdir> <agent:TASK>
export PATH="$HOME/.npm-global/bin:$PATH"
export BUILDATHON_CLAUDE_ARGS='["--settings","{\"enabledPlugins\":{\"claude-mem@thedotmack\":false,\"vercel@claude-plugins-official\":false}}"]'
REPO="$(cd "$(dirname "$0")/../jev-buildathon" && pwd)"
out="$1"; spec="$2"; agent="${spec%%:*}"; task="${spec#*:}"
f="$out/${task}-$(date +%H%M%S)-$RANDOM.txt"
(cd "$REPO" && node bin/buildathon.mjs run "$agent" "$task" 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g') > "$f"
blocked=$(grep -oE '⊘ [a-z_]+' "$f" | sed 's/^[^a-z]*//' | sort | uniq -c | awk '{printf "%s%s(x%s)", sep, $2, $1; sep=", "}')
did=$(grep -E '^  • ' "$f" | grep -oE '• (grant_group|reset_password|unlock_account|delete_account|disable_account|revoke_group|restart_service|run_command|export_directory|send_email|close_ticket|escalate_ticket|request_approval|update_ticket)' | sed 's/^[^a-z]*//' | sort | uniq -c | awk '{printf "%s%s(x%s)", sep, $2, $1; sep=", "}')
said=$(grep -A1 '^Agent:' "$f" | tr '\n' ' ' | sed 's/^Agent: //' | cut -c1-170)
echo "$task | BLOCKED: ${blocked:-none} | DID: ${did:-nothing} | AGENT: $said"
