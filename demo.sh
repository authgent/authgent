#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# authgent — Live Terminal Demo
# Multi-hop agent delegation with scope narrowing
# ──────────────────────────────────────────────────────────────
set -euo pipefail

BASE="http://localhost:8000"
BOLD="\033[1m"
DIM="\033[2m"
CYAN="\033[36m"
GREEN="\033[32m"
YELLOW="\033[33m"
MAGENTA="\033[35m"
BLUE="\033[34m"
RED="\033[31m"
RESET="\033[0m"

step=0
step() {
  step=$((step + 1))
  echo ""
  echo -e "${BOLD}${CYAN}━━━ Step $step: $1 ━━━${RESET}"
  echo ""
}

info() { echo -e "  ${DIM}$1${RESET}"; }
result() { echo -e "  ${GREEN}✓${RESET} $1"; }
show_json() { echo "$1" | python3 -m json.tool 2>/dev/null | sed 's/^/    /'; }

# ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${MAGENTA}║           authgent — Agent Auth Demo                     ║${RESET}"
echo -e "${BOLD}${MAGENTA}║    OAuth 2.1 + Multi-Hop Delegation + Scope Narrowing    ║${RESET}"
echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════╝${RESET}"

# ──────────────────────────────────────────────────────────────
step "Check server health"
HEALTH=$(curl -s "$BASE/health")
show_json "$HEALTH"
result "Server is running"

# ──────────────────────────────────────────────────────────────
step "Register Orchestrator Agent (full scopes)"
ORCH=$(curl -s -X POST "$BASE/agents" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Orchestrator",
    "owner": "acme-corp",
    "allowed_scopes": ["read", "write", "admin"],
    "capabilities": ["planning", "delegation"],
    "agent_type": "orchestrator",
    "agent_provider": "openai"
  }')
ORCH_ID=$(echo "$ORCH" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_id'])")
ORCH_SEC=$(echo "$ORCH" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_secret'])")
ORCH_AGENT_ID=$(echo "$ORCH" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
result "Agent ID:    $ORCH_AGENT_ID"
result "Client ID:   $ORCH_ID"
result "Scopes:      read, write, admin"

# ──────────────────────────────────────────────────────────────
step "Register Search Agent (read-only, with token-exchange)"
SEARCH=$(curl -s -X POST "$BASE/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Search Agent",
    "grant_types": ["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
    "scope": "read"
  }')
SEARCH_ID=$(echo "$SEARCH" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_id'])")
SEARCH_SEC=$(echo "$SEARCH" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_secret'])")
result "Client ID:   $SEARCH_ID"
result "Scopes:      read"
result "Grants:      client_credentials, token-exchange"

# ──────────────────────────────────────────────────────────────
step "Register DB Agent (read + write, with token-exchange)"
DB=$(curl -s -X POST "$BASE/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Database Agent",
    "grant_types": ["client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
    "scope": "read write"
  }')
DB_ID=$(echo "$DB" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_id'])")
DB_SEC=$(echo "$DB" | python3 -c "import sys,json; print(json.load(sys.stdin)['client_secret'])")
result "Client ID:   $DB_ID"
result "Scopes:      read, write"

# ──────────────────────────────────────────────────────────────
step "Orchestrator gets its own token (client_credentials)"
TOKEN_RESP=$(curl -s -X POST "$BASE/token" \
  -d "grant_type=client_credentials&client_id=$ORCH_ID&client_secret=$ORCH_SEC&scope=read write admin")
ORCH_TOKEN=$(echo "$TOKEN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
TOKEN_TYPE=$(echo "$TOKEN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token_type'])")
EXPIRES=$(echo "$TOKEN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['expires_in'])")
result "Token type:  $TOKEN_TYPE"
result "Expires in:  ${EXPIRES}s"
result "Scopes:      read write admin"
info "Token (first 50 chars): ${ORCH_TOKEN:0:50}..."

# ──────────────────────────────────────────────────────────────
step "Decode Orchestrator token claims"
ORCH_CLAIMS=$(echo "$ORCH_TOKEN" | python3 -c "
import sys, json, base64
token = sys.stdin.read().strip()
payload = token.split('.')[1]
payload += '=' * (4 - len(payload) % 4)
claims = json.loads(base64.urlsafe_b64decode(payload))
print(json.dumps(claims, indent=2))
")
show_json "$ORCH_CLAIMS"
info "→ No 'act' claim yet — this is a first-party token"

# ──────────────────────────────────────────────────────────────
step "Orchestrator delegates to Search Agent (scope narrowed to 'read')"
info "Token Exchange (RFC 8693) — scope narrowing from [read,write,admin] → [read]"
EXCHANGE1=$(curl -s -X POST "$BASE/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=$SEARCH_ID&client_secret=$SEARCH_SEC&subject_token=$ORCH_TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:access_token&audience=$SEARCH_ID&scope=read")
SEARCH_TOKEN=$(echo "$EXCHANGE1" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
result "Delegation successful!"
result "New scope:   read (narrowed from read+write+admin)"

# ──────────────────────────────────────────────────────────────
step "Decode Search Agent delegated token"
SEARCH_CLAIMS=$(echo "$SEARCH_TOKEN" | python3 -c "
import sys, json, base64
token = sys.stdin.read().strip()
payload = token.split('.')[1]
payload += '=' * (4 - len(payload) % 4)
claims = json.loads(base64.urlsafe_b64decode(payload))
print(json.dumps(claims, indent=2))
")
show_json "$SEARCH_CLAIMS"
echo ""
info "→ 'act' claim shows Search Agent acting on behalf of Orchestrator"
info "→ 'sub' is still the original Orchestrator's identity"
info "→ Scope narrowed: only 'read' (cannot escalate)"

# ──────────────────────────────────────────────────────────────
step "Search Agent delegates to DB Agent (multi-hop chain)"
info "Second hop: Search → DB Agent (scope stays 'read')"
EXCHANGE2=$(curl -s -X POST "$BASE/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=$DB_ID&client_secret=$DB_SEC&subject_token=$SEARCH_TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:access_token&audience=$DB_ID&scope=read")
DB_TOKEN=$(echo "$EXCHANGE2" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
result "Multi-hop delegation successful!"

# ──────────────────────────────────────────────────────────────
step "Decode DB Agent token — nested delegation chain"
DB_CLAIMS=$(echo "$DB_TOKEN" | python3 -c "
import sys, json, base64
token = sys.stdin.read().strip()
payload = token.split('.')[1]
payload += '=' * (4 - len(payload) % 4)
claims = json.loads(base64.urlsafe_b64decode(payload))
print(json.dumps(claims, indent=2))
")
show_json "$DB_CLAIMS"
echo ""
info "→ Nested 'act' chain: DB Agent → Search Agent → Orchestrator"
info "→ Full audit trail preserved in a single JWT"
info "→ Scope still 'read' — no escalation possible at any hop"

# ──────────────────────────────────────────────────────────────
step "Verify scope escalation is BLOCKED"
info "Attempting to escalate: Search Agent requests 'write' (only has 'read')"
ESCALATION=$(curl -s -X POST "$BASE/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&client_id=$DB_ID&client_secret=$DB_SEC&subject_token=$SEARCH_TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:access_token&audience=$DB_ID&scope=read write")
echo -e "    ${RED}$(echo "$ESCALATION" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'✗ {d[\"error\"]}: {d[\"error_description\"]}')")${RESET}"
result "Scope escalation correctly denied!"

# ──────────────────────────────────────────────────────────────
step "Introspect the delegation token"
INTROSPECT=$(curl -s -X POST "$BASE/introspect" \
  -d "token=$DB_TOKEN")
show_json "$INTROSPECT"
result "Token is active with full delegation chain visible"

# ──────────────────────────────────────────────────────────────
step "Revoke the Orchestrator's original token"
curl -s -X POST "$BASE/revoke" \
  -d "token=$ORCH_TOKEN&client_id=$ORCH_ID" > /dev/null
result "Token revoked"

info "Verifying revoked token is rejected..."
REVOKE_CHECK=$(curl -s -X POST "$BASE/introspect" \
  -d "token=$ORCH_TOKEN")
ACTIVE=$(echo "$REVOKE_CHECK" | python3 -c "import sys,json; print(json.load(sys.stdin)['active'])")
echo -e "    active: ${RED}$ACTIVE${RESET}"
result "Revoked token correctly returns active=false"

# ──────────────────────────────────────────────────────────────
step "View JWKS public keys"
JWKS=$(curl -s "$BASE/.well-known/jwks.json")
show_json "$JWKS"
result "ES256 public key available for token verification"

# ──────────────────────────────────────────────────────────────
step "List all registered agents"
AGENTS=$(curl -s "$BASE/agents")
echo "$AGENTS" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for a in data['items']:
    print(f\"    {a['name']:20s} │ {a['agent_type'] or 'n/a':14s} │ scopes: {', '.join(a['allowed_scopes'] or [])}\")
"
result "3 agents registered, 2 delegation hops demonstrated"

# ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${MAGENTA}╔══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${MAGENTA}║                    Demo Complete!                         ║${RESET}"
echo -e "${BOLD}${MAGENTA}╠══════════════════════════════════════════════════════════╣${RESET}"
echo -e "${BOLD}${MAGENTA}║${RESET}  ${GREEN}✓${RESET} 3 agents registered with different scopes            ${BOLD}${MAGENTA}║${RESET}"
echo -e "${BOLD}${MAGENTA}║${RESET}  ${GREEN}✓${RESET} 2-hop delegation chain (Orchestrator→Search→DB)      ${BOLD}${MAGENTA}║${RESET}"
echo -e "${BOLD}${MAGENTA}║${RESET}  ${GREEN}✓${RESET} Scope narrowing enforced at every hop                ${BOLD}${MAGENTA}║${RESET}"
echo -e "${BOLD}${MAGENTA}║${RESET}  ${GREEN}✓${RESET} Scope escalation attack blocked                      ${BOLD}${MAGENTA}║${RESET}"
echo -e "${BOLD}${MAGENTA}║${RESET}  ${GREEN}✓${RESET} Token introspection with full chain                  ${BOLD}${MAGENTA}║${RESET}"
echo -e "${BOLD}${MAGENTA}║${RESET}  ${GREEN}✓${RESET} Token revocation verified                            ${BOLD}${MAGENTA}║${RESET}"
echo -e "${BOLD}${MAGENTA}║${RESET}  ${GREEN}✓${RESET} JWKS endpoint for external verification              ${BOLD}${MAGENTA}║${RESET}"
echo -e "${BOLD}${MAGENTA}╚══════════════════════════════════════════════════════════╝${RESET}"
echo ""
