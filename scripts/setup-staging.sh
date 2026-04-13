#!/usr/bin/env bash
# ─── CLPI Phase 0: Staging Environment Setup ─────────────────────────────────
#
# This script guides you through setting up the staging environment.
# It automates KV namespace creation and secret migration where possible,
# and prompts for manual steps (Supabase, CF AI Gateway, Netlify, Fly.io).
#
# Prerequisites:
#   - wrangler CLI installed and authenticated
#   - flyctl CLI installed and authenticated
#   - All repo wrangler.toml files already updated with [env.staging] + [env.production] blocks
#
# Usage:
#   chmod +x scripts/setup-staging.sh
#   ./scripts/setup-staging.sh
#
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
err()   { echo -e "${RED}[ERROR]${NC} $1"; }

pause() {
  echo ""
  read -rp "Press Enter to continue (or Ctrl+C to abort)..."
  echo ""
}

# ─── Paths ────────────────────────────────────────────────────────────────────

SMOLTBOT_DIR="${SMOLTBOT_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
API_DIR="${API_DIR:-$SMOLTBOT_DIR/../mnemom-api}"
REPUTATION_DIR="${REPUTATION_DIR:-$SMOLTBOT_DIR/../mnemom-reputation}"
RISK_DIR="${RISK_DIR:-$SMOLTBOT_DIR/../mnemom-risk}"
HUNTER_DIR="${HUNTER_DIR:-$SMOLTBOT_DIR/../hunter}"

echo "═══════════════════════════════════════════════════════════════════"
echo " CLPI Phase 0: Staging Environment Setup"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo " Repos:"
echo "   mnemom-platform: $SMOLTBOT_DIR"
echo "   mnemom-api:  $API_DIR"
echo "   reputation:  $REPUTATION_DIR"
echo "   risk:        $RISK_DIR"
echo "   hunter:      $HUNTER_DIR"
echo ""

# ─── Step 1: Manual Prerequisites ─────────────────────────────────────────────

echo "═══════════════════════════════════════════════════════════════════"
echo " Step 1: Manual Prerequisites"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
warn "The following must be done manually in web dashboards:"
echo ""
echo "  1. Supabase: Create 'mnemom-staging' project"
echo "     - https://supabase.com/dashboard/projects"
echo "     - Run: supabase db dump | supabase db push (to copy schema)"
echo "     - Note the project URL and anon key"
echo ""
echo "  2. Cloudflare AI Gateway: Create 'mnemom-staging' gateway"
echo "     - https://dash.cloudflare.com → AI → AI Gateway → Create"
echo "     - Enable logging"
echo "     - Note the gateway URL"
echo ""
echo "  3. Cloudflare DNS: Add staging subdomains"
echo "     - gateway-staging.mnemom.ai → (will be set by wrangler)"
echo "     - api-staging.mnemom.ai → (will be set by wrangler)"
echo ""
echo "  4. Netlify: Enable branch deploys for 'staging' branch"
echo "     - Site settings → Build & deploy → Branches"
echo "     - Add 'staging' to branch deploy allowlist"
echo ""
pause

# ─── Step 2: Create Staging KV Namespaces ─────────────────────────────────────

echo "═══════════════════════════════════════════════════════════════════"
echo " Step 2: Create Staging KV Namespaces"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

create_kv() {
  local dir="$1"
  local name="$2"
  local env="$3"
  info "Creating KV namespace '$name' (--env $env) in $dir..."
  cd "$dir"
  local output
  output=$(wrangler kv:namespace create "$name" --env "$env" 2>&1) || {
    warn "KV creation returned non-zero. Output: $output"
    return
  }
  # Extract the ID from wrangler output
  local id
  id=$(echo "$output" | grep -oP 'id = "\K[^"]+' || echo "")
  if [ -n "$id" ]; then
    ok "Created KV namespace: $name → $id"
    echo "    Update wrangler.toml with: id = \"$id\""
  else
    echo "$output"
    warn "Could not parse KV ID. Check output above and update wrangler.toml manually."
  fi
  echo ""
}

info "Creating KV namespaces for staging workers..."
echo ""

create_kv "$SMOLTBOT_DIR/gateway"     "BILLING_CACHE"  "staging"
create_kv "$API_DIR"                   "SONAR_KV"       "staging"
create_kv "$REPUTATION_DIR/server"     "REPUTATION_KV"  "staging"
create_kv "$RISK_DIR/server"           "RISK_KV"        "staging"

warn "Update the staging KV IDs in each wrangler.toml before deploying!"
pause

# ─── Step 3: Re-set Production Secrets ─────────────────────────────────────────

echo "═══════════════════════════════════════════════════════════════════"
echo " Step 3: Re-set Production Secrets (CRITICAL)"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
warn "Once [env.production] blocks exist, secrets set without --env"
warn "are NOT available to --env production deploys."
warn ""
warn "You MUST re-set ALL production secrets with --env production"
warn "BEFORE the first env-aware deploy."
echo ""
echo "For each worker, run commands like:"
echo ""
echo "  # mnemom-platform gateway"
echo "  cd $SMOLTBOT_DIR/gateway"
echo "  echo \$SUPABASE_URL | wrangler secret put SUPABASE_URL --env production"
echo "  echo \$SUPABASE_KEY | wrangler secret put SUPABASE_KEY --env production"
echo "  # ... repeat for all secrets listed in wrangler.toml"
echo ""
echo "  # mnemom-api"
echo "  cd $API_DIR"
echo "  echo \$SUPABASE_URL | wrangler secret put SUPABASE_URL --env production"
echo "  # ... etc"
echo ""
echo "  # mnemom-reputation (from server/ directory)"
echo "  cd $REPUTATION_DIR/server"
echo "  # ... etc"
echo ""
echo "  # mnemom-risk (from server/ directory)"
echo "  cd $RISK_DIR/server"
echo "  # ... etc"
echo ""
err "DO NOT SKIP THIS STEP. Workers will break without their secrets."
pause

# ─── Step 4: Deploy Production (Verify Health) ─────────────────────────────────

echo "═══════════════════════════════════════════════════════════════════"
echo " Step 4: Deploy Production with --env production"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
info "After re-setting secrets, deploy production to verify health:"
echo ""
echo "  cd $SMOLTBOT_DIR/gateway  && npm run deploy:production"
echo "  cd $SMOLTBOT_DIR/observer && npm run deploy:production"
echo "  cd $API_DIR               && npm run deploy:production"
echo "  cd $REPUTATION_DIR/server && npm run deploy:production"
echo "  cd $RISK_DIR/server       && npm run deploy:production"
echo ""
warn "Verify each worker is healthy before proceeding!"
echo "  curl https://gateway.mnemom.ai/health"
echo "  curl https://api.mnemom.ai/v1/health"
echo ""
pause

# ─── Step 5: Set Staging Secrets ───────────────────────────────────────────────

echo "═══════════════════════════════════════════════════════════════════"
echo " Step 5: Set Staging Secrets"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
info "Set secrets for staging workers. Use staging Supabase credentials"
info "and Stripe test keys (sk_test_*)."
echo ""
echo "  # mnemom-platform gateway"
echo "  cd $SMOLTBOT_DIR/gateway"
echo "  echo \$STAGING_SUPABASE_URL | wrangler secret put SUPABASE_URL --env staging"
echo "  echo \$STAGING_SUPABASE_KEY | wrangler secret put SUPABASE_KEY --env staging"
echo "  # ... etc"
echo ""
pause

# ─── Step 6: Deploy Staging ───────────────────────────────────────────────────

echo "═══════════════════════════════════════════════════════════════════"
echo " Step 6: Deploy Staging"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
info "Deploy all staging workers:"
echo ""
echo "  cd $SMOLTBOT_DIR/gateway  && npm run deploy:staging"
echo "  cd $SMOLTBOT_DIR/observer && npm run deploy:staging"
echo "  cd $API_DIR               && npm run deploy:staging"
echo "  cd $REPUTATION_DIR/server && npm run deploy:staging"
echo "  cd $RISK_DIR/server       && npm run deploy:staging"
echo ""
echo "Verify staging health:"
echo "  curl https://gateway-staging.mnemom.ai/health"
echo "  curl https://api-staging.mnemom.ai/v1/health"
echo ""
pause

# ─── Step 7: Hunter Staging ───────────────────────────────────────────────────

echo "═══════════════════════════════════════════════════════════════════"
echo " Step 7: Hunter Staging (Fly.io)"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
info "Create the hunter-staging Fly.io app:"
echo ""
echo "  cd $HUNTER_DIR"
echo "  flyctl apps create hunter-staging"
echo "  flyctl volumes create data --app hunter-staging --region sjc --size 1"
echo "  flyctl secrets set --app hunter-staging \\"
echo "    ANTHROPIC_API_KEY=\$ANTHROPIC_API_KEY \\"
echo "    MOLTBOOK_API_KEY=\$MOLTBOOK_API_KEY \\"
echo "    MNEMOM_PUBLISH_KEY=\$MNEMOM_PUBLISH_KEY \\"
echo "    MNEMOM_API_KEY=\$MNEMOM_API_KEY \\"
echo "    OPENCLAW_GATEWAY_TOKEN=\$(openssl rand -hex 32)"
echo "  flyctl deploy --config fly.staging.toml --remote-only"
echo ""
pause

# ─── Step 8: Create Staging Branches ─────────────────────────────────────────

echo "═══════════════════════════════════════════════════════════════════"
echo " Step 8: Create Staging Branches"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
info "Create 'staging' branches in all repos:"
echo ""

for dir in "$SMOLTBOT_DIR" "$API_DIR" "$REPUTATION_DIR" "$RISK_DIR" "$HUNTER_DIR" "$SMOLTBOT_DIR/../mnemom-website"; do
  name=$(basename "$dir")
  echo "  cd $dir && git checkout -b staging && git push -u origin staging"
done

echo ""
pause

# ─── Step 9: Verification ────────────────────────────────────────────────────

echo "═══════════════════════════════════════════════════════════════════"
echo " Step 9: End-to-End Verification"
echo "═══════════════════════════════════════════════════════════════════"
echo ""
echo "Checklist:"
echo ""
echo "  [ ] Gateway staging responds:     curl https://gateway-staging.mnemom.ai/health"
echo "  [ ] API staging responds:         curl https://api-staging.mnemom.ai/v1/health"
echo "  [ ] Observer staging running:     wrangler tail mnemom-observer-staging"
echo "  [ ] Dashboard staging loads:      https://staging--mnemom.netlify.app"
echo "  [ ] Production still healthy:     curl https://gateway.mnemom.ai/health"
echo "  [ ] Full trace flow in staging:   Send request → gateway → observer → API → dashboard"
echo ""
echo "  [ ] CI/CD: Push to staging branch triggers staging deploy"
echo "  [ ] CI/CD: workflow_dispatch on main deploys to production"
echo ""
ok "Setup complete! Phase 0 staging environment is ready."
echo ""
