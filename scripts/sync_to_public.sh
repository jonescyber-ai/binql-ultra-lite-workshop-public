#!/usr/bin/env bash
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
PRIVATE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PUBLIC_DIR="${PRIVATE_DIR}/../binql-ultra-lite-workshop-public"

if [ ! -d "$PUBLIC_DIR/.git" ]; then
  echo "❌  Public repo not found at: $PUBLIC_DIR"
  echo "    Clone it first:  git clone git@github.com:jonescyber-ai/binql-ultra-lite-workshop-public.git"
  exit 1
fi

# ── Sync files (excluding .git and private-only content) ─────────────────────
echo "Syncing private → public..."
rsync -a --delete \
  --exclude='.git' \
  --exclude='.claude' \
  --exclude='internal_docs' \
  --exclude='labs' \
  --exclude='venv' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='.output.txt' \
  --exclude='.idea' \
  --exclude='Blackfyre' \
  "$PRIVATE_DIR/" "$PUBLIC_DIR/"

# ── Sensitive-content checks ─────────────────────────────────────────────────
echo "Running sensitive-content checks..."
FAIL=0

# 1. Check that api_key is null in the YAML config
if grep -P '^\s*api_key:' "$PUBLIC_DIR/lab_common/llm/llm_client_config.yaml" 2>/dev/null | grep -vqP '^\s*api_key:\s*null'; then
  echo "❌  FAIL: llm_client_config.yaml contains a non-null api_key!"
  FAIL=1
fi

# 2. Scan for common secret patterns (API keys, tokens, passwords)
SECRET_HITS=$(grep -rInP \
  '(sk-[A-Za-z0-9_-]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|password\s*=\s*"[^"]+")' \
  "$PUBLIC_DIR" \
  --include='*.py' --include='*.yaml' --include='*.yml' --include='*.json' \
  --include='*.md' --include='*.txt' --include='*.cfg' --include='*.ini' \
  --include='*.toml' --include='*.sh' --include='*.env*' \
  2>/dev/null || true)

if [ -n "$SECRET_HITS" ]; then
  echo "❌  FAIL: Potential secrets/tokens found:"
  echo "$SECRET_HITS"
  FAIL=1
fi

# 3. Check for .env files that slipped through
ENV_FILES=$(find "$PUBLIC_DIR" -name '.env' -o -name '.env.*' -not -path '*/.git/*' 2>/dev/null || true)
if [ -n "$ENV_FILES" ]; then
  echo "❌  FAIL: .env file(s) found:"
  echo "$ENV_FILES"
  FAIL=1
fi

# 4. Verify excluded directories are actually gone
for DIR in .claude internal_docs labs venv Blackfyre; do
  if [ -d "$PUBLIC_DIR/$DIR" ]; then
    echo "❌  FAIL: $DIR/ still present in public repo! (Attempting manual removal...)"
    rm -rf "$PUBLIC_DIR/$DIR"
    if [ -d "$PUBLIC_DIR/$DIR" ]; then
        FAIL=1
    fi
  fi
done

if [ "$FAIL" -ne 0 ]; then
  echo ""
  echo "🛑  Sensitive-content checks FAILED. Review the public folder before committing."
  exit 1
fi
echo "✅  All sensitive-content checks passed."
# ─────────────────────────────────────────────────────────────────────────────

# ── Show what changed (don't auto-commit — let the user review) ──────────────
echo ""
echo "Public repo updated at: $PUBLIC_DIR"
echo "Review the changes, then commit and push:"
echo ""
echo "  cd $PUBLIC_DIR"
echo "  git add -A"
echo "  git diff --cached --stat"
echo "  git commit -m \"Sync from private repo — $(date +%Y-%m-%d)\""
echo "  git push origin main"
echo ""
echo "Done."
