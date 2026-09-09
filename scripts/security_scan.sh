#!/bin/bash
# security_scan.sh -- run this from the NETVA repo root before every push.
# Catches common hardcoded-secret patterns in the CURRENT working tree.
# For a deeper one-time check of full git history, also run gitleaks or
# trufflehog (see note at the bottom) -- this script only covers files as
# they exist right now.

set -e
cd "$(dirname "$0")/.."

echo "=== 1. Checking for accidentally-tracked secret/credential files ==="
git ls-files | grep -iE "\.pem$|\.key$|id_rsa|credentials\.json|^\.env$|\.env\.[a-z]+$" \
    && echo "  [!] FOUND -- review above before committing" \
    || echo "  OK -- none tracked"

echo
echo "=== 2. Scanning tracked files for secret-like patterns ==="
MATCHES=$(git grep -inE \
    "(api[_-]?key|secret[_-]?key|aws_secret_access_key|AKIA[0-9A-Z]{16}|BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY|ghp_[a-zA-Z0-9]{20,}|sk-[a-zA-Z0-9]{20,}|xox[baprs]-[0-9a-zA-Z-]+)" \
    -- . ':!lab/seed_vulns.sh' ':!*.md' 2>/dev/null || true)
if [ -n "$MATCHES" ]; then
    echo "  [!] Possible secrets found (excluding known-fake lab fixtures):"
    echo "$MATCHES"
else
    echo "  OK -- no matches outside known fixtures"
fi

echo
echo "=== 3. Checking for hardcoded password defaults in Python source ==="
MATCHES=$(git grep -inE "pass(word)?\s*[:=]\s*str\s*=\s*['\"][^'\"]+['\"]" -- '*.py' 2>/dev/null || true)
if [ -n "$MATCHES" ]; then
    echo "  [!] Found -- password fields should default to empty and come from .env:"
    echo "$MATCHES"
else
    echo "  OK -- no hardcoded password defaults"
fi

echo
echo "=== 4. Confirming .env is gitignored (not tracked) ==="
if git check-ignore -q .env 2>/dev/null; then
    echo "  OK -- .env is gitignored"
elif [ ! -f .env ]; then
    echo "  OK -- no .env file present locally"
else
    echo "  [!] .env exists and is NOT gitignored -- fix .gitignore before committing"
fi

echo
echo "=== 5. Confirming git remote points to YOUR account ==="
git remote -v

echo
echo "Done. For a thorough one-time check of ALL git history (not just current"
echo "files), install and run gitleaks:"
echo "    brew install gitleaks"
echo "    gitleaks detect --source . -v"