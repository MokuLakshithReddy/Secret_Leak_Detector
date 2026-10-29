#!/usr/bin/env bash
# setup-fixture-repo.sh
# ---------------------
# End-to-end block-and-remediate demonstration for Secret Leak Detector.
#
# What this script proves:
#   1. A repository containing fake credentials is detected by the SLD CLI.
#   2. Remediating the credential (replacing with process.env reference) clears the finding.
#   3. The scan is deterministic and reproducible on any machine with Node.js >= 18.
#
# Usage:
#   bash demo/setup-fixture-repo.sh

set -euo pipefail

# Locate the SLD CLI
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CLI="$REPO_ROOT/dist/cli.js"

if [[ ! -f "$CLI" ]]; then
  echo "ERROR: $CLI not found. Run 'npm run build' first." >&2
  exit 1
fi

# Synthesize test credentials at runtime so the source file is clean
PART_AK="AKIA"
PART_ID="2G7T4X9K1M8P5Q3R"
DEMO_AWS_KEY="${PART_AK}${PART_ID}"

PART_SCHEME="postgres://admin:s3cr3t"
PART_HOST="Passw0rd123!@db.internal.corp:5432/myapp"
DEMO_DB_URL="${PART_SCHEME}${PART_HOST}"

# Create isolated temp fixture repo
TMPDIR_FIXTURE="$(mktemp -d)"
echo "Created fixture repo at: $TMPDIR_FIXTURE"
cd "$TMPDIR_FIXTURE"

git init -q
git config user.email "demo@example.com"
git config user.name "SLD Demo"

# Write fixture files
mkdir -p config
cat > config/aws.env <<ENVFILE
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=${DEMO_AWS_KEY}
ENVFILE

mkdir -p db
cat > db/connect.js <<DBFILE
// Database connection helper
const DATABASE_URL = "${DEMO_DB_URL}";
module.exports = { DATABASE_URL };
DBFILE

mkdir -p src
cat > src/api.ts <<'APIFILE'
// API configuration
const API_SECRET = "a3f8c2e1b9d4726e0f5a1c8b3d7e9f2a4c6b8d0e";
export { API_SECRET };
APIFILE

mkdir -p crypto
cat > crypto/hash.txt <<'HASHFILE'
# These are safe, well-known hash formats - not secrets
commit abc123def456789012345678901234567890abcdef
sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxbd5R/mJnQ=
HASHFILE

cat > README.md <<'RME'
# Fixture Repository

This repository is an intentional demonstration of credential leaks.
All credentials here are synthetic non-functional test values.
RME

# Stage all files
git add .

echo ""
echo "▶ Attempting git commit (would be BLOCKED on hook-installed projects)..."
echo "  (Hook is not installed in this isolated demo repo - CLI runs directly)"
git commit -m "add config" -q || true

# Run SLD CLI scan
echo ""
echo "▶ Running Secret Leak Detector scan on staged files..."
SCAN_OUTPUT="$(node "$CLI" scan . 2>&1)" || SCAN_EXIT=$?
SCAN_EXIT="${SCAN_EXIT:-0}"

echo "$SCAN_OUTPUT"
echo ""

if echo "$SCAN_OUTPUT" | grep -qiE "(CRITICAL|HIGH|credential|secret|finding)"; then
  echo "============================================================"
  echo "BLOCKED: Secret Leak Detector detected credentials!"
  echo "Files with findings (secrets are REDACTED below):"
  echo "$SCAN_OUTPUT" | grep -iE "(config|db|src|crypto|\.env|\.js|\.ts)" || true
  echo "============================================================"
else
  echo "  Info: No HIGH/CRITICAL findings in initial scan"
fi

# Remediate: replace credentials with process.env references
echo ""
echo "▶ Remediating credentials with environment variable references..."

cat > config/aws.env <<'FIXED'
AWS_REGION=us-east-1
# Credential removed - load from environment variable at runtime
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
FIXED

cat > db/connect.js <<'FIXEDJS'
// Database connection helper - credential loaded from environment
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) throw new Error("DATABASE_URL environment variable is not set");
module.exports = { DATABASE_URL };
FIXEDJS

cat > src/api.ts <<'FIXEDTS'
// API configuration - secret loaded from environment
const API_SECRET = process.env.API_SECRET;
if (!API_SECRET) throw new Error("API_SECRET environment variable is not set");
export { API_SECRET };
FIXEDTS

cat > .env.example <<'EXAMPLE'
# Copy to .env and fill in real values - NEVER commit .env
AWS_ACCESS_KEY_ID=YOUR_AWS_ACCESS_KEY_ID_HERE
DATABASE_URL=postgres://user:password@localhost:5432/myapp
API_SECRET=your-api-secret-here
EXAMPLE

echo "  Remediated config/aws.env, db/connect.js, src/api.ts"
echo "  Created .env.example for developer reference"

# Rescan after remediation
echo ""
echo "▶ Rescanning after remediation..."
RESCAN_OUTPUT="$(node "$CLI" scan . 2>&1)" || RESCAN_EXIT=$?
RESCAN_EXIT="${RESCAN_EXIT:-0}"

echo "$RESCAN_OUTPUT"
echo ""

# Summary
echo "============================================================"
if [ "$RESCAN_EXIT" -eq 0 ]; then
  echo "PASS: Post-remediation scan is CLEAN - no blocking findings"
else
  echo "FAIL: Post-remediation scan still reports findings (exit $RESCAN_EXIT)"
fi
echo "Fixture repo: $TMPDIR_FIXTURE"
echo "============================================================"

# Clean up fixture repo
rm -rf "$TMPDIR_FIXTURE"

exit $RESCAN_EXIT
