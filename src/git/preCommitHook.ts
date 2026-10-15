import { DEFAULT_FAIL_ON, RISK_LEVELS } from '../core/policy';
import { Risk } from '../core/types';

/** Marks a pre-commit hook as managed by Secret Leak Detector. */
export const SLD_HOOK_MARKER = '# [SLD_HOOK_MANAGED]';

/**
 * Build the pre-commit hook script.
 *
 * Security properties:
 *  - The blocking threshold comes from the single project policy
 *    (`src/core/policy.ts`), so the hook can never drift from the CLI/extension.
 *  - FAIL CLOSED: if no reliable scanner can be executed (no local CLI, no
 *    installed binary, no npx), the commit is BLOCKED. There is deliberately no
 *    "emergency regex" path — a weak regex is not equivalent to the full
 *    scanner and could allow a commit the real scanner would block.
 *  - No `eval` / shell string building from untrusted input.
 */
export function buildPreCommitHook(failOn: Risk = DEFAULT_FAIL_ON): string {
  const threshold = (RISK_LEVELS as readonly string[]).includes(failOn) ? failOn : DEFAULT_FAIL_ON;

  return `#!/bin/sh
${SLD_HOOK_MARKER}
# Secret Leak Detector Pre-Commit Hook
# Intercepts git commit and blocks unredacted credentials before they leave the machine.
#
# Severity policy (single source of truth: src/core/policy.ts):
#   Blocks findings at ${threshold} and above (LOW < MEDIUM < HIGH < CRITICAL).
#   Lower tiers are reported but do not block.
#
# Fail-closed: if the scanner cannot be executed, the commit is BLOCKED.
SLD_FAIL_ON="${threshold}"

echo "🔐 [Secret Leak Detector] Inspecting staged changes for credentials..."

# Determine the scanner without a shell interpreter or untrusted interpolation.
# Priority: local dist/cli.js > global binary > local npx.
if [ -f "./dist/cli.js" ]; then
  node ./dist/cli.js scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
elif command -v secret-leak-detector >/dev/null 2>&1; then
  secret-leak-detector scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
elif command -v npx >/dev/null 2>&1; then
  npx --no-install secret-leak-detector scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
else
  echo ""
  echo "❌ COMMIT BLOCKED (fail-closed): Secret Leak Detector scanner is unavailable."
  echo "   Staged changes could not be verified secret-free, so the commit was refused."
  echo "   Install Node.js (>=18) or the 'secret-leak-detector' CLI, then retry."
  exit 1
fi

if [ "$SCAN_STATUS" -ne 0 ]; then
  echo ""
  echo "❌ COMMIT BLOCKED: Secret Leak Detector detected credentials in staged files!"
  echo "Please rotate the secret or migrate it to an environment variable."
  exit 1
fi

# Chain an existing user hook if it was previously backed up.
# The path of the most recent backup is recorded by the installer.
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)"
LATEST_MARKER="$HOOKS_DIR/pre-commit.sld-backup.latest"
if [ -f "$LATEST_MARKER" ]; then
  BACKUP_HOOK=$(cat "$LATEST_MARKER")
  if [ -f "$BACKUP_HOOK" ]; then
    echo "🔗 Running chained pre-commit hook..."
    sh "$BACKUP_HOOK" "$@"
    exit $?
  fi
fi

exit 0
`;
}
