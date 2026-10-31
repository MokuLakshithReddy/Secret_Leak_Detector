import { DEFAULT_FAIL_ON, RISK_LEVELS } from '../core/policy';
import { Risk } from '../core/types';

/** Marks a pre-commit hook as managed by Secret Leak Detector. */
export const SLD_HOOK_MARKER = '# [SLD_HOOK_MANAGED]';

/**
 * Build the pre-commit hook script.
 *
 * Security properties:
 *  - Pins the scanner to the extension's or tool's bundled CLI (absolute path
 *    injected at install time) and never searches relative to the target repository
 *    (preventing malicious repositories from supplying a dummy ./dist/cli.js).
 *  - Distinguishes scanner runtime errors from detected credentials in exit codes.
 *  - Executes backed-up chained hooks directly preserving executable permissions,
 *    without breaking Python, Node, or Husky hooks.
 *  - FAIL CLOSED: if no reliable scanner can be executed, the commit is BLOCKED.
 *  - No `eval` / shell string building from untrusted input.
 */
export function buildPreCommitHook(
  failOn: Risk = DEFAULT_FAIL_ON,
  cliPath?: string
): string {
  const threshold = (RISK_LEVELS as readonly string[]).includes(failOn) ? failOn : DEFAULT_FAIL_ON;
  const pinnedCli = cliPath ? cliPath.replace(/\\/g, '/') : '';

  const scannerInvocation = pinnedCli
    ? `# Scanner pinned to bundled CLI path
if [ -f "${pinnedCli}" ]; then
  node "${pinnedCli}" scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
elif command -v secret-leak-detector >/dev/null 2>&1; then
  secret-leak-detector scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
else
  echo ""
  echo "❌ COMMIT BLOCKED (fail-closed): Secret Leak Detector scanner is unavailable."
  echo "   Pinned CLI (${pinnedCli}) not found and no global CLI available."
  echo "   Staged changes could not be verified secret-free, so the commit was refused."
  exit 1
fi`
    : `# Scanner determined from environment or global binary (never ./dist/cli.js relative to repo)
if [ -n "$SLD_CLI_PATH" ] && [ -f "$SLD_CLI_PATH" ]; then
  node "$SLD_CLI_PATH" scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
elif command -v secret-leak-detector >/dev/null 2>&1; then
  secret-leak-detector scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
else
  echo ""
  echo "❌ COMMIT BLOCKED (fail-closed): Secret Leak Detector scanner is unavailable."
  echo "   Staged changes could not be verified secret-free, so the commit was refused."
  echo "   Install Node.js (>=18) or the 'secret-leak-detector' CLI, then retry."
  exit 1
fi`;

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

${scannerInvocation}

if [ "$SCAN_STATUS" -eq 1 ]; then
  echo ""
  echo "❌ COMMIT BLOCKED: Secret Leak Detector detected credentials in staged files!"
  echo "Please rotate the secret or migrate it to an environment variable."
  exit 1
elif [ "$SCAN_STATUS" -ne 0 ]; then
  echo ""
  echo "❌ COMMIT BLOCKED (fail-closed): Scanner exited with error ($SCAN_STATUS)."
  exit 1
fi

# Chain an existing user hook if it was previously backed up.
# Executes directly when executable to support Python, Node, and Husky hooks.
HOOKS_DIR="$(cd "$(dirname "$0")" && pwd)"
LATEST_MARKER="$HOOKS_DIR/pre-commit.sld-backup.latest"
if [ -f "$LATEST_MARKER" ]; then
  BACKUP_HOOK=$(cat "$LATEST_MARKER")
  if [ -f "$BACKUP_HOOK" ]; then
    echo "🔗 Running chained pre-commit hook..."
    if [ -x "$BACKUP_HOOK" ]; then
      exec "$BACKUP_HOOK" "$@"
    else
      sh "$BACKUP_HOOK" "$@"
      exit $?
    fi
  fi
fi

exit 0
`;
}
