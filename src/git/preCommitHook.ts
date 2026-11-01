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
  cliPath?: string,
  nodePath?: string,
  blockCommits = true
): string {
  const threshold = (RISK_LEVELS as readonly string[]).includes(failOn) ? failOn : DEFAULT_FAIL_ON;
  const pinnedCli = cliPath ? cliPath.replace(/\\/g, '/') : '';
  const escapedCli = pinnedCli ? pinnedCli.replace(/'/g, `'\\''`) : '';
  const pinnedNode = nodePath ? nodePath.replace(/\\/g, '/') : '';
  const escapedNode = pinnedNode ? pinnedNode.replace(/'/g, `'\\''`) : '';

  const nodeResolution = escapedNode
    ? `# Resolved Node.js executable (prefer system node on PATH, fallback to pinned runtime)
if command -v node >/dev/null 2>&1; then
  NODE_CMD='node'
elif [ -x '${escapedNode}' ]; then
  NODE_CMD='${escapedNode}'
elif [ -x '/usr/local/bin/node' ]; then
  NODE_CMD='/usr/local/bin/node'
elif [ -x '/opt/homebrew/bin/node' ]; then
  NODE_CMD='/opt/homebrew/bin/node'
else
  NODE_CMD=''
fi`
    : `# Resolve Node.js from PATH
if command -v node >/dev/null 2>&1; then
  NODE_CMD='node'
elif [ -x '/usr/local/bin/node' ]; then
  NODE_CMD='/usr/local/bin/node'
elif [ -x '/opt/homebrew/bin/node' ]; then
  NODE_CMD='/opt/homebrew/bin/node'
else
  NODE_CMD=''
fi`;

  const scannerInvocation = pinnedCli
    ? `# Scanner pinned to bundled CLI path
PINNED_CLI='${escapedCli}'
if [ -n "$PINNED_CLI" ] && [ -f "$PINNED_CLI" ]; then
  if [ -z "$NODE_CMD" ]; then
    echo ""
    echo "❌ COMMIT BLOCKED: Node.js runtime not found on PATH (exit 127)."
    echo "   The pre-commit hook requires Node.js (>=18) to execute the scanner."
    echo "   Ensure 'node' is in your PATH or configure your Git client environment."
    exit 127
  fi
  ELECTRON_RUN_AS_NODE=1 "$NODE_CMD" "$PINNED_CLI" scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
elif command -v secret-leak-detector >/dev/null 2>&1; then
  secret-leak-detector scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
else
  echo ""
  echo "❌ COMMIT BLOCKED (fail-closed): Secret Leak Detector scanner is unavailable."
  echo "   Pinned CLI ($PINNED_CLI) not found and no global CLI available."
  echo "   Staged changes could not be verified secret-free, so the commit was refused."
  echo ""
  echo "   Recovery guidance (if Secret Leak Detector was uninstalled):"
  echo "     rm .git/hooks/pre-commit"
  echo "     (or restore your original hook from .git/hooks/pre-commit.sld-backup.*)"
  echo "   Or reinstall Secret Leak Detector in VS Code."
  exit 2
fi`
    : `# Scanner determined from environment or global binary (never ./dist/cli.js relative to repo)
if [ -n "$SLD_CLI_PATH" ] && [ -f "$SLD_CLI_PATH" ]; then
  if [ -z "$NODE_CMD" ]; then
    echo ""
    echo "❌ COMMIT BLOCKED: Node.js runtime not found on PATH (exit 127)."
    echo "   The pre-commit hook requires Node.js (>=18) to execute the scanner."
    exit 127
  fi
  ELECTRON_RUN_AS_NODE=1 "$NODE_CMD" "$SLD_CLI_PATH" scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
elif command -v secret-leak-detector >/dev/null 2>&1; then
  secret-leak-detector scan --staged --fail-on "$SLD_FAIL_ON"
  SCAN_STATUS=$?
else
  echo ""
  echo "❌ COMMIT BLOCKED (fail-closed): Secret Leak Detector scanner is unavailable."
  echo "   Staged changes could not be verified secret-free, so the commit was refused."
  echo "   Install Node.js (>=18) or the 'secret-leak-detector' CLI, then retry."
  exit 2
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
SLD_BLOCK_COMMITS="${blockCommits ? '1' : '0'}"

echo "🔐 [Secret Leak Detector] Inspecting staged changes for credentials..."

${nodeResolution}

${scannerInvocation}

if [ "$SCAN_STATUS" -eq 1 ]; then
  if [ "$SLD_BLOCK_COMMITS" = "0" ]; then
    echo ""
    echo "⚠️ WARNING: Secret Leak Detector detected credentials in staged files (commit blocking is disabled in settings)."
  else
    echo ""
    echo "❌ COMMIT BLOCKED: Secret Leak Detector detected credentials in staged files!"
    echo "Please rotate the secret or migrate it to an environment variable."
    exit 1
  fi
elif [ "$SCAN_STATUS" -eq 127 ]; then
  echo ""
  echo "❌ COMMIT BLOCKED: Node.js executable not found on PATH (exit 127)."
  echo "   If using a GUI Git client or nvm, ensure 'node' is available in the shell PATH."
  exit 2
elif [ "$SCAN_STATUS" -ne 0 ]; then
  echo ""
  echo "❌ COMMIT BLOCKED (fail-closed): Scanner exited with error ($SCAN_STATUS)."
  exit 2
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
