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
  blockCommits = true,
  disallowInline = true,
  failOnSkipped = false
): string {
  const threshold = (RISK_LEVELS as readonly string[]).includes(failOn) ? failOn : DEFAULT_FAIL_ON;
  const pinnedCli = cliPath ? cliPath.replace(/\\/g, '/') : '';
  const escapedCli = pinnedCli ? pinnedCli.replace(/'/g, `'\\''`) : '';
  const pinnedNode = nodePath ? nodePath.replace(/\\/g, '/') : '';
  const escapedNode = pinnedNode ? pinnedNode.replace(/'/g, `'\\''`) : '';

  const nodeResolution = escapedNode
    ? `# Resolved Node.js executable (prefer pinned runtime, fallback to system node on PATH)
if [ -n '${escapedNode}' ] && [ -x '${escapedNode}' ]; then
  NODE_CMD='${escapedNode}'
elif command -v node >/dev/null 2>&1; then
  NODE_CMD='node'
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
  NODE_MAJOR=$("$NODE_CMD" -e 'process.stdout.write(process.versions.node.split(".")[0])' 2>/dev/null || echo "0")
  if [ "$NODE_MAJOR" -gt 0 ] && [ "$NODE_MAJOR" -lt 18 ]; then
    echo ""
    echo "❌ COMMIT BLOCKED: Node.js runtime is too old (v$NODE_MAJOR detected, >=18 required)."
    exit 2
  fi
  ELECTRON_RUN_AS_NODE=1 "$NODE_CMD" "$PINNED_CLI" scan --staged --fail-on "$SLD_FAIL_ON" $DISALLOW_INLINE $IGNORE_SKIPPED $FAIL_ON_SKIPPED
  SCAN_STATUS=$?
elif command -v secret-leak-detector >/dev/null 2>&1; then
  secret-leak-detector scan --staged --fail-on "$SLD_FAIL_ON" $DISALLOW_INLINE $IGNORE_SKIPPED $FAIL_ON_SKIPPED
  SCAN_STATUS=$?
else
  HOOK_PATH="$(git rev-parse --git-path hooks/pre-commit 2>/dev/null || echo "$0")"
  HOOK_DIR="$(dirname "$HOOK_PATH")"
  LATEST_BACKUP="$HOOK_DIR/pre-commit.sld-backup.latest"
  # If pinned CLI was in an extension/editor folder that was uninstalled, auto-recover:
  case "$PINNED_CLI" in
    *extensions*|*globalStorage*|*.vscode*|*AppData*|*.config*)
      if [ "$SLD_STRICT" = "1" ] || [ "$SLD_FAIL_ON_SKIPPED_DEFAULT" = "1" ] || [ "$(git config --bool secret-leak-detector.strict 2>/dev/null)" = "true" ]; then
        echo ""
        echo "❌ COMMIT BLOCKED (strict mode): Secret Leak Detector scanner ($PINNED_CLI) is unavailable."
        exit 2
      fi
      echo "⚠️ [Secret Leak Detector] Extension was uninstalled (pinned scanner no longer exists)."
      if [ -f "$LATEST_BACKUP" ]; then
        BACKUP_FILE=$(cat "$LATEST_BACKUP" 2>/dev/null)
        if [ -f "$BACKUP_FILE" ]; then
          echo "   Restoring original backed-up pre-commit hook..."
          cp "$BACKUP_FILE" "$HOOK_PATH" 2>/dev/null && rm -f "$LATEST_BACKUP" "$BACKUP_FILE" 2>/dev/null
          if [ -x "$HOOK_PATH" ]; then
            exec "$HOOK_PATH" "$@"
          fi
          exit 0
        fi
      fi
      echo "   Removing stranded pre-commit hook..."
      rm -f "$HOOK_PATH" "$LATEST_BACKUP" 2>/dev/null
      exit 0
      ;;
  esac
  echo ""
  echo "❌ COMMIT BLOCKED (fail-closed): Secret Leak Detector scanner is unavailable."
  echo "   Pinned CLI ($PINNED_CLI) not found and no global CLI available."
  echo "   Recovery instructions:"
  echo "     - Remove stranded hook: rm \"$HOOK_PATH\""
  if [ -f "$LATEST_BACKUP" ]; then
    echo "     - Or restore backup: cp \"$LATEST_BACKUP\" \"$HOOK_PATH\""
  fi
  echo "     - Or install CLI globally: npm install -g secret-leak-detector"
  echo "     - Or re-pin hook: open the project in VS Code with Secret Leak Detector installed"
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
  NODE_MAJOR=$("$NODE_CMD" -e 'process.stdout.write(process.versions.node.split(".")[0])' 2>/dev/null || echo "0")
  if [ "$NODE_MAJOR" -gt 0 ] && [ "$NODE_MAJOR" -lt 18 ]; then
    echo ""
    echo "❌ COMMIT BLOCKED: Node.js runtime is too old (v$NODE_MAJOR detected, >=18 required)."
    exit 2
  fi
  ELECTRON_RUN_AS_NODE=1 "$NODE_CMD" "$SLD_CLI_PATH" scan --staged --fail-on "$SLD_FAIL_ON" $DISALLOW_INLINE $IGNORE_SKIPPED $FAIL_ON_SKIPPED
  SCAN_STATUS=$?
elif command -v secret-leak-detector >/dev/null 2>&1; then
  secret-leak-detector scan --staged --fail-on "$SLD_FAIL_ON" $DISALLOW_INLINE $IGNORE_SKIPPED $FAIL_ON_SKIPPED
  SCAN_STATUS=$?
else
  HOOK_PATH="$(git rev-parse --git-path hooks/pre-commit 2>/dev/null || echo "$0")"
  HOOK_DIR="$(dirname "$HOOK_PATH")"
  LATEST_BACKUP="$HOOK_DIR/pre-commit.sld-backup.latest"
  echo ""
  echo "❌ COMMIT BLOCKED (fail-closed): Secret Leak Detector scanner is unavailable."
  echo "   Pinned CLI not found and no global CLI available."
  echo "   Recovery instructions:"
  echo "     - Remove stranded hook: rm \"$HOOK_PATH\""
  if [ -f "$LATEST_BACKUP" ]; then
    echo "     - Or restore backup: cp \"$LATEST_BACKUP\" \"$HOOK_PATH\""
  fi
  echo "     - Or install CLI globally: npm install -g secret-leak-detector"
  echo "     - Or re-pin hook: open the project in VS Code with Secret Leak Detector installed"
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
SLD_DISALLOW_INLINE_DEFAULT="${disallowInline ? '1' : '0'}"
SLD_FAIL_ON_SKIPPED_DEFAULT="${failOnSkipped ? '1' : '0'}"

echo "🔐 [Secret Leak Detector] Inspecting staged changes for credentials..."

DISALLOW_INLINE=""
if [ "$SLD_ALLOW_INLINE_IGNORE" != "1" ] && [ "$(git config --bool secret-leak-detector.allow-inline-ignore 2>/dev/null)" != "true" ]; then
  if [ "$SLD_DISALLOW_INLINE_IGNORE" = "1" ] || [ "$SLD_DISALLOW_INLINE_DEFAULT" = "1" ] || [ "$(git config --bool secret-leak-detector.disallow-inline-ignore 2>/dev/null)" = "true" ]; then
    DISALLOW_INLINE="--no-inline-ignore"
  fi
fi

IGNORE_SKIPPED=""
if [ "$SLD_IGNORE_SKIPPED" = "1" ] || [ "$(git config --bool secret-leak-detector.ignore-skipped 2>/dev/null)" = "true" ]; then
  IGNORE_SKIPPED="--ignore-skipped"
fi

FAIL_ON_SKIPPED=""
if [ "$SLD_FAIL_ON_SKIPPED" = "1" ] || [ "$SLD_FAIL_ON_SKIPPED_DEFAULT" = "1" ] || [ "$SLD_STRICT" = "1" ] || [ "$(git config --bool secret-leak-detector.fail-on-skipped 2>/dev/null)" = "true" ] || [ "$(git config --bool secret-leak-detector.strict 2>/dev/null)" = "true" ]; then
  FAIL_ON_SKIPPED="--fail-on-skipped"
fi

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
  echo "   If a file could not be read or inspected, you can bypass with:"
  echo "     SLD_IGNORE_SKIPPED=1 git commit"
  echo "     or: git config secret-leak-detector.ignore-skipped true"
  echo "   To configure strict blocking behavior:"
  echo "     git config secret-leak-detector.strict true (block on skipped)"
  echo "     git config secret-leak-detector.strict false (warn on skipped)"
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
