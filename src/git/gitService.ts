import { exec, execFile } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { SecretFinding } from '../core/types';
import { scanContent } from '../core/scanner/scanner';

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

export type GitScanStatus = 'CLEAN' | 'FINDINGS' | 'ERROR';

export interface StagedScanResult {
  status: GitScanStatus;
  findings: SecretFinding[];
  error?: string;
  filesScanned?: number;
}

export class GitService {
  private workspaceRoot: string;

  constructor(workspaceRoot: string) {
    this.workspaceRoot = workspaceRoot;
  }

  /**
   * Checks if the workspace root is a git repository.
   */
  public async isGitRepo(): Promise<boolean> {
    try {
      await execAsync('git rev-parse --is-inside-work-tree', { cwd: this.workspaceRoot });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Retrieves staged diff, extracts exact modified line coordinates,
   * scans the staged file version, and returns a fail-closed scan result.
   */
  public async scanStagedChanges(): Promise<StagedScanResult> {
    const isGit = await this.isGitRepo();
    if (!isGit) {
      // FAIL CLOSED: A non-Git workspace cannot be scanned for staged secrets.
      // Returning ERROR ensures callers treat this as an explicit scan failure,
      // not as an absence of secrets.
      return {
        status: 'ERROR',
        findings: [],
        error: 'Not a Git repository — staged scan cannot run.',
      };
    }

    try {
      // Get unified diff of staged changes with 0 lines of context to isolate added lines
      const { stdout: diffOutput } = await execAsync('git diff --cached --unified=0', {
        cwd: this.workspaceRoot,
        maxBuffer: 10 * 1024 * 1024,
      });

      if (!diffOutput || diffOutput.trim().length === 0) {
        return {
          status: 'CLEAN',
          findings: [],
          filesScanned: 0,
        };
      }

      const allFindings: SecretFinding[] = [];
      const fileDiffs = diffOutput.split(/^diff --git /m);
      let filesScanned = 0;

      for (const diff of fileDiffs) {
        if (!diff.trim()) continue;

        // Parse file path
        const fileMatch = diff.match(/^[ab]\/(.+?) [ab]\/(.+)/m) || diff.match(/^\+\+\+ b\/(.+)/m);
        if (!fileMatch) continue;

        const relativePath = fileMatch[2] || fileMatch[1];
        if (relativePath === '/dev/null') continue; // File deleted

        const normalizedRelPath = relativePath.replace(/\\/g, '/');
        const fullPath = path.join(this.workspaceRoot, relativePath);

        // Parse diff hunk headers to get exact added line numbers in the staged version
        // Format: @@ -oldStart[,oldCount] +newStart[,newCount] @@
        const addedLineNumbers = new Set<number>();
        const hunkRegex = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm;
        let hunkMatch: RegExpExecArray | null;

        while ((hunkMatch = hunkRegex.exec(diff)) !== null) {
          const newStart = parseInt(hunkMatch[1], 10);
          const newCount = hunkMatch[2] !== undefined ? parseInt(hunkMatch[2], 10) : 1;

          for (let i = 0; i < newCount; i++) {
            addedLineNumbers.add(newStart + i);
          }
        }

        if (addedLineNumbers.size === 0) continue;

        // Read the exact staged blob content from Git index.
        // SECURITY: Use execFile with an argument array instead of execAsync to prevent
        // shell injection via filenames containing metacharacters (spaces, $(), backticks, etc.).
        // SECURITY: Do NOT fall back to working-tree content. The staged index and the
        // working tree can diverge; substituting disk content would scan the wrong data
        // and could produce a false-clean result for a file that IS staged with a secret.
        let stagedContent: string;
        try {
          const { stdout: blobContent } = await execFileAsync(
            'git',
            ['show', `:${normalizedRelPath}`],
            { cwd: this.workspaceRoot, maxBuffer: 10 * 1024 * 1024 }
          );
          stagedContent = blobContent;
        } catch (blobErr: any) {
          // Blob read failed — treat as a scan error for this file.
          // Do NOT continue silently: push an error marker so callers know a file was skipped.
          allFindings.push({
            // Minimal synthetic finding that signals a scan failure without false-positive.
            type: 'SCAN_ERROR',
            provider: 'Internal',
            file: normalizedRelPath,
            fullPath,
            line: 0,
            column: 0,
            rawSecret: '',
            redactedSecret: '',
            confidence: 0,
            risk: 'CRITICAL' as any,
            signals: [`git show failed: ${blobErr.message || String(blobErr)}`],
            evidence: { score: 0, items: [] },
            riskAssessment: { score: 100, blastRadius: { level: 'UNKNOWN', summary: 'Staged blob unreadable — scan blocked' }, factors: [] },
            remediation: { steps: [], envVarName: '', replacementCode: '', envFileSnippet: '', envExampleSnippet: '', gitHistoryPurgeCommand: '', diffPreview: '' },
          } as any);
          continue;
        }

        filesScanned++;

        // Scan full staged content: preserves AST structure, lexical context, and line/col mapping
        const fileFindings = scanContent(stagedContent, fullPath, { workspaceRoot: this.workspaceRoot });

        // Filter findings to only those that fall on newly added/modified lines in this commit
        for (const finding of fileFindings) {
          if (addedLineNumbers.has(finding.line)) {
            allFindings.push(finding);
          }
        }
      }

      if (allFindings.length > 0) {
        return {
          status: 'FINDINGS',
          findings: allFindings,
          filesScanned,
        };
      }

      return {
        status: 'CLEAN',
        findings: [],
        filesScanned,
      };
    } catch (err: any) {
      console.error('Failed to run git diff --cached:', err);
      // FAIL CLOSED: Do not return an empty findings list on error.
      // An error must be explicitly reported as ERROR so security gates can block.
      return {
        status: 'ERROR',
        findings: [],
        error: `Git staged scan failed: ${err.message || String(err)}`,
      };
    }
  }

  public formatTerminalBlockedMessage(findings: SecretFinding[]): string {
    const criticals = findings.filter((f) => f.risk === 'CRITICAL');
    const primary = criticals[0] || findings[0];

    const remediationText =
      typeof primary.remediation === 'string'
        ? primary.remediation
        : primary.remediation?.steps?.join('\n') || 'Rotate and move to .env';

    const signalsList =
      primary.evidence?.items?.map((i) => `  - [${i.confidenceImpact >= 0 ? '+' : ''}${i.confidenceImpact}] ${i.description}`).join('\n') ||
      primary.signals?.map((s) => `  - ${s}`).join('\n') ||
      '  - Known pattern match';

    const blastRadiusText = primary.riskAssessment?.blastRadius
      ? `${primary.riskAssessment.blastRadius.level} (${primary.riskAssessment.blastRadius.summary})`
      : 'Local Working Tree';

    const banner = `
============================================================
❌ COMMIT BLOCKED BY SECRET LEAK DETECTOR
============================================================
🚨 Security Risk: Hard-coded secret detected before commit!

Finding Details:
------------------------------------------------------------
• Type:        ${primary.type}
• Provider:    ${primary.provider}
• File:        ${primary.file} (Line ${primary.line})
• Secret:      ${primary.redactedSecret}
• Risk Level:  ${primary.risk} (Score: ${primary.riskAssessment?.score ?? 95}/100)
• Confidence:  ${primary.confidence}%
• Blast Radius: ${blastRadiusText}

Evidence & Signals Detected:
${signalsList}

Recommended Remediation:
------------------------------------------------------------
${remediationText}

Example Fix:
  ${primary.exampleFix || primary.remediation?.replacementCode}

After fixing:
  1. Replace the secret in ${primary.file} with an environment variable.
  2. Add the sensitive value to your local .env (ensure .env is in .gitignore!).
  3. Run 'git add ${primary.file}'
  4. Run your 'git commit' again.
============================================================
`;
    return banner;
  }

  /**
   * Resolves the effective Git hooks directory for this repository.
   * Handles worktrees, bare repos, and core.hooksPath overrides correctly
   * by asking Git itself rather than assuming .git/hooks.
   */
  private async resolveHooksDir(): Promise<string> {
    try {
      const { stdout } = await execFileAsync(
        'git',
        ['rev-parse', '--git-path', 'hooks'],
        { cwd: this.workspaceRoot }
      );
      const resolved = stdout.trim();
      // git rev-parse --git-path can return a relative path
      return path.isAbsolute(resolved)
        ? resolved
        : path.resolve(this.workspaceRoot, resolved);
    } catch {
      // Fall back to the conventional location if git itself fails
      return path.join(this.workspaceRoot, '.git', 'hooks');
    }
  }

  /**
   * Installs pre-commit hook into the effective Git hooks directory.
   * If an existing hook exists, backs it up with a timestamped name and chains it.
   */
  public async installPreCommitHook(): Promise<{ success: boolean; message: string }> {
    if (!(await this.isGitRepo())) {
      return { success: false, message: 'Workspace is not a Git repository.' };
    }

    const hooksDir = await this.resolveHooksDir();
    if (!fs.existsSync(hooksDir)) {
      try {
        fs.mkdirSync(hooksDir, { recursive: true });
      } catch (err) {
        return { success: false, message: `Could not create hooks directory (${hooksDir}): ${err}` };
      }
    }

    const hookPath = path.join(hooksDir, 'pre-commit');
    // Use a timestamped backup name so repeated installs never silently overwrite a prior backup.
    const timestamp = Date.now();
    const backupPath = path.join(hooksDir, `pre-commit.sld-backup.${timestamp}`);
    // The latest backup symlink always points to the most recent one, used during uninstall.
    const latestBackupMarkerPath = path.join(hooksDir, 'pre-commit.sld-backup.latest');
    const marker = '# [SLD_HOOK_MANAGED]';

    // If existing hook exists and is not managed by SLD, back it up for chaining
    if (fs.existsSync(hookPath)) {
      try {
        const existingContent = fs.readFileSync(hookPath, 'utf8');
        if (!existingContent.includes(marker)) {
          fs.writeFileSync(backupPath, existingContent, { mode: 0o755 });
          // Record path of the most recent backup so uninstall can locate it
          fs.writeFileSync(latestBackupMarkerPath, backupPath, 'utf8');
        }
      } catch (err) {
        return { success: false, message: `Could not backup existing hook: ${err}` };
      }
    }

    const hookContent = `#!/bin/sh
${marker}
# Secret Leak Detector Pre-Commit Hook
# Intercepts git commit and blocks unredacted credentials before they leave the machine.
#
# Severity policy: blocks commits containing findings at HIGH or CRITICAL risk.
# LOW / MEDIUM findings are reported but do not block the commit by default.
# To change this threshold, edit --fail-on below (CRITICAL | HIGH | MEDIUM).
SLD_FAIL_ON="HIGH"

echo "🔐 [Secret Leak Detector] Inspecting staged changes for credentials..."

# Determine CLI binary without using eval (avoids shell injection via env var content).
# Priority: local dist/cli.js > global binary > npx.
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
  # Fail-safe regex inspection if Node/CLI is unavailable in this environment.
  # Check that git diff itself succeeds before examining its output.
  DIFF_OUTPUT=$(git diff --cached --unified=0 2>&1)
  GIT_DIFF_STATUS=$?
  if [ $GIT_DIFF_STATUS -ne 0 ]; then
    echo "❌ COMMIT BLOCKED: git diff --cached failed (exit $GIT_DIFF_STATUS). Cannot verify staged content is secret-free."
    exit 1
  fi
  if echo "$DIFF_OUTPUT" | grep -E '^[+]' | grep -E -q '(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}|(gh[pousr]_[A-Za-z0-9_]{36,82}|github_pat_[A-Za-z0-9_]{82})|(sk|rk)_(live|test)_[0-9a-zA-Z]{24}|-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----'; then
    echo "❌ COMMIT BLOCKED: Potential secret detected in staged changes!"
    exit 1
  fi
  SCAN_STATUS=0
fi

if [ "$SCAN_STATUS" -ne 0 ]; then
  echo ""
  echo "❌ COMMIT BLOCKED: Secret Leak Detector detected credentials in staged files!"
  echo "Please rotate the secret or migrate it to an environment variable."
  exit 1
fi

# Chain existing user hook if it was previously backed up.
# Read the path of the most recent backup from the marker file.
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

    try {
      fs.writeFileSync(hookPath, hookContent, { mode: 0o755 });
      return { success: true, message: `Pre-commit hook successfully installed to ${hookPath}` };
    } catch (err) {
      return { success: false, message: `Failed to write hook file: ${err}` };
    }
  }

  /**
   * Safely uninstalls pre-commit hook and restores any previous backup.
   * Resolves the same hooks directory used during install.
   */
  public async uninstallPreCommitHook(): Promise<{ success: boolean; message: string }> {
    const hooksDir = await this.resolveHooksDir();
    const hookPath = path.join(hooksDir, 'pre-commit');
    const latestBackupMarkerPath = path.join(hooksDir, 'pre-commit.sld-backup.latest');

    if (!fs.existsSync(hookPath)) {
      return { success: true, message: 'No pre-commit hook found to uninstall.' };
    }

    try {
      // Locate the most recent backup via the marker file
      if (fs.existsSync(latestBackupMarkerPath)) {
        const backupPath = fs.readFileSync(latestBackupMarkerPath, 'utf8').trim();
        if (backupPath && fs.existsSync(backupPath)) {
          fs.copyFileSync(backupPath, hookPath);
          fs.unlinkSync(backupPath);
          fs.unlinkSync(latestBackupMarkerPath);
          return { success: true, message: 'Uninstalled SLD hook and restored original pre-commit hook.' };
        }
      }
      // No backup — simply remove the SLD hook
      fs.unlinkSync(hookPath);
      return { success: true, message: 'Removed Secret Leak Detector pre-commit hook.' };
    } catch (err: any) {
      return { success: false, message: `Failed to uninstall hook: ${err.message}` };
    }
  }
}
