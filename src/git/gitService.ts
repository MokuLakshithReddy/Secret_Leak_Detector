import { execFile } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { SecretFinding } from '../core/types';
import { scanStagedChangesSync } from './stagedScanner';
import { buildPreCommitHook, SLD_HOOK_MARKER } from './preCommitHook';
import { DEFAULT_FAIL_ON } from '../core/policy';

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
      await execFileAsync('git', ['rev-parse', '--is-inside-work-tree'], {
        cwd: this.workspaceRoot,
      });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Retrieves staged diff, extracts exact modified line coordinates,
   * scans the staged file version, and returns a fail-closed scan result.
   *
   * Delegates to the shared staged-scan module (execFileSync argument arrays +
   * NUL-delimited output), so the CLI and the extension use one tested parser.
   * Handles scored statuses (R100/C80) and never falls back to working-tree content.
   */
  public async scanStagedChanges(): Promise<StagedScanResult> {
    return scanStagedChangesSync(this.workspaceRoot);
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
    const marker = SLD_HOOK_MARKER;

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

    // Hook body is built by the shared, fail-closed builder so the CLI and the
    // VS Code extension install byte-identical hooks using the one project policy.
    const hookContent = buildPreCommitHook(DEFAULT_FAIL_ON);

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
