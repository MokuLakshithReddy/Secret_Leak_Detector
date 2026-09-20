import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import { SecretFinding } from '../types';
import { scanContent } from '../engine/scanner';

const execAsync = promisify(exec);

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
   * Retrieves staged diff and scans all newly added lines for leaked secrets.
   */
  public async scanStagedChanges(): Promise<SecretFinding[]> {
    if (!(await this.isGitRepo())) {
      return [];
    }

    try {
      const { stdout } = await execAsync('git diff --cached --unified=0', { cwd: this.workspaceRoot });
      if (!stdout || stdout.trim().length === 0) {
        return [];
      }

      const allFindings: SecretFinding[] = [];
      const fileDiffs = stdout.split(/^diff --git /m);

      for (const diff of fileDiffs) {
        if (!diff.trim()) continue;

        const fileMatch = diff.match(/^[ab]\/(.+?) [ab]\/(.+)/m) || diff.match(/^\+\+\+ b\/(.+)/m);
        const fileName = fileMatch ? fileMatch[1] : 'staged-file';
        const fullPath = path.join(this.workspaceRoot, fileName);

        // Extract newly added lines marked with '+'
        const addedLines = diff
          .split('\n')
          .filter((line) => line.startsWith('+') && !line.startsWith('+++'))
          .map((line) => line.substring(1))
          .join('\n');

        if (addedLines.trim()) {
          const findings = scanContent(addedLines, fullPath, this.workspaceRoot);
          allFindings.push(...findings);
        }
      }

      return allFindings;
    } catch (err) {
      console.error('Failed to run git diff --cached:', err);
      return [];
    }
  }

  /**
   * Generates a terminal-formatted remediation message conforming to the project spec.
   */
  public formatTerminalBlockedMessage(findings: SecretFinding[]): string {
    const criticals = findings.filter((f) => f.risk === 'CRITICAL');
    const primary = criticals[0] || findings[0];

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
• Risk Level:  ${primary.risk}
• Confidence:  ${primary.confidence}%
• Entropy:     ${primary.entropy} bits/char

Signals Detected:
${primary.signals.map((s) => `  - ${s}`).join('\n')}

Recommended Remediation:
------------------------------------------------------------
${primary.remediation}

Example Fix:
  ${primary.exampleFix}

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
   * Installs a standalone pre-commit hook into .git/hooks/pre-commit
   */
  public async installPreCommitHook(): Promise<{ success: boolean; message: string }> {
    if (!(await this.isGitRepo())) {
      return { success: false, message: 'Workspace is not a Git repository.' };
    }

    const hooksDir = path.join(this.workspaceRoot, '.git', 'hooks');
    if (!fs.existsSync(hooksDir)) {
      try {
        fs.mkdirSync(hooksDir, { recursive: true });
      } catch (err) {
        return { success: false, message: `Could not create .git/hooks directory: ${err}` };
      }
    }

    const hookPath = path.join(hooksDir, 'pre-commit');
    const hookContent = `#!/bin/sh
# Secret Leak Detector Pre-Commit Hook
# Automatically blocks git commit if secrets are detected in staged changes

echo "🔐 [Secret Leak Detector] Scanning staged changes for credentials..."

DIFF=$(git diff --cached --unified=0)

# Check for AWS Access Keys
if echo "$DIFF" | grep -E '^[+]' | grep -E -q '(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}'; then
    echo "❌ COMMIT BLOCKED: Potential AWS Access Key found in staged changes!"
    echo "Please remove the credential or use an environment variable before committing."
    exit 1
fi

# Check for GitHub Tokens
if echo "$DIFF" | grep -E '^[+]' | grep -E -q '(gh[pousr]_[A-Za-z0-9_]{36}|github_pat_[A-Za-z0-9_]{82})'; then
    echo "❌ COMMIT BLOCKED: Potential GitHub Personal Access Token found in staged changes!"
    echo "Please remove the token before committing."
    exit 1
fi

# Check for Stripe Secret Keys
if echo "$DIFF" | grep -E '^[+]' | grep -E -q '(sk|rk)_(live|test)_[0-9a-zA-Z]{24}'; then
    echo "❌ COMMIT BLOCKED: Stripe Secret Key found in staged changes!"
    exit 1
fi

# Check for Private Keys
if echo "$DIFF" | grep -E '^[+]' | grep -E -q '-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----'; then
    echo "❌ COMMIT BLOCKED: Unencrypted Private Key found in staged changes!"
    exit 1
fi

echo "✅ [Secret Leak Detector] Staged changes clean. Proceeding with commit."
exit 0
`;

    try {
      fs.writeFileSync(hookPath, hookContent, { mode: 0o755 });
      return { success: true, message: `Pre-commit hook successfully installed to ${hookPath}` };
    } catch (err) {
      return { success: false, message: `Failed to write hook file: ${err}` };
    }
  }
}
