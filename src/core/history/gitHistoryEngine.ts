import { exec } from 'child_process';
import { promisify } from 'util';
import { GitExposure, GitCommitInfo, SecretFinding } from '../types';
import { scanContent } from '../scanner/scanner';
import { calculateRiskAssessment } from '../risk/riskEngine';
import { CORE_RULES } from '../detectors/rules';

const execAsync = promisify(exec);

export class GitHistoryEngine {
  private workspaceRoot: string;

  constructor(workspaceRoot: string) {
    this.workspaceRoot = workspaceRoot;
  }

  public async isGitRepo(): Promise<boolean> {
    try {
      await execAsync('git rev-parse --is-inside-work-tree', { cwd: this.workspaceRoot });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Traces the provenance and historical exposure lifecycle of a specific secret.
   */
  public async traceSecret(secret: string): Promise<GitExposure> {
    const isGit = await this.isGitRepo();
    if (!isGit) {
      return {
        isPresentInHead: true,
        isPresentInHistory: false,
        exposureDurationDays: 0,
        branches: ['untracked'],
        isRemote: false,
        statusDescription: 'Local filesystem (not in Git version control)',
      };
    }

    try {
      // Find all commits that added or removed the secret string
      // git log -S <string> --all --format="%H|%an|%ad|%s" --date=iso
      const escapedSecret = secret.replace(/"/g, '\\"');
      const { stdout } = await execAsync(
        `git log -S "${escapedSecret}" --all --format="%H|%an|%ad|%s" --date=iso`,
        { cwd: this.workspaceRoot, maxBuffer: 10 * 1024 * 1024 }
      );

      const lines = stdout.trim().split('\n').filter((l) => l.trim().length > 0);
      if (lines.length === 0) {
        return {
          isPresentInHead: true,
          isPresentInHistory: false,
          exposureDurationDays: 0,
          branches: ['working-tree'],
          isRemote: false,
          statusDescription: 'Present in working tree only (uncommitted)',
        };
      }

      // Commits are returned newest first.
      const parsedCommits: GitCommitInfo[] = lines.map((line) => {
        const [sha, author, date, ...rest] = line.split('|');
        return {
          sha: sha || '',
          author: author || 'Unknown',
          date: date || new Date().toISOString(),
          message: rest.join('|') || '',
        };
      });

      const introducedCommit = parsedCommits[parsedCommits.length - 1];
      const lastModifiedCommit = parsedCommits[0];

      // Check if secret currently exists in HEAD
      let isPresentInHead = false;
      try {
        const { stdout: grepOut } = await execAsync(
          `git grep -F -q "${escapedSecret}" HEAD`,
          { cwd: this.workspaceRoot }
        );
        isPresentInHead = true;
      } catch {
        isPresentInHead = false;
      }

      // Check branches containing the introduced commit
      let branches: string[] = [];
      let isRemote = false;
      try {
        const { stdout: branchOut } = await execAsync(
          `git branch -a --contains ${introducedCommit.sha}`,
          { cwd: this.workspaceRoot }
        );
        branches = branchOut
          .split('\n')
          .map((b) => b.trim().replace(/^[\*\s]+/, ''))
          .filter((b) => b.length > 0);
        isRemote = branches.some((b) => b.startsWith('remotes/') || b.startsWith('origin/'));
      } catch {
        branches = ['main'];
      }

      // Compute exposure duration
      const introDate = new Date(introducedCommit.date).getTime();
      let removedCommit: GitCommitInfo | undefined;
      let endDate = Date.now();

      if (!isPresentInHead && parsedCommits.length > 1) {
        // If not in HEAD, latest commit in the list was likely the removal commit
        removedCommit = parsedCommits[0];
        endDate = new Date(removedCommit.date).getTime();
      }

      const exposureDurationDays = Math.max(
        0,
        Math.round((endDate - introDate) / (1000 * 60 * 60 * 24))
      );

      let statusDescription = '';
      if (!isPresentInHead) {
        statusDescription = `REMOVED FROM HEAD BUT STILL PRESENT IN GIT HISTORY! (Introduced ${exposureDurationDays} days ago by ${introducedCommit.author} in ${introducedCommit.sha.substring(0, 7)})`;
      } else {
        statusDescription = `ACTIVE IN HEAD & COMMITTED (Introduced ${exposureDurationDays} days ago by ${introducedCommit.author} in ${introducedCommit.sha.substring(0, 7)})`;
      }

      return {
        introducedCommit,
        lastModifiedCommit,
        removedCommit,
        isPresentInHead,
        isPresentInHistory: true,
        exposureDurationDays,
        branches,
        isRemote,
        statusDescription,
      };
    } catch {
      return {
        isPresentInHead: true,
        isPresentInHistory: false,
        exposureDurationDays: 0,
        branches: ['main'],
        isRemote: false,
        statusDescription: 'Failed to query git log',
      };
    }
  }

  /**
   * Scans full Git commit log diffs to detect historical secrets that may have been deleted from HEAD.
   */
  public async scanHistoryCommits(maxCommits = 100): Promise<SecretFinding[]> {
    const isGit = await this.isGitRepo();
    if (!isGit) return [];

    try {
      // Get recent commit diffs
      const { stdout } = await execAsync(
        `git log -n ${maxCommits} -p -U1 --no-merges`,
        { cwd: this.workspaceRoot, maxBuffer: 20 * 1024 * 1024 }
      );

      const findings: SecretFinding[] = [];
      const commitBlocks = stdout.split(/^commit /m);

      for (const block of commitBlocks) {
        if (!block.trim()) continue;

        const shaMatch = block.match(/^([0-9a-f]{40})/);
        const sha = shaMatch ? shaMatch[1] : '';

        const authorMatch = block.match(/^Author:\s*(.+)$/m);
        const author = authorMatch ? authorMatch[1] : 'Unknown';

        const dateMatch = block.match(/^Date:\s*(.+)$/m);
        const date = dateMatch ? dateMatch[1] : '';

        // Extract added lines from the diff
        const fileDiffs = block.split(/^diff --git /m);
        for (const diff of fileDiffs) {
          const fileMatch = diff.match(/^[ab]\/(.+?) [ab]\/(.+)/m) || diff.match(/^\+\+\+ b\/(.+)/m);
          const fileName = fileMatch ? fileMatch[1] : 'history-file';

          const addedLines = diff
            .split('\n')
            .filter((l) => l.startsWith('+') && !l.startsWith('+++'))
            .map((l) => l.substring(1))
            .join('\n');

          if (!addedLines.trim()) continue;

          const diffFindings = scanContent(addedLines, fileName, {
            workspaceRoot: this.workspaceRoot,
          });

          for (const f of diffFindings) {
            f.gitExposure = {
              introducedCommit: {
                sha,
                author,
                date,
                message: 'Committed to repository history',
              },
              isPresentInHead: false, // In history commit
              isPresentInHistory: true,
              exposureDurationDays: 1,
              branches: ['history'],
              isRemote: false,
              statusDescription: `Found in commit ${sha.substring(0, 7)} by ${author}`,
            };

            // Recalculate risk with git history exposure
            const matchingRule = CORE_RULES.find((r) => r.name === f.type) || CORE_RULES[0];
            f.riskAssessment = calculateRiskAssessment(
              matchingRule,
              f.confidence,
              f.evidence.fileContext,
              f.gitExposure
            );
            f.risk = f.riskAssessment.tier;

            findings.push(f);
          }
        }
      }

      return findings;
    } catch {
      return [];
    }
  }
}
