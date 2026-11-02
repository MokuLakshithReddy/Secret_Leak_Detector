import { execFile } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { GitExposure, GitCommitInfo, SecretFinding } from '../types';
import { scanContent } from '../scanner/scanner';
import { calculateRiskAssessment } from '../risk/riskEngine';
import { CORE_RULES } from '../detectors/rules';

// execFile is used with safe argument arrays and pattern files so credentials
// are NEVER exposed in command-line arguments or process inspection tables (ps aux / /proc).
const execFileAsync = promisify(execFile);

function parseAddedLineNumbersFromDiff(diffText: string): Set<number> {
  const addedLines = new Set<number>();
  const lines = diffText.split('\n');
  let currentNewLine = 0;
  let inHunk = false;

  for (const line of lines) {
    const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunkMatch) {
      currentNewLine = parseInt(hunkMatch[1], 10);
      inHunk = true;
      continue;
    }
    if (!inHunk) continue;

    if (line.startsWith('+') && !line.startsWith('+++')) {
      addedLines.add(currentNewLine);
      currentNewLine++;
    } else if (line.startsWith('-') && !line.startsWith('---')) {
      // old file line; does not advance currentNewLine
    } else if (line.startsWith(' ') || line === '') {
      currentNewLine++;
    }
  }

  return addedLines;
}

export class GitHistoryEngine {
  private workspaceRoot: string;

  constructor(workspaceRoot: string) {
    this.workspaceRoot = workspaceRoot;
  }

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
   * Selects the most specific and identifying line from a secret for secure pattern matching.
   * For multiline secrets (such as PEM blocks), ignores common delimiters (e.g. -----BEGIN...)
   * and chooses the longest high-entropy body line.
   */
  public pickDistinctiveSearchLine(secret: string): string {
    const lines = secret.split(/\r?\n/).map((l) => l.trim()).filter((l) => l.length > 0);
    if (lines.length <= 1) return secret.trim();
    const nonDelim = lines.filter((l) => !l.startsWith('-----') && !l.endsWith('-----'));
    if (nonDelim.length > 0) {
      return nonDelim.reduce((a, b) => (a.length >= b.length ? a : b));
    }
    return lines[0];
  }

  /**
   * Safely checks whether a secret exists anywhere in HEAD (by full content comparison,
   * without ever exposing the credential in process command-line arguments).
   */
  public async isSecretInHead(secret: string, hintFileName?: string): Promise<boolean> {
    if (!secret || !secret.trim()) return false;
    const normSecret = secret.replace(/\r\n/g, '\n');

    // 1. If a hint file path is known, check that file directly at HEAD
    if (hintFileName) {
      try {
        const { stdout: fileContent } = await execFileAsync(
          'git',
          ['show', `HEAD:${hintFileName}`],
          { cwd: this.workspaceRoot, maxBuffer: 10 * 1024 * 1024, encoding: 'utf8' }
        );
        if (fileContent.replace(/\r\n/g, '\n').includes(normSecret)) {
          return true;
        }
      } catch {}
    }

    // 2. Search candidate files in HEAD using an isolated pattern file
    const tmp = path.join(os.tmpdir(), `sld-hcheck-${Date.now()}-${Math.random().toString(36).slice(2)}.pat`);
    const patternLine = this.pickDistinctiveSearchLine(secret);
    if (!patternLine) return false;

    try {
      fs.writeFileSync(tmp, patternLine + '\n', { encoding: 'utf8', mode: 0o600 });
      const { stdout } = await execFileAsync(
        'git',
        ['grep', '-F', '-l', '-f', tmp, 'HEAD'],
        { cwd: this.workspaceRoot, encoding: 'utf8' }
      );
      const matches = stdout.trim().split('\n').filter(Boolean);
      for (const m of matches) {
        const candidateFile = m.replace(/^HEAD:/, '').trim();
        try {
          const { stdout: content } = await execFileAsync(
            'git',
            ['show', `HEAD:${candidateFile}`],
            { cwd: this.workspaceRoot, maxBuffer: 10 * 1024 * 1024, encoding: 'utf8' }
          );
          if (content.replace(/\r\n/g, '\n').includes(normSecret)) {
            return true;
          }
        } catch {}
      }
      return false;
    } catch {
      return false;
    } finally {
      try { fs.unlinkSync(tmp); } catch {}
    }
  }

  /**
   * Safely checks whether a secret exists in tracked, staged, or untracked working-tree files
   * without exposing credentials in command-line arguments.
   */
  public async isSecretInWorkingTree(secret: string): Promise<boolean> {
    if (!secret || !secret.trim()) return false;
    const tmp = path.join(os.tmpdir(), `sld-wtcheck-${Date.now()}-${Math.random().toString(36).slice(2)}.pat`);
    const patternLine = this.pickDistinctiveSearchLine(secret);
    if (!patternLine) return false;

    try {
      fs.writeFileSync(tmp, patternLine + '\n', { encoding: 'utf8', mode: 0o600 });
      const matchedFiles: string[] = [];

      try {
        const { stdout: untrackedOut } = await execFileAsync(
          'git',
          ['grep', '-F', '-l', '-f', tmp, '--untracked'],
          { cwd: this.workspaceRoot, encoding: 'utf8' }
        );
        matchedFiles.push(...untrackedOut.trim().split('\n').filter(Boolean));
      } catch {}

      try {
        const { stdout: cachedOut } = await execFileAsync(
          'git',
          ['grep', '-F', '-l', '-f', tmp, '--cached'],
          { cwd: this.workspaceRoot, encoding: 'utf8' }
        );
        matchedFiles.push(...cachedOut.trim().split('\n').filter(Boolean));
      } catch {}

      if (matchedFiles.length === 0) return false;

      const normSecret = secret.replace(/\r\n/g, '\n');
      const uniqueFiles = Array.from(new Set(matchedFiles));
      for (const relFile of uniqueFiles) {
        const absPath = path.resolve(this.workspaceRoot, relFile);
        if (fs.existsSync(absPath)) {
          try {
            const content = fs.readFileSync(absPath, 'utf8').replace(/\r\n/g, '\n');
            if (content.includes(normSecret)) {
              return true;
            }
          } catch {}
        }
      }
      return false;
    } catch {
      return false;
    } finally {
      try { fs.unlinkSync(tmp); } catch {}
    }
  }

  /**
   * Finds all Git commit SHAs that touched or introduced a secret without passing the secret
   * in command-line arguments. Uses temporary pattern files with git grep across rev-list commits.
   */
  public async findCommitsContainingSecret(secret: string, maxCommits = 200): Promise<string[]> {
    if (!secret || !secret.trim()) return [];
    const tmp = path.join(os.tmpdir(), `sld-trace-${Date.now()}-${Math.random().toString(36).slice(2)}.pat`);
    const patternLine = this.pickDistinctiveSearchLine(secret);
    if (!patternLine) return [];

    try {
      fs.writeFileSync(tmp, patternLine + '\n', { encoding: 'utf8', mode: 0o600 });
      const revArgs = ['rev-list', '--all'];
      if (maxCommits > 0) {
        revArgs.push('-n', String(maxCommits));
      }
      const { stdout: revOut } = await execFileAsync(
        'git',
        revArgs,
        { cwd: this.workspaceRoot, maxBuffer: 10 * 1024 * 1024, encoding: 'utf8' }
      );
      const revs = revOut.trim().split('\n').filter(Boolean);
      if (revs.length === 0) return [];

      const chunkSize = 40;
      const matchingCommitsSet = new Set<string>();
      const normSecret = secret.replace(/\r\n/g, '\n');

      for (let i = 0; i < revs.length; i += chunkSize) {
        const chunk = revs.slice(i, i + chunkSize);
        try {
          const { stdout: grepOut } = await execFileAsync(
            'git',
            ['grep', '-F', '-l', '-f', tmp, ...chunk],
            { cwd: this.workspaceRoot, maxBuffer: 10 * 1024 * 1024, encoding: 'utf8' }
          );
          const matches = grepOut.trim().split('\n').filter(Boolean);
          for (const m of matches) {
            const colonIdx = m.indexOf(':');
            if (colonIdx !== -1) {
              const cSha = m.substring(0, colonIdx);
              const cPath = m.substring(colonIdx + 1);
              if (secret.includes('\n')) {
                try {
                  const { stdout: content } = await execFileAsync(
                    'git',
                    ['show', `${cSha}:${cPath}`],
                    { cwd: this.workspaceRoot, maxBuffer: 10 * 1024 * 1024, encoding: 'utf8' }
                  );
                  if (content.replace(/\r\n/g, '\n').includes(normSecret)) {
                    matchingCommitsSet.add(cSha);
                  }
                } catch {}
              } else {
                matchingCommitsSet.add(cSha);
              }
            }
          }
        } catch {}
      }

      return Array.from(matchingCommitsSet);
    } catch {
      return [];
    } finally {
      try { fs.unlinkSync(tmp); } catch {}
    }
  }

  /**
   * Traces the provenance and historical exposure lifecycle of a specific secret.
   * Never exposes credentials in process arguments; verifies presence in working tree
   * before reporting uncommitted status.
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
      if (secret.length === 0) {
        return {
          isPresentInHead: false,
          isPresentInHistory: false,
          exposureDurationDays: 0,
          branches: ['working-tree'],
          isRemote: false,
          statusDescription: 'Empty string is not a traceable credential',
        };
      }

      const commitShas = await this.findCommitsContainingSecret(secret);
      if (commitShas.length === 0) {
        const inWorkingTree = await this.isSecretInWorkingTree(secret);
        if (inWorkingTree) {
          return {
            isPresentInHead: false,
            isPresentInHistory: false,
            exposureDurationDays: 0,
            branches: ['working-tree'],
            isRemote: false,
            statusDescription: 'Present in working tree only (uncommitted)',
            commitCount: 0,
          };
        } else {
          return {
            isPresentInHead: false,
            isPresentInHistory: false,
            exposureDurationDays: 0,
            branches: [],
            isRemote: false,
            statusDescription: 'Credential not found in Git history or working tree',
            commitCount: 0,
          };
        }
      }

      const parsedCommits: GitCommitInfo[] = [];
      for (const sha of commitShas) {
        try {
          const { stdout: commitInfo } = await execFileAsync(
            'git',
            ['log', '-1', '--format=%H|%an|%ad|%s', '--date=iso', sha],
            { cwd: this.workspaceRoot, encoding: 'utf8' }
          );
          const [cSha, author, date, ...rest] = commitInfo.trim().split('|');
          if (cSha) {
            parsedCommits.push({
              sha: cSha,
              author: author || 'Unknown',
              date: date || new Date().toISOString(),
              message: rest.join('|') || '',
            });
          }
        } catch {}
      }

      if (parsedCommits.length === 0) {
        return {
          isPresentInHead: false,
          isPresentInHistory: false,
          exposureDurationDays: 0,
          branches: [],
          isRemote: false,
          statusDescription: 'Credential not found in Git history or working tree',
          commitCount: 0,
        };
      }

      // Sort newest first
      parsedCommits.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());

      const introducedCommit = parsedCommits[parsedCommits.length - 1];
      const lastModifiedCommit = parsedCommits[0];

      const isPresentInHead = await this.isSecretInHead(secret);

      // Check branches containing the introduced commit
      let branches: string[] = [];
      let isRemote = false;
      try {
        const { stdout: branchOut } = await execFileAsync(
          'git',
          ['branch', '-a', '--contains', introducedCommit.sha],
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
        commitCount: parsedCommits.length,
      };
    } catch {
      return {
        isPresentInHead: false,
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
      // Get commit diffs across all branches, including merge commits
      const gitArgs = ['log', '--all', '-p', '-U1'];
      if (maxCommits > 0) {
        gitArgs.push('-n', String(maxCommits));
      }
      const { stdout } = await execFileAsync(
        'git',
        gitArgs,
        { cwd: this.workspaceRoot, maxBuffer: 20 * 1024 * 1024 }
      );

      const findings: SecretFinding[] = [];
      const commitBlocks = stdout.split(/^commit /m);
      const headCheckCache = new Map<string, boolean>();

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

          // Always check the full snapshot for multiline secrets (e.g. PEM keys whose body was
          // added or modified while the header was pre-existing) across relevant files,
          // rather than skipping when other findings (e.g. an API key) are detected in addedLines.
          if (
            diff.includes('-----BEGIN') ||
            diff.includes('KEY') ||
            diff.includes('CERTIFICATE') ||
            diff.includes('SECRET') ||
            diff.length > 250
          ) {
            try {
              const { stdout: fullSnapshot } = await execFileAsync(
                'git',
                ['show', `${sha}:${fileName}`],
                { cwd: this.workspaceRoot, maxBuffer: 10 * 1024 * 1024, encoding: 'utf8' }
              );
              const snapshotFindings = scanContent(fullSnapshot, fileName, { workspaceRoot: this.workspaceRoot });
              if (snapshotFindings.length > 0) {
                const addedLineNumbers = parseAddedLineNumbersFromDiff(diff);
                for (const sf of snapshotFindings) {
                  const secretLines = sf.rawSecret ? (sf.rawSecret.match(/\n/g) || []).length + 1 : 1;
                  let intersects = false;
                  for (let i = 0; i < secretLines; i++) {
                    if (addedLineNumbers.has(sf.line + i)) {
                      intersects = true;
                      break;
                    }
                  }
                  if (intersects) {
                    if (!diffFindings.some((df) => df.fingerprint === sf.fingerprint)) {
                      diffFindings.push(sf);
                    }
                  }
                }
              }
            } catch {}
          }

          for (const f of diffFindings) {
            let isPresentInHead = false;
            if (headCheckCache.has(f.rawSecret)) {
              isPresentInHead = headCheckCache.get(f.rawSecret)!;
            } else {
              isPresentInHead = await this.isSecretInHead(f.rawSecret, fileName);
              headCheckCache.set(f.rawSecret, isPresentInHead);
            }

            f.gitExposure = {
              introducedCommit: {
                sha,
                author,
                date,
                message: 'Committed to repository history',
              },
              isPresentInHead,
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
    } catch (err: any) {
      throw new Error(`Failed to scan Git history commits: ${err.message || String(err)}`);
    }
  }
}
