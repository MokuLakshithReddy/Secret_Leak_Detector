import { execFile } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { GitExposure, GitCommitInfo, SecretFinding } from '../types';
import { scanContent } from '../scanner/scanner';
import { decodeTextBuffer } from '../encoding/textDecoder';
import { calculateRiskAssessment } from '../risk/riskEngine';
import { CORE_RULES } from '../detectors/rules';

// execFile is used with safe argument arrays and pattern files so credentials
// are NEVER exposed in command-line arguments or process inspection tables (ps aux / /proc).
const execFileAsync = promisify(execFile);

export interface GitSearchResult {
  status: 'FOUND' | 'NOT_FOUND' | 'PARTIAL_HISTORY' | 'SEARCH_INCOMPLETE' | 'ERROR';
  commitShas: string[];
  error?: string;
  isPartialHistory?: boolean;
}

interface SecurePatternFile {
  filePath: string;
  cleanup: () => void;
}

/**
 * Creates an isolated, securely randomized pattern file inside a private directory
 * with exclusive creation ('wx') and strict 0o600 permissions.
 */
function createSecurePatternFile(pattern: string): SecurePatternFile {
  const secureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-pat-'));
  const randomHex = crypto.randomBytes(16).toString('hex');
  const filePath = path.join(secureDir, `${randomHex}.pat`);
  fs.writeFileSync(filePath, pattern + '\n', { encoding: 'utf8', mode: 0o600, flag: 'wx' });

  const cleanup = () => {
    try {
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
      }
    } catch {}
    try {
      if (fs.existsSync(secureDir)) {
        fs.rmSync(secureDir, { recursive: true, force: true });
      }
    } catch {}
  };

  return { filePath, cleanup };
}

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
      } catch (err: any) {
        // Missing hint file at HEAD is normal if file was deleted or renamed
      }
    }

    // 2. Search candidate files in HEAD using an isolated, cryptographically secure pattern file
    const patternLine = this.pickDistinctiveSearchLine(secret);
    if (!patternLine) return false;

    const pat = createSecurePatternFile(patternLine);
    try {
      const { stdout } = await execFileAsync(
        'git',
        ['grep', '-F', '-l', '-f', pat.filePath, 'HEAD'],
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
    } catch (err: any) {
      if (err && err.code === 1) {
        // Exit code 1 indicates normal no-match condition in git grep
        return false;
      }
      throw err;
    } finally {
      pat.cleanup();
    }
  }

  /**
   * Safely checks whether a secret exists in tracked, staged, or untracked working-tree files
   * without exposing credentials in command-line arguments. Inspects staged blobs directly via
   * `git show :<path>` rather than reading disk files that may have been cleaned after staging.
   */
  public async isSecretInWorkingTree(secret: string): Promise<boolean> {
    if (!secret || !secret.trim()) return false;
    const patternLine = this.pickDistinctiveSearchLine(secret);
    if (!patternLine) return false;
    const normSecret = secret.replace(/\r\n/g, '\n');

    const pat = createSecurePatternFile(patternLine);
    try {
      // 1. Check untracked working tree files
      try {
        const { stdout: untrackedOut } = await execFileAsync(
          'git',
          ['grep', '-F', '-l', '-f', pat.filePath, '--untracked'],
          { cwd: this.workspaceRoot, encoding: 'utf8' }
        );
        for (const file of untrackedOut.trim().split('\n').filter(Boolean)) {
          const absPath = path.resolve(this.workspaceRoot, file);
          if (fs.existsSync(absPath)) {
            try {
              const content = fs.readFileSync(absPath, 'utf8').replace(/\r\n/g, '\n');
              if (content.includes(normSecret)) return true;
            } catch {}
          }
        }
      } catch (err: any) {
        if (err && err.code !== 1) throw err;
      }

      // 2. Check cached (staged index) files by directly inspecting the staged blob via git show :<path>
      try {
        const { stdout: cachedOut } = await execFileAsync(
          'git',
          ['grep', '-F', '-l', '-f', pat.filePath, '--cached'],
          { cwd: this.workspaceRoot, encoding: 'utf8' }
        );
        for (const file of cachedOut.trim().split('\n').filter(Boolean)) {
          try {
            const { stdout: stagedContent } = await execFileAsync(
              'git',
              ['show', `:${file}`],
              { cwd: this.workspaceRoot, maxBuffer: 10 * 1024 * 1024, encoding: 'utf8' }
            );
            if (stagedContent.replace(/\r\n/g, '\n').includes(normSecret)) {
              return true;
            }
          } catch {}
        }
      } catch (err: any) {
        if (err && err.code !== 1) throw err;
      }

      // 3. Check tracked working-tree files
      try {
        const { stdout: trackedOut } = await execFileAsync(
          'git',
          ['grep', '-F', '-l', '-f', pat.filePath],
          { cwd: this.workspaceRoot, encoding: 'utf8' }
        );
        for (const file of trackedOut.trim().split('\n').filter(Boolean)) {
          const absPath = path.resolve(this.workspaceRoot, file);
          if (fs.existsSync(absPath)) {
            try {
              const content = fs.readFileSync(absPath, 'utf8').replace(/\r\n/g, '\n');
              if (content.includes(normSecret)) return true;
            } catch {}
          }
        }
      } catch (err: any) {
        if (err && err.code !== 1) throw err;
      }

      return false;
    } finally {
      pat.cleanup();
    }
  }

  /**
   * Finds all Git commit SHAs that touched or introduced a secret without passing the secret
   * in command-line arguments. Returns structured result distinguishing clean not-found from
   * operational search failures and partial history limits.
   */
  public async findCommitsContainingSecretResult(
    secret: string,
    maxCommits = 0
  ): Promise<GitSearchResult> {
    if (!secret || !secret.trim()) {
      return { status: 'NOT_FOUND', commitShas: [] };
    }
    const patternLine = this.pickDistinctiveSearchLine(secret);
    if (!patternLine) {
      return { status: 'NOT_FOUND', commitShas: [] };
    }

    let totalRevCount = 0;
    try {
      const { stdout: countOut } = await execFileAsync(
        'git',
        ['rev-list', '--all', '--count'],
        { cwd: this.workspaceRoot, maxBuffer: 10 * 1024 * 1024, encoding: 'utf8' }
      );
      totalRevCount = parseInt(countOut.trim(), 10) || 0;
    } catch {}

    const revArgs = ['rev-list', '--all'];
    let isPartialHistory = false;
    if (maxCommits > 0) {
      revArgs.push('-n', String(maxCommits));
      if (totalRevCount > maxCommits) {
        isPartialHistory = true;
      }
    }

    let revs: string[] = [];
    try {
      const { stdout: revOut } = await execFileAsync(
        'git',
        revArgs,
        { cwd: this.workspaceRoot, maxBuffer: 20 * 1024 * 1024, encoding: 'utf8' }
      );
      revs = revOut.trim().split('\n').filter(Boolean);
    } catch (err: any) {
      return {
        status: 'ERROR',
        commitShas: [],
        error: err?.message || String(err),
      };
    }

    if (revs.length === 0) {
      return { status: 'NOT_FOUND', commitShas: [] };
    }

    const pat = createSecurePatternFile(patternLine);
    let searchIncomplete = false;
    let operationalError: string | undefined;
    const chunkSize = 40;
    const matchingCommitsSet = new Set<string>();
    const normSecret = secret.replace(/\r\n/g, '\n');

    try {
      for (let i = 0; i < revs.length; i += chunkSize) {
        const chunk = revs.slice(i, i + chunkSize);
        try {
          const { stdout: grepOut } = await execFileAsync(
            'git',
            ['grep', '-F', '-l', '-f', pat.filePath, ...chunk],
            { cwd: this.workspaceRoot, maxBuffer: 15 * 1024 * 1024, encoding: 'utf8' }
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
        } catch (err: any) {
          if (err && err.code === 1) {
            // Exit code 1 indicates normal no-matches for this commit chunk
            continue;
          }
          searchIncomplete = true;
          operationalError = err?.message || String(err);
        }
      }
    } finally {
      pat.cleanup();
    }

    if (matchingCommitsSet.size > 0) {
      return {
        status: 'FOUND',
        commitShas: Array.from(matchingCommitsSet),
        isPartialHistory,
      };
    }

    if (searchIncomplete) {
      return {
        status: 'SEARCH_INCOMPLETE',
        commitShas: [],
        error: operationalError,
        isPartialHistory,
      };
    }

    if (isPartialHistory) {
      return {
        status: 'PARTIAL_HISTORY',
        commitShas: [],
        isPartialHistory: true,
      };
    }

    return {
      status: 'NOT_FOUND',
      commitShas: [],
    };
  }

  /**
   * Finds all Git commit SHAs that touched or introduced a secret without passing the secret
   * in command-line arguments. Default is unlimited search across complete history (maxCommits = 0).
   */
  public async findCommitsContainingSecret(secret: string, maxCommits = 0): Promise<string[]> {
    const res = await this.findCommitsContainingSecretResult(secret, maxCommits);
    return res.commitShas;
  }

  /**
   * Traces the provenance and historical exposure lifecycle of a specific secret.
   * Default searches full history without silently capping at 200 commits.
   */
  public async traceSecret(secret: string, maxCommits = 0): Promise<GitExposure> {
    const isGit = await this.isGitRepo();
    if (!isGit) {
      return {
        isPresentInHead: true,
        isPresentInHistory: false,
        exposureDurationDays: 0,
        branches: ['untracked'],
        isRemote: false,
        statusDescription: 'Local filesystem (not in Git version control)',
        searchStatus: 'ERROR',
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
          searchStatus: 'NOT_FOUND',
        };
      }

      const searchResult = await this.findCommitsContainingSecretResult(secret, maxCommits);

      if (searchResult.status === 'ERROR' || searchResult.status === 'SEARCH_INCOMPLETE') {
        return {
          isPresentInHead: false,
          isPresentInHistory: false,
          exposureDurationDays: 0,
          branches: [],
          isRemote: false,
          statusDescription: `Git history search was incomplete: ${searchResult.error || 'operational error'}`,
          searchStatus: searchResult.status,
          isPartialHistory: searchResult.isPartialHistory,
        };
      }

      const commitShas = searchResult.commitShas;
      if (commitShas.length === 0) {
        let inWorkingTree = false;
        try {
          inWorkingTree = await this.isSecretInWorkingTree(secret);
        } catch (err: any) {
          return {
            isPresentInHead: false,
            isPresentInHistory: false,
            exposureDurationDays: 0,
            branches: [],
            isRemote: false,
            statusDescription: `Failed to inspect working tree: ${err?.message || err}`,
            searchStatus: 'ERROR',
          };
        }

        if (inWorkingTree) {
          return {
            isPresentInHead: false,
            isPresentInHistory: false,
            isPresentInWorkingTree: true,
            isSecretInWorkingTree: true,
            exposureDurationDays: 0,
            branches: ['working-tree'],
            isRemote: false,
            statusDescription: 'Present in working tree only (uncommitted)',
            commitCount: 0,
            searchStatus: 'FOUND',
          };
        } else if (searchResult.status === 'PARTIAL_HISTORY') {
          return {
            isPresentInHead: false,
            isPresentInHistory: false,
            isPresentInWorkingTree: false,
            isSecretInWorkingTree: false,
            exposureDurationDays: 0,
            branches: [],
            isRemote: false,
            statusDescription: `Credential not found in scanned commits, but history search was limited to ${maxCommits} commit(s)`,
            commitCount: 0,
            isPartialHistory: true,
            searchStatus: 'PARTIAL_HISTORY',
          };
        } else {
          return {
            isPresentInHead: false,
            isPresentInHistory: false,
            isPresentInWorkingTree: false,
            isSecretInWorkingTree: false,
            exposureDurationDays: 0,
            branches: [],
            isRemote: false,
            statusDescription: 'Credential not found in Git history or working tree',
            commitCount: 0,
            searchStatus: 'NOT_FOUND',
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
          searchStatus: 'NOT_FOUND',
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

      let inWorkingTree = false;
      try {
        inWorkingTree = await this.isSecretInWorkingTree(secret);
      } catch {}

      return {
        introducedCommit,
        lastModifiedCommit,
        removedCommit,
        isPresentInHead,
        isPresentInHistory: true,
        isPresentInWorkingTree: inWorkingTree,
        isSecretInWorkingTree: inWorkingTree,
        exposureDurationDays,
        branches,
        isRemote,
        statusDescription,
        commitCount: parsedCommits.length,
        searchStatus: 'FOUND',
        isPartialHistory: searchResult.isPartialHistory,
      };
    } catch (err: any) {
      return {
        isPresentInHead: false,
        isPresentInHistory: false,
        exposureDurationDays: 0,
        branches: ['main'],
        isRemote: false,
        statusDescription: `Git history query failed: ${err?.message || String(err)}`,
        searchStatus: 'ERROR',
      };
    }
  }

  /**
   * Scans full Git commit log diffs to detect historical secrets that may have been deleted from HEAD.
   * Transparently inspects binary diffs via decodeTextBuffer and unconditionally verifies snapshots.
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

        // Extract added lines and files from diff
        const fileDiffs = block.split(/^diff --git /m);
        for (const diff of fileDiffs) {
          const fileMatch = diff.match(/^[ab]\/(.+?) [ab]\/(.+)/m) || diff.match(/^\+\+\+ b\/(.+)/m);
          const fileName = fileMatch ? fileMatch[1] : 'history-file';

          const diffFindings: SecretFinding[] = [];
          const isBinaryDiff = diff.includes('Binary files') || diff.includes('GIT binary patch');

          if (isBinaryDiff) {
            // Retrieve binary blob and decode via content decoder
            try {
              const { stdout: binBuf } = await execFileAsync(
                'git',
                ['show', `${sha}:${fileName}`],
                { cwd: this.workspaceRoot, maxBuffer: 15 * 1024 * 1024, encoding: 'buffer' }
              );
              const decoded = decodeTextBuffer(binBuf);
              if (decoded) {
                const binFindings = scanContent(decoded, fileName, { workspaceRoot: this.workspaceRoot });
                diffFindings.push(...binFindings);
              }
            } catch {}
          } else {
            const addedLines = diff
              .split('\n')
              .filter((l) => l.startsWith('+') && !l.startsWith('+++'))
              .map((l) => l.substring(1))
              .join('\n');

            if (addedLines.trim()) {
              const addedFindings = scanContent(addedLines, fileName, {
                workspaceRoot: this.workspaceRoot,
              });
              diffFindings.push(...addedFindings);
            }

            // Unconditionally inspect full snapshot for multiline findings intersecting added lines
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
