import { execFile, spawn } from 'child_process';
import * as readline from 'readline';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as crypto from 'crypto';
import { GitExposure, GitCommitInfo, SecretFinding, BranchRemovalInfo } from '../types';
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
  isShallow?: boolean;
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
    } catch { }
    try {
      if (fs.existsSync(secureDir)) {
        fs.rmSync(secureDir, { recursive: true, force: true });
      }
    } catch { }
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

/**
 * Unquotes a Git path formatted according to Git's C-style string quoting rules
 * (octal escapes \ooo for byte values, escaped quotes, tabs, newlines, etc.).
 */
export function unquoteGitPath(rawPath: string): string {
  rawPath = rawPath.trim();
  if (!rawPath.startsWith('"') || !rawPath.endsWith('"')) {
    return rawPath;
  }
  // Strip outer quotes
  const inner = rawPath.slice(1, -1);
  const bytes: number[] = [];
  let i = 0;
  while (i < inner.length) {
    if (inner[i] === '\\' && i + 1 < inner.length) {
      i++;
      const nextChar = inner[i];
      if (nextChar === '\\') {
        bytes.push(0x5c);
        i++;
      } else if (nextChar === '"') {
        bytes.push(0x22);
        i++;
      } else if (nextChar === 'n') {
        bytes.push(0x0a);
        i++;
      } else if (nextChar === 't') {
        bytes.push(0x09);
        i++;
      } else if (nextChar === 'r') {
        bytes.push(0x0d);
        i++;
      } else if (nextChar === 'a') {
        bytes.push(0x07);
        i++;
      } else if (nextChar === 'b') {
        bytes.push(0x08);
        i++;
      } else if (nextChar === 'f') {
        bytes.push(0x0c);
        i++;
      } else if (nextChar === 'v') {
        bytes.push(0x0b);
        i++;
      } else if (nextChar >= '0' && nextChar <= '7') {
        // Octal escape \ooo (1-3 octal digits)
        let octalStr = nextChar;
        i++;
        while (octalStr.length < 3 && i < inner.length && inner[i] >= '0' && inner[i] <= '7') {
          octalStr += inner[i];
          i++;
        }
        bytes.push(parseInt(octalStr, 8));
      } else {
        // Unknown escape, keep verbatim ASCII code
        bytes.push(nextChar.charCodeAt(0));
        i++;
      }
    } else {
      // Standard UTF-8 character
      const codePoint = inner.codePointAt(i)!;
      const charBuf = Buffer.from(String.fromCodePoint(codePoint), 'utf8');
      for (const b of charBuf) {
        bytes.push(b);
      }
      i += String.fromCodePoint(codePoint).length;
    }
  }
  return Buffer.from(bytes).toString('utf8');
}

/**
 * Extracts and unquotes pathA and pathB from the first line of a git diff header
 * (e.g. `diff --git "a/path 1.bin" "b/path 2.bin"` or `diff --git a/foo.ts b/foo.ts`).
 */
export function parseDiffHeaderPaths(diffLine: string): { pathA: string; pathB: string } | null {
  let line = diffLine.trim();
  if (line.startsWith('diff --git ')) {
    line = line.substring(11).trim();
  }

  let pathA = '';
  let rest = '';

  if (line.startsWith('"')) {
    let i = 1;
    let inEscape = false;
    while (i < line.length) {
      if (inEscape) {
        inEscape = false;
        i++;
      } else if (line[i] === '\\') {
        inEscape = true;
        i++;
      } else if (line[i] === '"') {
        break;
      } else {
        i++;
      }
    }
    if (i < line.length) {
      pathA = unquoteGitPath(line.slice(0, i + 1));
      rest = line.slice(i + 1).trim();
    } else {
      return null;
    }
  } else {
    // Unquoted pathA: search for delimiter before pathB: ' b/' or ' "b/'
    const match = line.match(/^(\S+)\s+(.+)$/);
    if (!match) return null;
    pathA = match[1];
    rest = match[2].trim();
  }

  let pathB = '';
  if (rest.startsWith('"')) {
    pathB = unquoteGitPath(rest);
  } else {
    pathB = rest;
  }

  // Strip leading a/ and b/
  if (pathA.startsWith('a/')) pathA = pathA.slice(2);
  if (pathB.startsWith('b/')) pathB = pathB.slice(2);

  return { pathA, pathB };
}

export class GitHistoryEngine {
  protected workspaceRoot: string;

  constructor(workspaceRoot: string) {
    this.workspaceRoot = workspaceRoot;
  }

  protected async execGit(args: string[], options: any = {}): Promise<{ stdout: any; stderr: any }> {
    return execFileAsync('git', args, { cwd: this.workspaceRoot, ...options });
  }

  public async isGitRepo(): Promise<boolean> {
    try {
      await this.execGit(['rev-parse', '--is-inside-work-tree']);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Checks whether the current repository is a shallow clone (e.g. cloned with --depth).
   * In a shallow clone, earlier commit history is omitted, making a negative search result
   * incomplete rather than definitively clean.
   */
  public async isShallowRepo(): Promise<boolean> {
    try {
      const { stdout } = await this.execGit(['rev-parse', '--is-shallow-repository']);
      return stdout.trim().toLowerCase() === 'true';
    } catch {
      try {
        const { stdout: shallowPath } = await this.execGit(['rev-parse', '--git-path', 'shallow']);
        const trimmed = shallowPath.trim();
        if (trimmed) {
          const resolvedPath = path.isAbsolute(trimmed) ? trimmed : path.resolve(this.workspaceRoot, trimmed);
          return fs.existsSync(resolvedPath);
        }
      } catch {
        // Fallback to legacy path check if git rev-parse is completely unavailable
      }
      return fs.existsSync(path.join(this.workspaceRoot, '.git', 'shallow'));
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
        const { stdout: fileContent } = await this.execGit(
          ['show', `HEAD:${hintFileName}`],
          { maxBuffer: 10 * 1024 * 1024, encoding: 'utf8' }
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
      const { stdout } = await this.execGit(
        ['grep', '-F', '-l', '-f', pat.filePath, 'HEAD'],
        { encoding: 'utf8' }
      );
      const matches = stdout.trim().split('\n').filter(Boolean);
      for (const m of matches) {
        const candidateFile = m.replace(/^HEAD:/, '').trim();
        try {
          const { stdout: content } = await this.execGit(
            ['show', `HEAD:${candidateFile}`],
            { maxBuffer: 10 * 1024 * 1024, encoding: 'utf8' }
          );
          if (content.replace(/\r\n/g, '\n').includes(normSecret)) {
            return true;
          }
        } catch (err: any) {
          throw new Error(`Failed to inspect candidate blob 'HEAD:${candidateFile}': ${err?.message || err}`);
        }
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
        const { stdout: untrackedOut } = await this.execGit(
          ['grep', '-F', '-l', '-f', pat.filePath, '--untracked'],
          { encoding: 'utf8' }
        );
        for (const file of untrackedOut.trim().split('\n').filter(Boolean)) {
          const absPath = path.resolve(this.workspaceRoot, file);
          if (fs.existsSync(absPath)) {
            try {
              const content = fs.readFileSync(absPath, 'utf8').replace(/\r\n/g, '\n');
              if (content.includes(normSecret)) return true;
            } catch (readErr: any) {
              throw new Error(`Failed to read untracked candidate file '${file}': ${readErr?.message || readErr}`);
            }
          } else {
            throw new Error(`Candidate untracked file disappeared during inspection: '${file}'`);
          }
        }
      } catch (err: any) {
        if (err && err.code !== 1) throw err;
      }

      // 2. Check cached (staged index) files by directly inspecting the staged blob via git show :<path>
      try {
        const { stdout: cachedOut } = await this.execGit(
          ['grep', '-F', '-l', '-f', pat.filePath, '--cached'],
          { encoding: 'utf8' }
        );
        for (const file of cachedOut.trim().split('\n').filter(Boolean)) {
          try {
            const { stdout: stagedContent } = await this.execGit(
              ['show', `:${file}`],
              { maxBuffer: 10 * 1024 * 1024, encoding: 'utf8' }
            );
            if (stagedContent.replace(/\r\n/g, '\n').includes(normSecret)) {
              return true;
            }
          } catch (err: any) {
            throw new Error(`Failed to inspect staged blob for '${file}': ${err?.message || err}`);
          }
        }
      } catch (err: any) {
        if (err && err.code !== 1) throw err;
      }

      // 3. Check tracked working-tree files
      try {
        const { stdout: trackedOut } = await this.execGit(
          ['grep', '-F', '-l', '-f', pat.filePath],
          { encoding: 'utf8' }
        );
        for (const file of trackedOut.trim().split('\n').filter(Boolean)) {
          const absPath = path.resolve(this.workspaceRoot, file);
          if (fs.existsSync(absPath)) {
            try {
              const content = fs.readFileSync(absPath, 'utf8').replace(/\r\n/g, '\n');
              if (content.includes(normSecret)) return true;
            } catch (readErr: any) {
              throw new Error(`Failed to read tracked candidate file '${file}': ${readErr?.message || readErr}`);
            }
          } else {
            throw new Error(`Candidate tracked file disappeared during inspection: '${file}'`);
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

    let isShallow = false;
    try {
      isShallow = await this.isShallowRepo();
    } catch {
      isShallow = false;
    }

    let totalRevCount = 0;
    let countOperationFailed = false;
    let countError: string | undefined;
    if (maxCommits > 0) {
      try {
        const { stdout: countOut } = await this.execGit(
          ['rev-list', '--all', '--count'],
          { maxBuffer: 10 * 1024 * 1024, encoding: 'utf8' }
        );
        totalRevCount = parseInt(countOut.trim(), 10) || 0;
      } catch (err: any) {
        countOperationFailed = true;
        countError = err?.message || String(err);
      }
    }

    const revArgs = ['rev-list', '--all'];
    let isPartialHistory = isShallow;
    let searchIncomplete = false;
    let operationalError: string | undefined;

    if (maxCommits > 0) {
      revArgs.push('-n', String(maxCommits));
      if (countOperationFailed) {
        // Count operation failed: cannot determine full history depth, so limited search is marked partial & incomplete
        isPartialHistory = true;
        searchIncomplete = true;
        operationalError = `Failed to verify repository commit count: ${countError}`;
      } else if (totalRevCount > maxCommits) {
        isPartialHistory = true;
      }
    }

    let revs: string[] = [];
    try {
      const { stdout: revOut } = await this.execGit(
        revArgs,
        { maxBuffer: 20 * 1024 * 1024, encoding: 'utf8' }
      );
      revs = revOut.trim().split('\n').filter(Boolean);
    } catch (err: any) {
      return {
        status: 'ERROR',
        commitShas: [],
        error: err?.message || String(err),
        isShallow,
      };
    }

    if (revs.length === 0) {
      if (isShallow) {
        return { status: 'PARTIAL_HISTORY', commitShas: [], isPartialHistory: true, isShallow: true };
      }
      return { status: 'NOT_FOUND', commitShas: [], isShallow: false };
    }

    const pat = createSecurePatternFile(patternLine);
    const chunkSize = 40;
    const matchingCommitsSet = new Set<string>();
    const normSecret = secret.replace(/\r\n/g, '\n');

    try {
      for (let i = 0; i < revs.length; i += chunkSize) {
        const chunk = revs.slice(i, i + chunkSize);
        try {
          const { stdout: grepOut } = await this.execGit(
            ['grep', '-F', '-l', '-f', pat.filePath, ...chunk],
            { maxBuffer: 15 * 1024 * 1024, encoding: 'utf8' }
          );
          const matches = grepOut.trim().split('\n').filter(Boolean);
          for (const m of matches) {
            const colonIdx = m.indexOf(':');
            if (colonIdx !== -1) {
              const cSha = m.substring(0, colonIdx);
              const cPath = m.substring(colonIdx + 1);
              if (secret.includes('\n')) {
                try {
                  const { stdout: content } = await this.execGit(
                    ['show', `${cSha}:${cPath}`],
                    { maxBuffer: 10 * 1024 * 1024, encoding: 'utf8' }
                  );
                  if (content.replace(/\r\n/g, '\n').includes(normSecret)) {
                    matchingCommitsSet.add(cSha);
                  }
                } catch (showErr: any) {
                  searchIncomplete = true;
                  operationalError = `Failed to inspect historical blob '${cSha}:${cPath}': ${showErr?.message || showErr}`;
                }
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

    if (searchIncomplete) {
      return {
        status: 'SEARCH_INCOMPLETE',
        commitShas: Array.from(matchingCommitsSet),
        error: operationalError,
        isPartialHistory,
        isShallow,
      };
    }

    if (matchingCommitsSet.size > 0) {
      return {
        status: 'FOUND',
        commitShas: Array.from(matchingCommitsSet),
        isPartialHistory,
        isShallow,
      };
    }

    if (isPartialHistory) {
      return {
        status: 'PARTIAL_HISTORY',
        commitShas: [],
        isPartialHistory: true,
        isShallow,
      };
    }

    return {
      status: 'NOT_FOUND',
      commitShas: [],
      isShallow,
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
   * Establishes whether ancestorSha is an ancestor of targetRef (defaults to 'HEAD').
   * Uses git merge-base --is-ancestor:
   * - Exit code 0: true (confirmed ancestor).
   * - Exit code 1: false (confirmed not an ancestor).
   * - Other exit code / operational error: 'UNKNOWN' (lineage check failed).
   */
  public async isAncestor(ancestorSha: string, targetRef = 'HEAD'): Promise<boolean | 'UNKNOWN'> {
    if (!ancestorSha || !targetRef) return 'UNKNOWN';
    try {
      await this.execGit(['merge-base', '--is-ancestor', ancestorSha, targetRef]);
      return true;
    } catch (err: any) {
      const exitCode = err?.code ?? err?.status;
      if (
        exitCode === 1 ||
        exitCode === '1' ||
        (typeof err?.message === 'string' && /\bexit code 1\b/i.test(err.message))
      ) {
        return false;
      }
      return 'UNKNOWN';
    }
  }

  /**
   * Establishes whether a genuine removal commit exists between lastSeenSha and targetRef (default HEAD)
   * using secure pattern-file matching without passing credentials or pattern fragments
   * in command-line arguments. Before searching commits, establishes that lastSeenSha is actually
   * an ancestor of targetRef so unrelated branch commits are never falsely attributed as removal commits.
   */
  public async findRemovalCommit(secret: string, lastSeenSha: string, targetRef = 'HEAD'): Promise<GitCommitInfo | undefined> {
    const patternLine = this.pickDistinctiveSearchLine(secret);
    if (!patternLine) return undefined;

    // Establish ancestry: lastSeenSha MUST be an ancestor of targetRef.
    // If ancestry check fails (UNKNOWN), throw an operational error rather than assuming absence.
    const isAnc = await this.isAncestor(lastSeenSha, targetRef);
    if (isAnc === 'UNKNOWN') {
      throw new Error(`Git operational error establishing ancestry between ${lastSeenSha.substring(0, 7)} and ${targetRef}`);
    }
    if (!isAnc) return undefined;

    // List commits chronologically forward on targetRef's first-parent ancestry path starting from lastSeenSha.
    // Using --ancestry-path and --first-parent ensures that:
    // 1. Commits that diverged before introduction are excluded.
    // 2. Commits on side branches that removed the secret before merging into targetRef are excluded,
    //    ensuring that removal from targetRef is attributed to the merge commit (or subsequent commit)
    //    where the secret actually disappeared from targetRef's effective history.
    const { stdout: revsOut } = await this.execGit([
      'log',
      '--reverse',
      '--ancestry-path',
      '--first-parent',
      '--format=%H|%an|%ad|%cn|%cd|%s',
      '--date=iso',
      `${lastSeenSha}..${targetRef}`,
    ]);
    const lines = revsOut.trim().split('\n').filter(Boolean);
    if (lines.length === 0) return undefined;

    const commitList: Array<{ sha: string; author: string; date: string; committer?: string; committerDate?: string; message: string }> = [];
    for (const line of lines) {
      const parts = line.split('|');
      if (parts.length >= 4) {
        commitList.push({
          sha: parts[0],
          author: parts[1] || 'Unknown',
          date: parts[2] || new Date().toISOString(),
          committer: parts[3] || parts[1] || 'Unknown',
          committerDate: parts[4] || parts[2] || new Date().toISOString(),
          message: parts.slice(5).join('|') || parts.slice(3).join('|') || '',
        });
      }
    }
    if (commitList.length === 0) return undefined;

    const pat = createSecurePatternFile(patternLine);
    const normSecret = secret.replace(/\r\n/g, '\n');

    try {
      // Chunk commits to check presence efficiently with git grep using the pattern file
      const chunkSize = 40;
      const commitsContainingSecret = new Set<string>();

      for (let i = 0; i < commitList.length; i += chunkSize) {
        const chunk = commitList.slice(i, i + chunkSize);
        const chunkShas = chunk.map((c) => c.sha);
        try {
          const { stdout: grepOut } = await this.execGit(
            ['grep', '-F', '-l', '-f', pat.filePath, ...chunkShas],
            { maxBuffer: 15 * 1024 * 1024, encoding: 'utf8' }
          );
          const matches = grepOut.trim().split('\n').filter(Boolean);
          for (const m of matches) {
            const colonIdx = m.indexOf(':');
            if (colonIdx !== -1) {
              const cSha = m.substring(0, colonIdx);
              const cPath = m.substring(colonIdx + 1);
              if (secret.includes('\n')) {
                try {
                  const { stdout: content } = await this.execGit(
                    ['show', `${cSha}:${cPath}`],
                    { maxBuffer: 10 * 1024 * 1024, encoding: 'utf8' }
                  );
                  if (content.replace(/\r\n/g, '\n').includes(normSecret)) {
                    commitsContainingSecret.add(cSha);
                  }
                } catch (showErr: any) {
                  throw new Error(`Failed to inspect blob '${cSha}:${cPath}': ${showErr?.message || showErr}`);
                }
              } else {
                commitsContainingSecret.add(cSha);
              }
            }
          }
        } catch (err: any) {
          if (err && err.code === 1) {
            // Exit code 1 indicates normal no-match condition in git grep
            continue;
          }
          // Do NOT treat unexpected Git errors as absence! Propagate as operational error.
          throw new Error(`Git error during removal commit grep: ${err?.message || err}`);
        }
      }

      // lastSeenSha is known to contain the secret.
      // Walk forward chronologically through commits between lastSeenSha and targetRef.
      let previousHadSecret = true;
      for (const commit of commitList) {
        const containsSecret = commitsContainingSecret.has(commit.sha);
        if (previousHadSecret && !containsSecret) {
          return {
            sha: commit.sha,
            author: commit.author,
            date: commit.date,
            committer: commit.committer,
            committerDate: commit.committerDate,
            message: commit.message,
          };
        }
        previousHadSecret = containsSecret;
      }
      return undefined;
    } finally {
      pat.cleanup();
    }
  }

  /**
   * Discovers branch containment for a set of commit SHAs efficiently in O(branches)
   * instead of launching a separate Git process for every commit.
   *
   * Scalability & Architectural Guarantees:
   * 1. Memory bound: Uses streaming child process stdout (spawn + readline) so commit SHAs
   *    are processed incrementally with O(1) buffer overhead, eliminating Node.js buffer
   *    overflows (RangeError ERR_CHILD_PROCESS_STDIO_MAXBUFFER) even on repositories with
   *    millions of commits or commit outputs exceeding 30 MB.
   * 2. Early termination: For each branch, once all requested target commit SHAs have been
   *    encountered in the revision stream, the child process is terminated immediately via
   *    child.kill() and readline.close(), preventing unnecessary traversal of older history.
   * 3. Bounded concurrency: Traverses branches across a pool of concurrent workers (default 8)
   *    to minimize execution time across repositories with dozens or hundreds of branches
   *    without unbounded process explosion.
   */
  public async getBranchesForCommits(commitShas: string[], targetRoot?: string): Promise<{
    commitBranchesMap: Map<string, string[]>;
    allBranches: string[];
    failed: boolean;
    error?: string;
  }> {
    const commitBranchesMap = new Map<string, string[]>();
    for (const sha of commitShas) {
      commitBranchesMap.set(sha, []);
    }

    if (commitShas.length === 0) {
      return { commitBranchesMap, allBranches: [], failed: false };
    }

    const targetShas = new Set(commitShas);
    const allBranchesSet = new Set<string>();
    let failed = false;
    let error: string | undefined;
    const cwd = targetRoot || this.workspaceRoot;

    let branchNames: string[] = [];
    try {
      const { stdout: bOut } = await this.execGit(['branch', '-a'], {
        maxBuffer: 10 * 1024 * 1024,
        encoding: 'utf8',
        cwd,
      });
      branchNames = Array.from(new Set(
        String(bOut)
          .split('\n')
          .map((b: string) => b.trim())
          .filter((b: string) => b.length > 0 && !b.includes(' -> ') && !b.includes('(HEAD detached'))
          .map((b: string) => b.replace(/^\*\s+/, ''))
      ));
    } catch (err: any) {
      return {
        commitBranchesMap,
        allBranches: [],
        failed: true,
        error: err?.message || String(err),
      };
    }

    const scanBranch = async (branch: string): Promise<void> => {
      return new Promise<void>((resolve) => {
        let settled = false;
        let earlyTerminated = false;
        const branchFoundShas = new Set<string>();

        const child = spawn('git', ['rev-list', branch], {
          cwd,
          stdio: ['ignore', 'pipe', 'pipe'],
        });

        let stderrBuf = '';
        if (child.stderr) {
          child.stderr.on('data', (chunk) => {
            if (stderrBuf.length < 1024) {
              stderrBuf += chunk.toString();
            }
          });
          child.stderr.on('error', () => {});
        }
        if (child.stdout) {
          child.stdout.on('error', () => {});
        }

        const rl = readline.createInterface({
          input: child.stdout,
          crlfDelay: Infinity,
        });

        const finish = (isErr = false, errMsg?: string) => {
          if (settled) return;
          settled = true;
          try {
            rl.close();
          } catch {}
          if (!child.killed) {
            try {
              child.kill();
            } catch {}
          }
          if (isErr && !earlyTerminated) {
            failed = true;
            if (errMsg) {
              error = errMsg;
            }
          }
          resolve();
        };

        rl.on('line', (line: string) => {
          const rev = line.trim();
          if (rev && targetShas.has(rev)) {
            const list = commitBranchesMap.get(rev);
            if (list && !list.includes(branch)) {
              list.push(branch);
            }
            allBranchesSet.add(branch);
            branchFoundShas.add(rev);

            // Early termination: stop walking this branch once all target commits were found
            if (branchFoundShas.size >= targetShas.size) {
              earlyTerminated = true;
              finish();
            }
          }
        });

        rl.on('close', () => {
          finish();
        });

        child.on('error', (err: any) => {
          finish(true, err?.message || String(err));
        });

        child.on('close', (code: number | null) => {
          if (code !== 0 && code !== null && !earlyTerminated) {
            finish(true, stderrBuf.trim() || `git rev-list exited with code ${code}`);
          } else {
            finish();
          }
        });
      });
    };

    // Bounded concurrency pool (up to 8 concurrent workers)
    const concurrency = Math.min(8, Math.max(1, branchNames.length));
    const queue = [...branchNames];
    const workers = Array.from({ length: concurrency }, async () => {
      while (queue.length > 0) {
        const nextBranch = queue.shift();
        if (nextBranch) {
          await scanBranch(nextBranch);
        }
      }
    });

    await Promise.all(workers);

    return {
      commitBranchesMap,
      allBranches: Array.from(allBranchesSet),
      failed,
      error,
    };
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
      const isShallow = !!searchResult.isShallow;

      if (searchResult.status === 'ERROR' || searchResult.status === 'SEARCH_INCOMPLETE') {
        const hasMatches = searchResult.commitShas.length > 0;
        return {
          isPresentInHead: 'UNKNOWN',
          isPresentInHistory: hasMatches ? true : 'UNKNOWN',
          isPresentInWorkingTree: 'UNKNOWN',
          isSecretInWorkingTree: 'UNKNOWN',
          exposureDurationDays: 0,
          branches: [],
          isRemote: 'UNKNOWN',
          statusDescription: `Git history search was incomplete: ${searchResult.error || 'operational error'}${hasMatches ? ` (${searchResult.commitShas.length} matching commit(s) discovered before failure)` : ''
            }`,
          commitCount: searchResult.commitShas.length,
          searchStatus: searchResult.status,
          isPartialHistory: searchResult.isPartialHistory,
          isShallow,
        };
      }

      const commitShas = searchResult.commitShas;
      if (commitShas.length === 0) {
        let inWorkingTree: boolean | 'UNKNOWN' = false;
        try {
          inWorkingTree = await this.isSecretInWorkingTree(secret);
        } catch (err: any) {
          return {
            isPresentInHead: 'UNKNOWN',
            isPresentInHistory: 'UNKNOWN',
            isPresentInWorkingTree: 'UNKNOWN',
            isSecretInWorkingTree: 'UNKNOWN',
            exposureDurationDays: 0,
            branches: [],
            isRemote: 'UNKNOWN',
            statusDescription: `Failed to inspect working tree: ${err?.message || err}`,
            searchStatus: 'ERROR',
            isShallow,
          };
        }

        if (inWorkingTree) {
          return {
            isPresentInHead: false,
            isPresentInHistory: searchResult.isPartialHistory ? 'UNKNOWN' : false,
            isPresentInWorkingTree: true,
            isSecretInWorkingTree: true,
            exposureDurationDays: 0,
            branches: ['working-tree'],
            isRemote: searchResult.isPartialHistory ? 'UNKNOWN' : false,
            statusDescription: searchResult.isPartialHistory
              ? (isShallow
                ? 'Present in working tree (uncommitted); shallow Git clone detected with truncated history'
                : `Present in working tree (uncommitted); search limited to ${maxCommits} commit(s)`)
              : 'Present in working tree only (uncommitted)',
            commitCount: 0,
            searchStatus: searchResult.isPartialHistory ? 'PARTIAL_HISTORY' : 'FOUND',
            isPartialHistory: searchResult.isPartialHistory,
            isShallow,
          };
        } else if (searchResult.status === 'PARTIAL_HISTORY') {
          return {
            isPresentInHead: 'UNKNOWN',
            isPresentInHistory: 'UNKNOWN',
            isPresentInWorkingTree: false,
            isSecretInWorkingTree: false,
            exposureDurationDays: 0,
            branches: [],
            isRemote: 'UNKNOWN',
            statusDescription: isShallow
              ? 'Shallow Git clone detected: repository history is truncated, cannot confirm historical clean state'
              : `Credential not found in scanned commits, but history search was limited to ${maxCommits} commit(s)`,
            commitCount: 0,
            isPartialHistory: true,
            isShallow,
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
            isShallow,
          };
        }
      }

      const parsedCommits: GitCommitInfo[] = [];
      let metadataError: string | undefined;
      let failedMetadataCount = 0;

      for (const sha of commitShas) {
        try {
          const { stdout: commitInfo } = await this.execGit(
            ['log', '-1', '--format=%H|%an|%ad|%cn|%cd|%s', '--date=iso', sha],
            { encoding: 'utf8' }
          );
          const [cSha, author, authorDate, committer, committerDate, ...rest] = commitInfo.trim().split('|');
          if (cSha) {
            parsedCommits.push({
              sha: cSha,
              author: author || 'Unknown',
              date: committerDate || authorDate || new Date().toISOString(),
              committerDate: committerDate || authorDate,
              committer: committer || author,
              message: rest.join('|') || '',
            });
          } else {
            failedMetadataCount++;
          }
        } catch (mErr: any) {
          failedMetadataCount++;
          metadataError = mErr?.message || String(mErr);
        }
      }

      if (parsedCommits.length === 0) {
        if (commitShas.length > 0) {
          return {
            isPresentInHead: 'UNKNOWN',
            isPresentInHistory: true,
            isPresentInWorkingTree: 'UNKNOWN',
            isSecretInWorkingTree: 'UNKNOWN',
            exposureDurationDays: 0,
            branches: [],
            isRemote: 'UNKNOWN',
            statusDescription: `Secret detected in ${commitShas.length} commit(s), but commit metadata retrieval failed: ${metadataError || 'git log error'}`,
            commitCount: commitShas.length,
            searchStatus: 'SEARCH_INCOMPLETE',
            isPartialHistory: searchResult.isPartialHistory,
          };
        }
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

      const ancestryCache = new Map<string, boolean | 'UNKNOWN'>();
      const checkAncestry = async (aSha: string, bSha: string): Promise<boolean | 'UNKNOWN'> => {
        const key = `${aSha}->${bSha}`;
        if (ancestryCache.has(key)) return ancestryCache.get(key)!;
        const res = await this.isAncestor(aSha, bSha);
        ancestryCache.set(key, res);
        return res;
      };

      // Sort topologically newest first (descendants before ancestors) using Git's native topological ordering.
      // This prevents quadratic Git-process calls (avoiding pairwise isAncestor checks across thousands of commits)
      // and neutralizes manipulated/backdated author timestamps (e.g. GIT_AUTHOR_DATE).
      const shaSet = new Set(parsedCommits.map((c) => c.sha));
      try {
        const { stdout: topoOut } = await this.execGit([
          'rev-list',
          '--all',
          '--topo-order',
        ], { maxBuffer: 30 * 1024 * 1024, encoding: 'utf8' });
        const topoAllShas = topoOut.trim().split('\n').filter(Boolean);
        const topoIndexMap = new Map<string, number>();
        topoAllShas.forEach((sha: string, idx: number) => {
          if (shaSet.has(sha)) {
            topoIndexMap.set(sha, idx);
          }
        });

        parsedCommits.sort((a, b) => {
          const idxA = topoIndexMap.has(a.sha) ? topoIndexMap.get(a.sha)! : Number.MAX_SAFE_INTEGER;
          const idxB = topoIndexMap.has(b.sha) ? topoIndexMap.get(b.sha)! : Number.MAX_SAFE_INTEGER;
          if (idxA !== idxB) {
            return idxA - idxB;
          }
          // Fallback to committer date if both are not in topoIndexMap
          const timeA = new Date(a.committerDate || a.date).getTime();
          const timeB = new Date(b.committerDate || b.date).getTime();
          return timeB - timeA;
        });
      } catch {
        // Fallback to committer timestamp if git rev-list fails
        parsedCommits.sort((a, b) => {
          const timeA = new Date(a.committerDate || a.date).getTime();
          const timeB = new Date(b.committerDate || b.date).getTime();
          return timeB - timeA;
        });
      }

      let isPresentInHead: boolean | 'UNKNOWN' = 'UNKNOWN';
      let headCheckFailed = false;
      try {
        isPresentInHead = await this.isSecretInHead(secret);
      } catch (headErr: any) {
        isPresentInHead = 'UNKNOWN';
        headCheckFailed = true;
      }

      // Discover containing branches efficiently in O(branches) instead of launching a separate Git process per commit
      const branchDiscovery = await this.getBranchesForCommits(parsedCommits.map((c) => c.sha));
      const commitBranchesMap = branchDiscovery.commitBranchesMap;
      const branches = branchDiscovery.allBranches;
      const branchQueryFailed = branchDiscovery.failed;

      let isRemote: boolean | 'UNKNOWN' = 'UNKNOWN';
      const hasRemoteConfirmed = branches.some((b) => b.startsWith('remotes/') || b.startsWith('origin/'));
      if (hasRemoteConfirmed) {
        isRemote = true;
      } else if (branchQueryFailed) {
        // If a branch query failed and no remote ref was positively discovered, remote status remains UNKNOWN
        isRemote = 'UNKNOWN';
      } else {
        isRemote = false;
      }

      // Track exposure and removal independently per branch
      const branchRemovals: Record<string, BranchRemovalInfo> = {};
      const containingBranches = branches.filter((b) => !b.includes('(HEAD detached'));

      for (const branch of containingBranches) {
        const commitsOnBranch = parsedCommits.filter((c) =>
          commitBranchesMap.get(c.sha)?.includes(branch)
        );

        if (commitsOnBranch.length === 0) {
          branchRemovals[branch] = {
            isAncestor: false,
            isRemoved: false,
          };
          continue;
        }

        const branchIntroCommit = commitsOnBranch[commitsOnBranch.length - 1];
        const branchLastSeenCommit = commitsOnBranch[0];

        try {
          const isAnc = await checkAncestry(branchLastSeenCommit.sha, branch);
          if (isAnc === true) {
            const bRemoval = await this.findRemovalCommit(secret, branchLastSeenCommit.sha, branch);
            const branchIntroTime = new Date(branchIntroCommit.committerDate || branchIntroCommit.date).getTime();
            const branchEndTime = bRemoval
              ? new Date(bRemoval.committerDate || bRemoval.date).getTime()
              : Date.now();
            const branchDuration = Math.max(0, Math.round((branchEndTime - branchIntroTime) / (1000 * 60 * 60 * 24)));
            branchRemovals[branch] = {
              isAncestor: true,
              isRemoved: !!bRemoval,
              removalCommit: bRemoval,
              introducedCommit: branchIntroCommit,
              exposureDurationDays: branchDuration,
            };
          } else if (isAnc === false) {
            branchRemovals[branch] = {
              isAncestor: false,
              isRemoved: false,
              introducedCommit: branchIntroCommit,
            };
          } else {
            branchRemovals[branch] = {
              isAncestor: 'UNKNOWN',
              isRemoved: 'UNKNOWN',
              introducedCommit: branchIntroCommit,
            };
          }
        } catch {
          branchRemovals[branch] = {
            isAncestor: 'UNKNOWN',
            isRemoved: 'UNKNOWN',
            introducedCommit: branchIntroCommit,
          };
        }
      }

      // Check whether matching commits exist in HEAD's lineage in O(1) queries instead of O(N)
      const commitsInHeadLineage: GitCommitInfo[] = [];
      let isAncestorOfHead: boolean | 'UNKNOWN' = 'UNKNOWN';
      try {
        const { stdout: headRevOut } = await this.execGit(
          ['rev-list', 'HEAD'],
          { maxBuffer: 30 * 1024 * 1024, encoding: 'utf8' }
        );
        const headAncestorShas = new Set(headRevOut.trim().split('\n').filter(Boolean));
        for (const c of parsedCommits) {
          if (headAncestorShas.has(c.sha)) {
            commitsInHeadLineage.push(c);
          }
        }
        isAncestorOfHead = commitsInHeadLineage.length > 0;
      } catch {
        // Fallback to per-commit ancestry query if bulk rev-list fails
        for (const c of parsedCommits) {
          const isAnc = await checkAncestry(c.sha, 'HEAD');
          if (isAnc === true) {
            commitsInHeadLineage.push(c);
          }
        }
        if (commitsInHeadLineage.length > 0) {
          isAncestorOfHead = true;
        } else {
          let anyUnknown = false;
          for (const c of parsedCommits) {
            const anc = await checkAncestry(c.sha, 'HEAD');
            if (anc === 'UNKNOWN') {
              anyUnknown = true;
              break;
            }
          }
          isAncestorOfHead = anyUnknown ? 'UNKNOWN' : false;
        }
      }

      const introducedCommit = parsedCommits[parsedCommits.length - 1];
      const lastModifiedCommit = parsedCommits[0];
      const lastSeenCommit = parsedCommits[0];

      let removedCommit: GitCommitInfo | undefined;
      let removalCheckFailed = false;
      let removalError: string | undefined;
      let endDate = Date.now();

      if (isPresentInHead === false) {
        if (isAncestorOfHead === true && commitsInHeadLineage.length > 0) {
          try {
            removedCommit = await this.findRemovalCommit(secret, commitsInHeadLineage[0].sha, 'HEAD');
          } catch (remErr: any) {
            removalCheckFailed = true;
            removalError = remErr?.message || String(remErr);
          }
        } else if (isAncestorOfHead === 'UNKNOWN') {
          removalCheckFailed = true;
          removalError = 'Failed to verify lineage between commit history and HEAD';
          removedCommit = undefined;
        } else {
          // If not an ancestor of HEAD (false), HEAD never passed through this commit lineage.
          // Therefore HEAD did NOT remove the credential; removal cannot be attributed to HEAD.
          removedCommit = undefined;
        }

        if (removedCommit) {
          endDate = new Date(removedCommit.committerDate || removedCommit.date).getTime();
        } else {
          endDate = new Date(lastSeenCommit.committerDate || lastSeenCommit.date).getTime();
        }
      }

      const introDate = new Date(introducedCommit.committerDate || introducedCommit.date).getTime();
      const globalExposureDuration = Math.max(
        0,
        Math.round((endDate - introDate) / (1000 * 60 * 60 * 24))
      );

      // Use the maximum confirmed branch duration for the aggregate risk calculation
      const confirmedBranchDurations = Object.values(branchRemovals)
        .map((b) => b.exposureDurationDays)
        .filter((d): d is number => typeof d === 'number');

      const exposureDurationDays = confirmedBranchDurations.length > 0
        ? Math.max(globalExposureDuration, ...confirmedBranchDurations)
        : globalExposureDuration;

      let statusDescription = '';
      if (headCheckFailed) {
        statusDescription = `INCOMPLETE HEAD VERIFICATION: Present in commit history (${parsedCommits.length} commit(s)), but HEAD verification failed`;
      } else if (isShallow) {
        if (isPresentInHead === true) {
          statusDescription = `ACTIVE IN HEAD & COMMITTED (Earliest visible commit: ${introducedCommit.sha.substring(0, 7)} by ${introducedCommit.author}; original introduction date and total exposure duration unverified due to shallow clone)`;
        } else if (isAncestorOfHead === false) {
          statusDescription = `UNMERGED BRANCH EXPOSURE: Credential present in history on branch(es) [${containingBranches.join(', ') || 'unmerged'}], but never merged into HEAD (Earliest visible commit: ${introducedCommit.sha.substring(0, 7)}; original introduction unverified due to shallow clone)`;
        } else {
          statusDescription = `REMOVED FROM HEAD BUT STILL PRESENT IN GIT HISTORY! (Earliest visible commit: ${introducedCommit.sha.substring(0, 7)} by ${introducedCommit.author}; original introduction unverified due to shallow clone)`;
        }
      } else if (isPresentInHead === true) {
        statusDescription = `ACTIVE IN HEAD & COMMITTED (Introduced ${exposureDurationDays} days ago by ${introducedCommit.author} in ${introducedCommit.sha.substring(0, 7)})`;
      } else if (isAncestorOfHead === false) {
        statusDescription = `UNMERGED BRANCH EXPOSURE: Credential present in history on branch(es) [${containingBranches.join(', ') || 'unmerged'}], but never merged into HEAD (Introduced ${exposureDurationDays} days ago by ${introducedCommit.author} in ${introducedCommit.sha.substring(0, 7)})`;
      } else if (isAncestorOfHead === 'UNKNOWN') {
        statusDescription = `INCOMPLETE LINEAGE VERIFICATION: Present in commit history (${exposureDurationDays} days exposure, ${parsedCommits.length} commit(s)), but Git ancestry check to HEAD failed`;
      } else {
        statusDescription = `REMOVED FROM HEAD BUT STILL PRESENT IN GIT HISTORY! (Introduced ${exposureDurationDays} days ago by ${introducedCommit.author} in ${introducedCommit.sha.substring(0, 7)})`;
      }

      if (failedMetadataCount > 0) {
        statusDescription += ` [INCOMPLETE METADATA: ${failedMetadataCount} of ${commitShas.length} metadata request(s) failed: ${metadataError}]`;
      }
      if (removalCheckFailed) {
        statusDescription += ` [INCOMPLETE REMOVAL VERIFICATION: ${removalError}]`;
      }

      let inWorkingTree: boolean | 'UNKNOWN' = false;
      let wtCheckFailed = false;
      try {
        inWorkingTree = await this.isSecretInWorkingTree(secret);
      } catch (wtErr: any) {
        inWorkingTree = 'UNKNOWN';
        wtCheckFailed = true;
      }

      if (wtCheckFailed) {
        statusDescription += ` [Working-tree verification incomplete]`;
      }
      if (branchQueryFailed) {
        statusDescription += ` [INCOMPLETE BRANCH INSPECTION: branch reachability query failed for one or more commits]`;
      }
      if (searchResult.isShallow) {
        statusDescription += ` [SHALLOW CLONE: repository history is truncated at shallow boundary; original introduction date, total exposure duration, and complete branch coverage are unverified]`;
      } else if (searchResult.isPartialHistory && maxCommits > 0) {
        statusDescription += ` [PARTIAL HISTORY: search depth limited to ${maxCommits} commit(s)]`;
      }

      const finalSearchStatus: GitExposure['searchStatus'] =
        (failedMetadataCount > 0 || headCheckFailed || wtCheckFailed || removalCheckFailed || isAncestorOfHead === 'UNKNOWN' || searchResult.isShallow || branchQueryFailed || searchResult.isPartialHistory)
          ? 'SEARCH_INCOMPLETE'
          : 'FOUND';

      return {
        introducedCommit,
        lastModifiedCommit,
        lastSeenCommit,
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
        searchStatus: finalSearchStatus,
        isPartialHistory: searchResult.isPartialHistory || failedMetadataCount > 0,
        isShallow,
        isIntroductionUnverified: isShallow,
        isAncestorOfHead,
        branchRemovals,
      };
    } catch (err: any) {
      return {
        isPresentInHead: 'UNKNOWN',
        isPresentInHistory: 'UNKNOWN',
        isPresentInWorkingTree: 'UNKNOWN',
        isSecretInWorkingTree: 'UNKNOWN',
        exposureDurationDays: 0,
        branches: [],
        isRemote: 'UNKNOWN',
        statusDescription: `Git history query failed: ${err?.message || String(err)}`,
        searchStatus: 'ERROR',
      };
    }
  }

  private async processCommitBlock(
    block: string,
    findings: SecretFinding[],
    headCheckCache: Map<string, boolean>
  ): Promise<void> {
    if (!block.trim()) return;

    const shaMatch = block.match(/^(?:commit\s+)?([0-9a-f]{40})/m);
    const sha = shaMatch ? shaMatch[1] : '';
    if (!sha) return;

    const authorMatch = block.match(/^Author:\s*(.+)$/m);
    const author = authorMatch ? authorMatch[1] : 'Unknown';

    const dateMatch = block.match(/^Date:\s*(.+)$/m);
    const date = dateMatch ? dateMatch[1] : '';

    // Extract added lines and files from diff
    const fileDiffs = block.split(/^diff --git /m);
    // Index 0 contains commit metadata / log message prior to first diff --git
    for (let i = 1; i < fileDiffs.length; i++) {
      const diff = fileDiffs[i];
      const firstLine = diff.split('\n')[0].trim();
      const headerPaths = parseDiffHeaderPaths(firstLine);
      let fileName = headerPaths ? headerPaths.pathB : '';
      if (!fileName) {
        const plusMatch = diff.match(/^\+\+\+ b\/(.+)$/m);
        if (plusMatch) {
          fileName = unquoteGitPath(plusMatch[1].trim());
        }
      }
      if (!fileName) continue;

      const diffFindings: SecretFinding[] = [];
      const isBinaryDiff = diff.includes('Binary files') || diff.includes('GIT binary patch');
      const isDeleted = diff.includes('deleted file mode') || diff.includes('+++ /dev/null');
      const isSubmodule = diff.includes('Subproject commit');

      if (isBinaryDiff) {
        if (!isDeleted && !isSubmodule) {
          // Retrieve binary blob and decode via content decoder
          try {
            const { stdout: binBuf } = await this.execGit(
              ['show', `${sha}:${fileName}`],
              { maxBuffer: 15 * 1024 * 1024, encoding: 'buffer' }
            );
            const decoded = decodeTextBuffer(binBuf);
            if (decoded) {
              const binFindings = scanContent(decoded, fileName, { workspaceRoot: this.workspaceRoot });
              diffFindings.push(...binFindings);
            }
          } catch (err: any) {
            throw new Error(`Failed to inspect binary blob at commit ${sha.substring(0, 8)} for file '${fileName}': ${err?.message || err}`);
          }
        }
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
        if (!isDeleted && !isSubmodule) {
          try {
            const { stdout: fullSnapshot } = await this.execGit(
              ['show', `${sha}:${fileName}`],
              { maxBuffer: 10 * 1024 * 1024, encoding: 'utf8' }
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
          } catch (err: any) {
            throw new Error(`Failed to inspect snapshot at commit ${sha.substring(0, 8)} for file '${fileName}': ${err?.message || err}`);
          }
        }
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

  /**
   * Scans full Git commit log diffs to detect historical secrets that may have been deleted from HEAD.
   * Transparently inspects merge commits (-m), binary diffs via decodeTextBuffer, and unconditionally verifies snapshots.
   * Streams commit blocks incrementally to avoid buffer overflow on large repositories.
   */
  public async scanHistoryCommits(maxCommits = 100): Promise<SecretFinding[]> {
    const isGit = await this.isGitRepo();
    if (!isGit) {
      throw new Error(`Target directory is not a Git repository: ${this.workspaceRoot}`);
    }

    try {
      // Get commit diffs across all branches, including merge commits (-m)
      const gitArgs = ['log', '--all', '-p', '-m', '-U1'];
      if (maxCommits > 0) {
        gitArgs.push('-n', String(maxCommits));
      }

      const findings: SecretFinding[] = [];
      const headCheckCache = new Map<string, boolean>();

      const child = spawn('git', gitArgs, { cwd: this.workspaceRoot });
      const rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });

      let currentBlockLines: string[] = [];
      const closePromise = new Promise<void>((resolve, reject) => {
        child.on('error', (err) => {
          reject(err);
        });
        child.on('close', (code) => {
          if (code !== 0 && code !== 1) {
            reject(new Error(`git log process exited with code ${code}`));
          } else {
            resolve();
          }
        });
      });

      for await (const line of rl) {
        if (/^commit [0-9a-f]{40}/.test(line)) {
          if (currentBlockLines.length > 0) {
            await this.processCommitBlock(currentBlockLines.join('\n'), findings, headCheckCache);
            currentBlockLines = [];
          }
        }
        currentBlockLines.push(line);
      }

      if (currentBlockLines.length > 0) {
        await this.processCommitBlock(currentBlockLines.join('\n'), findings, headCheckCache);
      }

      await closePromise;

      return findings;
    } catch (err: any) {
      throw new Error(`Failed to scan Git history commits: ${err.message || String(err)}`);
    }
  }
}
