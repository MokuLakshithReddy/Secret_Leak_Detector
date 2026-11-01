import { execFileSync, execFile } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';
import { scanContent } from '../core/scanner/scanner';
import { SecretFinding } from '../core/types';
import {
  loadIgnorePatterns,
  matchesIgnorePattern,
  DEFAULT_IGNORE_PATTERNS,
  BINARY_EXTENSIONS,
} from '../core/ignore/ignoreEngine';

const execFileAsync = promisify(execFile);

export interface SkippedFile {
  path: string;
  reason: string;
}

export interface StagedScanResult {
  status: 'CLEAN' | 'FINDINGS' | 'ERROR';
  findings: SecretFinding[];
  skippedFiles?: SkippedFile[];
  error?: string;
  filesScanned?: number;
}

const GIT_BASE_ARGS = ['-c', 'core.quotepath=false', '--literal-pathspecs'];
const MAX_STAGED_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

function getGitTopLevelSync(dir: string): string {
  try {
    const out = execFileSync('git', ['rev-parse', '--show-toplevel'], { cwd: dir, encoding: 'utf8' }).trim();
    if (out) return path.resolve(out);
  } catch {}
  return dir;
}

async function getGitTopLevelAsync(dir: string): Promise<string> {
  try {
    const { stdout } = await execFileAsync('git', ['rev-parse', '--show-toplevel'], { cwd: dir, encoding: 'utf8' });
    const out = stdout.trim();
    if (out) return path.resolve(out);
  } catch {}
  return dir;
}

interface StagedDiffMeta {
  filesWithAdditions: Map<string, Set<number>>;
  binaryFiles: Set<string>;
}

function parseUnifiedDiff(diffOutput: string): StagedDiffMeta {
  const filesWithAdditions = new Map<string, Set<number>>();
  const binaryFiles = new Set<string>();

  const diffChunks = diffOutput.split(/^diff --git /m);
  for (const chunk of diffChunks) {
    if (!chunk.trim()) continue;
    const lines = chunk.split(/\r?\n/);
    const headerLine = lines[0];
    const match = headerLine.match(/a\/(.+)\s+b\/(.+)/);
    if (!match) continue;

    const bPath = match[2].trim().replace(/\\/g, '/');
    if (bPath === '/dev/null') continue;

    // Check if binary
    if (chunk.includes('Binary files') || chunk.includes('GIT binary patch')) {
      binaryFiles.add(bPath);
      continue;
    }

    const addedLines = new Set<number>();
    const hunkRegex = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm;
    let hunkMatch: RegExpExecArray | null;
    while ((hunkMatch = hunkRegex.exec(chunk)) !== null) {
      const newStart = parseInt(hunkMatch[1], 10);
      const newCount = hunkMatch[2] !== undefined ? parseInt(hunkMatch[2], 10) : 1;
      for (let k = 0; k < newCount; k++) {
        addedLines.add(newStart + k);
      }
    }

    const isRename = chunk.includes('rename to ');
    if (addedLines.size > 0) {
      filesWithAdditions.set(bPath, addedLines);
    } else if (isRename) {
      filesWithAdditions.set(bPath, new Set([-1]));
    }
  }

  return { filesWithAdditions, binaryFiles };
}

/**
 * Fast synchronous staged changes scanner.
 * Executes a single `git diff --cached -U0` across the entire index,
 * honors ignore patterns and file size/binary safety, and avoids per-file process forks.
 */
export function scanStagedChangesSync(workspaceRoot: string): StagedScanResult {
  const gitRoot = getGitTopLevelSync(workspaceRoot);
  let diffOutput: string;
  try {
    diffOutput = execFileSync(
      'git',
      [...GIT_BASE_ARGS, 'diff', '--cached', '-U0'],
      { cwd: gitRoot, encoding: 'utf8', maxBuffer: 25 * 1024 * 1024 }
    );
  } catch (diffErr: any) {
    return {
      status: 'ERROR',
      findings: [],
      error: `git diff --cached failed: ${diffErr.message || String(diffErr)}`,
    };
  }

  const { filesWithAdditions, binaryFiles } = parseUnifiedDiff(diffOutput);
  const ignorePatterns = [...DEFAULT_IGNORE_PATTERNS, ...loadIgnorePatterns(gitRoot)];
  const allFindings: SecretFinding[] = [];
  const skippedFiles: SkippedFile[] = [];
  let filesScanned = 0;

  for (const [relPath, addedLines] of filesWithAdditions.entries()) {
    const ext = path.extname(relPath).toLowerCase();

    // Check ignore patterns (.sldignore and defaults)
    if (ignorePatterns.some((pattern) => matchesIgnorePattern(relPath, pattern))) {
      continue;
    }

    // Check binary file
    if (binaryFiles.has(relPath) || BINARY_EXTENSIONS.has(ext)) {
      skippedFiles.push({ path: relPath, reason: 'Binary file skipped' });
      continue;
    }

    // Check size before reading blob to avoid ENOBUFS
    let fileSize = 0;
    try {
      const sizeStr = execFileSync(
        'git',
        [...GIT_BASE_ARGS, 'cat-file', '-s', `:${relPath}`],
        { cwd: gitRoot, encoding: 'utf8' }
      ).trim();
      fileSize = parseInt(sizeStr, 10) || 0;
    } catch {
      // If cat-file fails (e.g. unreadable blob), skip safely
      skippedFiles.push({ path: relPath, reason: 'Could not inspect blob size' });
      continue;
    }

    if (fileSize > MAX_STAGED_FILE_SIZE) {
      skippedFiles.push({
        path: relPath,
        reason: `File size (${(fileSize / (1024 * 1024)).toFixed(1)}MB) exceeds 5MB limit`,
      });
      continue;
    }

    let stagedBlob: string;
    try {
      stagedBlob = execFileSync(
        'git',
        [...GIT_BASE_ARGS, 'show', `:${relPath}`],
        { cwd: gitRoot, encoding: 'utf8', maxBuffer: MAX_STAGED_FILE_SIZE + 1024 }
      );
    } catch (blobErr: any) {
      skippedFiles.push({ path: relPath, reason: `Unreadable staged blob: ${blobErr.message}` });
      continue;
    }

    const fileFindings = scanContent(stagedBlob, relPath, { workspaceRoot: gitRoot });
    const matchAll = addedLines.has(-1);
    for (const f of fileFindings) {
      if (matchAll || addedLines.has(f.line)) {
        allFindings.push(f);
      }
    }
    filesScanned++;
  }

  if (allFindings.length > 0) {
    return { status: 'FINDINGS', findings: allFindings, skippedFiles, filesScanned };
  }

  return { status: 'CLEAN', findings: [], skippedFiles, filesScanned };
}

/**
 * Asynchronous staged scanner for use in VS Code extension (keeps UI thread non-blocking).
 */
export async function scanStagedChangesAsync(workspaceRoot: string): Promise<StagedScanResult> {
  const gitRoot = await getGitTopLevelAsync(workspaceRoot);
  let diffOutput: string;
  try {
    const { stdout } = await execFileAsync(
      'git',
      [...GIT_BASE_ARGS, 'diff', '--cached', '-U0'],
      { cwd: gitRoot, encoding: 'utf8', maxBuffer: 25 * 1024 * 1024 }
    );
    diffOutput = stdout;
  } catch (diffErr: any) {
    return {
      status: 'ERROR',
      findings: [],
      error: `git diff --cached failed: ${diffErr.message || String(diffErr)}`,
    };
  }

  const { filesWithAdditions, binaryFiles } = parseUnifiedDiff(diffOutput);
  const ignorePatterns = [...DEFAULT_IGNORE_PATTERNS, ...loadIgnorePatterns(gitRoot)];
  const allFindings: SecretFinding[] = [];
  const skippedFiles: SkippedFile[] = [];
  let filesScanned = 0;

  for (const [relPath, addedLines] of filesWithAdditions.entries()) {
    const ext = path.extname(relPath).toLowerCase();

    if (ignorePatterns.some((pattern) => matchesIgnorePattern(relPath, pattern))) {
      continue;
    }

    if (binaryFiles.has(relPath) || BINARY_EXTENSIONS.has(ext)) {
      skippedFiles.push({ path: relPath, reason: 'Binary file skipped' });
      continue;
    }

    let fileSize = 0;
    try {
      const { stdout: sizeStr } = await execFileAsync(
        'git',
        [...GIT_BASE_ARGS, 'cat-file', '-s', `:${relPath}`],
        { cwd: gitRoot, encoding: 'utf8' }
      );
      fileSize = parseInt(sizeStr.trim(), 10) || 0;
    } catch {
      skippedFiles.push({ path: relPath, reason: 'Could not inspect blob size' });
      continue;
    }

    if (fileSize > MAX_STAGED_FILE_SIZE) {
      skippedFiles.push({
        path: relPath,
        reason: `File size (${(fileSize / (1024 * 1024)).toFixed(1)}MB) exceeds 5MB limit`,
      });
      continue;
    }

    let stagedBlob: string;
    try {
      const { stdout: blobOut } = await execFileAsync(
        'git',
        [...GIT_BASE_ARGS, 'show', `:${relPath}`],
        { cwd: gitRoot, encoding: 'utf8', maxBuffer: MAX_STAGED_FILE_SIZE + 1024 }
      );
      stagedBlob = blobOut;
    } catch (blobErr: any) {
      skippedFiles.push({ path: relPath, reason: `Unreadable staged blob: ${blobErr.message}` });
      continue;
    }

    const fileFindings = scanContent(stagedBlob, relPath, { workspaceRoot: gitRoot });
    const matchAll = addedLines.has(-1);
    for (const f of fileFindings) {
      if (matchAll || addedLines.has(f.line)) {
        allFindings.push(f);
      }
    }
    filesScanned++;
  }

  if (allFindings.length > 0) {
    return { status: 'FINDINGS', findings: allFindings, skippedFiles, filesScanned };
  }

  return { status: 'CLEAN', findings: [], skippedFiles, filesScanned };
}
