import { execFileSync, execFile } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';
import { scanContent } from '../core/scanner/scanner';
import { SecretFinding } from '../core/types';

const execFileAsync = promisify(execFile);

export interface StagedScanResult {
  status: 'CLEAN' | 'FINDINGS' | 'ERROR';
  findings: SecretFinding[];
  error?: string;
  filesScanned?: number;
}

const GIT_BASE_ARGS = ['-c', 'core.quotepath=false', '--literal-pathspecs'];

function isRenamedOrCopied(status: string): boolean {
  return status.startsWith('R') || status.startsWith('C');
}

function isDeleted(status: string): boolean {
  return status.startsWith('D');
}

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

/**
 * Scans Git staged changes for secrets using argument-array Git APIs
 * (no shell interpolation) and NUL-delimited machine-readable output.
 *
 * Runs from the Git root to ensure root-relative paths match index queries
 * even when invoked from a monorepo subfolder.
 */
export function scanStagedChangesSync(workspaceRoot: string): StagedScanResult {
  const gitRoot = getGitTopLevelSync(workspaceRoot);
  let statusOutput: string;
  try {
    statusOutput = execFileSync(
      'git',
      [...GIT_BASE_ARGS, 'diff', '--cached', '-z', '--name-status'],
      { cwd: gitRoot, encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }
    );
  } catch (listErr: any) {
    return {
      status: 'ERROR',
      findings: [],
      error: `git diff --cached failed: ${listErr.message || String(listErr)}`,
    };
  }

  const parts = statusOutput.split('\0').filter(Boolean);
  const allFindings: SecretFinding[] = [];
  let filesScanned = 0;

  for (let i = 0; i < parts.length; ) {
    const status = parts[i];
    const oldPath = parts[i + 1];
    let relPath = oldPath;
    let step = 2;

    if (isRenamedOrCopied(status) && parts[i + 2] !== undefined) {
      relPath = parts[i + 2];
      step = 3;
    }
    i += step;

    const normalizedRelPath = relPath.replace(/\\/g, '/');
    if (normalizedRelPath === '/dev/null') continue;
    if (isDeleted(status)) continue;

    let stagedBlob: string;
    try {
      stagedBlob = execFileSync(
        'git',
        [...GIT_BASE_ARGS, 'show', `:${normalizedRelPath}`],
        { cwd: gitRoot, encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }
      );
    } catch (blobErr: any) {
      return {
        status: 'ERROR',
        findings: allFindings,
        error: `Could not read staged blob for '${normalizedRelPath}': ${blobErr.message || String(blobErr)}`,
        filesScanned,
      };
    }

    const addedLineNumbers = new Set<number>();
    try {
      const diffForFile = execFileSync(
        'git',
        [...GIT_BASE_ARGS, 'diff', '--cached', '-U0', '--', normalizedRelPath],
        { cwd: gitRoot, encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }
      );
      const hunkRegex = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm;
      let hunkMatch: RegExpExecArray | null;
      while ((hunkMatch = hunkRegex.exec(diffForFile)) !== null) {
        const newStart = parseInt(hunkMatch[1], 10);
        const newCount = hunkMatch[2] !== undefined ? parseInt(hunkMatch[2], 10) : 1;
        for (let k = 0; k < newCount; k++) {
          addedLineNumbers.add(newStart + k);
        }
      }
    } catch (diffErr: any) {
      return {
        status: 'ERROR',
        findings: allFindings,
        error: `Could not determine staged diff for '${normalizedRelPath}': ${diffErr.message || String(diffErr)}`,
        filesScanned,
      };
    }

    if (addedLineNumbers.size === 0) continue;

    const fileFindings = scanContent(stagedBlob, normalizedRelPath, { workspaceRoot: gitRoot });
    for (const f of fileFindings) {
      if (addedLineNumbers.has(f.line)) {
        allFindings.push(f);
      }
    }
    filesScanned++;
  }

  if (allFindings.length > 0) {
    return { status: 'FINDINGS', findings: allFindings, filesScanned };
  }

  return { status: 'CLEAN', findings: [], filesScanned };
}

/**
 * Asynchronous staged scanner for use in VS Code extension (keeps UI thread non-blocking).
 */
export async function scanStagedChangesAsync(workspaceRoot: string): Promise<StagedScanResult> {
  const gitRoot = await getGitTopLevelAsync(workspaceRoot);
  let statusOutput: string;
  try {
    const { stdout } = await execFileAsync(
      'git',
      [...GIT_BASE_ARGS, 'diff', '--cached', '-z', '--name-status'],
      { cwd: gitRoot, encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }
    );
    statusOutput = stdout;
  } catch (listErr: any) {
    return {
      status: 'ERROR',
      findings: [],
      error: `git diff --cached failed: ${listErr.message || String(listErr)}`,
    };
  }

  const parts = statusOutput.split('\0').filter(Boolean);
  const allFindings: SecretFinding[] = [];
  let filesScanned = 0;

  for (let i = 0; i < parts.length; ) {
    const status = parts[i];
    const oldPath = parts[i + 1];
    let relPath = oldPath;
    let step = 2;

    if (isRenamedOrCopied(status) && parts[i + 2] !== undefined) {
      relPath = parts[i + 2];
      step = 3;
    }
    i += step;

    const normalizedRelPath = relPath.replace(/\\/g, '/');
    if (normalizedRelPath === '/dev/null') continue;
    if (isDeleted(status)) continue;

    let stagedBlob: string;
    try {
      const { stdout: blobOut } = await execFileAsync(
        'git',
        [...GIT_BASE_ARGS, 'show', `:${normalizedRelPath}`],
        { cwd: gitRoot, encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }
      );
      stagedBlob = blobOut;
    } catch (blobErr: any) {
      return {
        status: 'ERROR',
        findings: allFindings,
        error: `Could not read staged blob for '${normalizedRelPath}': ${blobErr.message || String(blobErr)}`,
        filesScanned,
      };
    }

    const addedLineNumbers = new Set<number>();
    try {
      const { stdout: diffOut } = await execFileAsync(
        'git',
        [...GIT_BASE_ARGS, 'diff', '--cached', '-U0', '--', normalizedRelPath],
        { cwd: gitRoot, encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }
      );
      const hunkRegex = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm;
      let hunkMatch: RegExpExecArray | null;
      while ((hunkMatch = hunkRegex.exec(diffOut)) !== null) {
        const newStart = parseInt(hunkMatch[1], 10);
        const newCount = hunkMatch[2] !== undefined ? parseInt(hunkMatch[2], 10) : 1;
        for (let k = 0; k < newCount; k++) {
          addedLineNumbers.add(newStart + k);
        }
      }
    } catch (diffErr: any) {
      return {
        status: 'ERROR',
        findings: allFindings,
        error: `Could not determine staged diff for '${normalizedRelPath}': ${diffErr.message || String(diffErr)}`,
        filesScanned,
      };
    }

    if (addedLineNumbers.size === 0) continue;

    const fileFindings = scanContent(stagedBlob, normalizedRelPath, { workspaceRoot: gitRoot });
    for (const f of fileFindings) {
      if (addedLineNumbers.has(f.line)) {
        allFindings.push(f);
      }
    }
    filesScanned++;
  }

  if (allFindings.length > 0) {
    return { status: 'FINDINGS', findings: allFindings, filesScanned };
  }

  return { status: 'CLEAN', findings: [], filesScanned };
}
