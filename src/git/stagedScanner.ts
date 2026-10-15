import { execFileSync } from 'child_process';
import * as path from 'path';
import { scanContent } from '../core/scanner/scanner';
import { SecretFinding } from '../core/types';

export interface StagedScanResult {
  status: 'CLEAN' | 'FINDINGS' | 'ERROR';
  findings: SecretFinding[];
  error?: string;
  filesScanned?: number;
}

const GIT_BASE_ARGS = ['-c', 'core.quotepath=false'];

function isRenamedOrCopied(status: string): boolean {
  return status.startsWith('R') || status.startsWith('C');
}

function isDeleted(status: string): boolean {
  return status.startsWith('D');
}

/**
 * Scans Git staged changes for secrets using only argument-array Git APIs
 * (no shell interpolation) and NUL-delimited machine-readable output.
 *
 * Every staged file is either scanned correctly or causes a blocking ERROR.
 * The staged blob is read from the Git index only — never the working tree —
 * because the index and working tree can diverge.
 */
export function scanStagedChangesSync(workspaceRoot: string): StagedScanResult {
  let statusOutput: string;
  try {
    // Enumerate every staged path unambiguously (NUL-separated, unquoted, raw bytes).
    // status records:  STATUS\0PATH\0   or   STATUS\0OLD_PATH\0NEW_PATH\0 (rename/copy)
    // Scores like R100 / C80 are handled via prefix matching (see isRenamedOrCopied).
    statusOutput = execFileSync(
      'git',
      [...GIT_BASE_ARGS, 'diff', '--cached', '-z', '--name-status'],
      { cwd: workspaceRoot, encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }
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
      // Renamed/copied file: scan the destination path (new content).
      relPath = parts[i + 2];
      step = 3;
    }
    i += step;

    const normalizedRelPath = relPath.replace(/\\/g, '/');
    if (normalizedRelPath === '/dev/null') continue;
    if (isDeleted(status)) continue; // Deleted — no staged content to scan.

    // Read the exact staged blob from the Git index via an argument array.
    // No shell interpolation: safe against crafted staged filenames.
    let stagedBlob: string;
    try {
      stagedBlob = execFileSync(
        'git',
        [...GIT_BASE_ARGS, 'show', `:${normalizedRelPath}`],
        { cwd: workspaceRoot, encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }
      );
    } catch (blobErr: any) {
      // A staged file whose blob cannot be read is a scan error. Block the commit
      // rather than substituting working-tree content.
      allFindings.push({
        type: 'SCAN_ERROR',
        provider: 'Internal',
        file: normalizedRelPath,
        fullPath: path.join(workspaceRoot, relPath),
        line: 0,
        column: 0,
        rawSecret: '',
        redactedSecret: '',
        confidence: 0,
        risk: 'CRITICAL' as any,
        signals: [`git show failed: ${blobErr.message || String(blobErr)}`],
        evidence: { score: 0, items: [] },
        riskAssessment: {
          score: 100,
          blastRadius: { level: 'UNKNOWN', summary: 'Staged blob unreadable — scan blocked' },
          factors: [],
        },
        remediation: {
          steps: [],
          envVarName: '',
          replacementCode: '',
          envFileSnippet: '',
          envExampleSnippet: '',
          gitHistoryPurgeCommand: '',
          diffPreview: '',
        },
      } as any);
      continue;
    }

    // Added lines for this exact path (path passed as argv — no shell).
    const addedLineNumbers = new Set<number>();
    try {
      const diffForFile = execFileSync(
        'git',
        [...GIT_BASE_ARGS, 'diff', '--cached', '-U0', '--', normalizedRelPath],
        { cwd: workspaceRoot, encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 }
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

    const fileFindings = scanContent(stagedBlob, normalizedRelPath, { workspaceRoot });
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
