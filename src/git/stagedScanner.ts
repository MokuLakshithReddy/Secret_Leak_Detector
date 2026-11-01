import { execFileSync, execFile, spawn, spawnSync } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';
import { scanContent, ScannerOptions } from '../core/scanner/scanner';
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

const GIT_BASE_ARGS = [
  '-c', 'core.quotepath=false',
  '-c', 'diff.noprefix=false',
  '-c', 'diff.mnemonicPrefix=false',
  '-c', 'color.diff=never',
];

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

export interface StagedFileEntry {
  status: string; // 'A', 'M', 'R', 'C', etc.
  path: string;
  oldPath?: string;
}

/**
 * Parses NUL-delimited output from `git diff --cached -z --name-status`.
 * Completely immune to user diff configs, prefixes, quotes, and backslashes in filenames.
 */
export function parseNameStatusZ(buf: Buffer): StagedFileEntry[] {
  const result: StagedFileEntry[] = [];
  const tokens: string[] = [];
  let start = 0;
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] === 0) {
      tokens.push(buf.toString('utf8', start, i));
      start = i + 1;
    }
  }

  let idx = 0;
  while (idx < tokens.length) {
    const status = tokens[idx++];
    if (!status) break;
    const statusCode = status[0];
    if (statusCode === 'R' || statusCode === 'C') {
      const oldPath = tokens[idx++];
      const newPath = tokens[idx++];
      if (newPath) {
        result.push({
          status: statusCode,
          path: newPath.replace(/\\/g, '/'),
          oldPath: oldPath ? oldPath.replace(/\\/g, '/') : undefined,
        });
      }
    } else {
      const p = tokens[idx++];
      if (p) {
        result.push({
          status: statusCode,
          path: p.replace(/\\/g, '/'),
        });
      }
    }
  }
  return result;
}

/**
 * Decodes buffer into string, transparently supporting UTF-8, UTF-16LE, and UTF-16BE.
 * Returns null if the buffer is genuinely a non-text binary asset.
 */
export function decodeTextBuffer(buf: Buffer): string | null {
  if (buf.length === 0) return '';

  // 1. UTF-16LE BOM: 0xFF 0xFE
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    return buf.subarray(2).toString('utf16le');
  }

  // 2. UTF-16BE BOM: 0xFE 0xFF
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    const swapped = Buffer.from(buf.subarray(2));
    swapped.swap16();
    return swapped.toString('utf16le');
  }

  // 3. UTF-16LE without BOM (ASCII characters with alternating null bytes)
  if (buf.length >= 4) {
    let nullOdds = 0;
    let nullEvens = 0;
    const sampleSize = Math.min(buf.length, 512);
    for (let i = 0; i < sampleSize; i++) {
      if (buf[i] === 0) {
        if (i % 2 === 1) nullOdds++;
        else nullEvens++;
      }
    }
    if (nullOdds > sampleSize * 0.35 && nullEvens < sampleSize * 0.05) {
      return buf.toString('utf16le');
    }
  }

  // 4. Binary check: scan for null bytes or control character density
  const checkLen = Math.min(buf.length, 1024);
  let nullCount = 0;
  for (let i = 0; i < checkLen; i++) {
    if (buf[i] === 0) nullCount++;
  }
  if (nullCount > 0) {
    return null; // Binary asset
  }

  return buf.toString('utf8');
}

/**
 * Batches file size check using a single `git cat-file --batch-check` process.
 */
function batchCheckSizesSync(gitRoot: string, relPaths: string[]): Map<string, number> {
  const sizes = new Map<string, number>();
  if (relPaths.length === 0) return sizes;

  const input = relPaths.map((p) => `:${p}\n`).join('');
  const res = spawnSync('git', [...GIT_BASE_ARGS, 'cat-file', '--batch-check'], {
    cwd: gitRoot,
    input,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });

  if (res.stdout) {
    const lines = res.stdout.split(/\r?\n/);
    for (let i = 0; i < relPaths.length; i++) {
      const line = lines[i];
      if (!line) continue;
      const parts = line.split(' ');
      if (parts.length >= 3 && parts[1] === 'blob') {
        sizes.set(relPaths[i], parseInt(parts[2], 10) || 0);
      }
    }
  }
  return sizes;
}

/**
 * Batches file blob reads using a single `git cat-file --batch` process.
 */
function batchReadBlobsSync(gitRoot: string, relPaths: string[]): Map<string, Buffer> {
  const blobs = new Map<string, Buffer>();
  if (relPaths.length === 0) return blobs;

  const input = relPaths.map((p) => `:${p}\n`).join('');
  const res = spawnSync('git', [...GIT_BASE_ARGS, 'cat-file', '--batch'], {
    cwd: gitRoot,
    input,
    maxBuffer: 64 * 1024 * 1024,
  });

  const buf = res.stdout;
  if (!buf || buf.length === 0) return blobs;

  let offset = 0;
  let pathIdx = 0;
  while (offset < buf.length && pathIdx < relPaths.length) {
    const newlineIdx = buf.indexOf(10, offset);
    if (newlineIdx === -1) break;
    const header = buf.toString('utf8', offset, newlineIdx).trim();
    offset = newlineIdx + 1;

    const parts = header.split(' ');
    if (parts.length >= 3 && parts[1] === 'blob') {
      const size = parseInt(parts[2], 10);
      const content = buf.subarray(offset, offset + size);
      blobs.set(relPaths[pathIdx++], content);
      offset += size;
      if (offset < buf.length && buf[offset] === 10) offset++;
    } else {
      pathIdx++;
    }
  }
  return blobs;
}

/**
 * Parses added line numbers from unified diff text.
 */
function parseDiffHunks(diffOutput: string): Map<string, Set<number>> {
  const filesWithAdditions = new Map<string, Set<number>>();
  const diffChunks = diffOutput.split(/^diff --git /m);

  for (const chunk of diffChunks) {
    if (!chunk.trim()) continue;
    const lines = chunk.split(/\r?\n/);
    const headerLine = lines[0];
    const match = headerLine.match(/a\/(.+)\s+b\/(.+)/);
    if (!match) continue;

    const bPath = match[2].trim().replace(/\\/g, '/');
    if (bPath === '/dev/null') continue;

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

    if (addedLines.size > 0) {
      filesWithAdditions.set(bPath, addedLines);
    } else if (chunk.includes('rename to ') || chunk.includes('new file mode ')) {
      // Scored rename or new mode with no hunk additions: scan whole file (fail closed)
      filesWithAdditions.set(bPath, new Set([-1]));
    }
  }

  return filesWithAdditions;
}

/**
 * Fast synchronous staged changes scanner.
 * Enforces fail-closed security, NUL-delimited status parsing, and batch blob reading.
 */
export function scanStagedChangesSync(workspaceRoot: string, options?: ScannerOptions): StagedScanResult {
  const gitRoot = getGitTopLevelSync(workspaceRoot);

  // 1. Authoritative staged file listing via NUL-delimited name-status
  let statusBuf: Buffer;
  try {
    statusBuf = execFileSync(
      'git',
      [
        ...GIT_BASE_ARGS,
        'diff',
        '--cached',
        '-z',
        '--name-status',
        '--no-color',
        '--no-ext-diff',
        '--src-prefix=a/',
        '--dst-prefix=b/',
      ],
      { cwd: gitRoot, maxBuffer: 64 * 1024 * 1024 }
    );
  } catch (diffErr: any) {
    return {
      status: 'ERROR',
      findings: [],
      error: `git diff --cached failed: ${diffErr.message || String(diffErr)}`,
    };
  }

  const stagedEntries = parseNameStatusZ(statusBuf);
  const activeEntries = stagedEntries.filter((e) => e.status !== 'D');

  if (activeEntries.length === 0) {
    return { status: 'CLEAN', findings: [], skippedFiles: [], filesScanned: 0 };
  }

  const ignorePatterns = [...DEFAULT_IGNORE_PATTERNS, ...loadIgnorePatterns(gitRoot)];
  const skippedFiles: SkippedFile[] = [];
  const candidatePaths: string[] = [];

  for (const entry of activeEntries) {
    const relPath = entry.path;
    const ext = path.extname(relPath).toLowerCase();

    // Honor ignore patterns (.sldignore and standard defaults)
    if (ignorePatterns.some((pattern) => matchesIgnorePattern(relPath, pattern))) {
      continue;
    }

    // Filter binary by extension
    if (BINARY_EXTENSIONS.has(ext)) {
      skippedFiles.push({ path: relPath, reason: 'Binary file extension skipped' });
      continue;
    }

    candidatePaths.push(relPath);
  }

  if (candidatePaths.length === 0) {
    return { status: 'CLEAN', findings: [], skippedFiles, filesScanned: 0 };
  }

  // 2. Batch size check via single git cat-file --batch-check
  const sizes = batchCheckSizesSync(gitRoot, candidatePaths);
  const readablePaths: string[] = [];

  for (const p of candidatePaths) {
    const size = sizes.get(p);
    if (size === undefined) {
      skippedFiles.push({ path: p, reason: 'Could not inspect blob size' });
      continue;
    }
    if (size > MAX_STAGED_FILE_SIZE) {
      skippedFiles.push({
        path: p,
        reason: `File size (${(size / (1024 * 1024)).toFixed(1)}MB) exceeds 5MB limit`,
      });
      continue;
    }
    readablePaths.push(p);
  }

  if (readablePaths.length === 0) {
    return { status: 'CLEAN', findings: [], skippedFiles, filesScanned: 0 };
  }

  // 3. Batch read blobs in a single spawn
  const blobs = batchReadBlobsSync(gitRoot, readablePaths);

  // 4. Decode contents & detect binary/encoding
  const textByPath = new Map<string, string>();
  for (const p of readablePaths) {
    const rawBuf = blobs.get(p);
    if (!rawBuf) {
      skippedFiles.push({ path: p, reason: 'Could not read staged blob' });
      continue;
    }
    const decoded = decodeTextBuffer(rawBuf);
    if (decoded === null) {
      skippedFiles.push({ path: p, reason: 'Binary content detected' });
      continue;
    }
    textByPath.set(p, decoded);
  }

  const scannablePaths = Array.from(textByPath.keys());
  if (scannablePaths.length === 0) {
    return { status: 'CLEAN', findings: [], skippedFiles, filesScanned: 0 };
  }

  // 5. Parse added line numbers from unified diff (bounded to scannable paths)
  let diffOutput = '';
  try {
    diffOutput = execFileSync(
      'git',
      [
        ...GIT_BASE_ARGS,
        'diff',
        '--cached',
        '-U0',
        '--no-color',
        '--no-ext-diff',
        '--src-prefix=a/',
        '--dst-prefix=b/',
        '--',
        ...scannablePaths,
      ],
      { cwd: gitRoot, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }
    );
  } catch (err: any) {
    // If diff fails, fail closed by scanning all lines of every scannable file
    diffOutput = '';
  }

  const hunksMap = parseDiffHunks(diffOutput);
  const allFindings: SecretFinding[] = [];
  let filesScanned = 0;

  for (const relPath of scannablePaths) {
    const text = textByPath.get(relPath);
    if (!text) continue;

    // Fail closed: if diff hunk parsing missed this file, scan all lines (set [-1])
    const addedLines = hunksMap.get(relPath) || new Set([-1]);

    const scanOpts: ScannerOptions = {
      workspaceRoot: gitRoot,
      disallowInlineIgnore: options?.disallowInlineIgnore,
    };

    const findings = scanContent(text, relPath, scanOpts);
    filesScanned++;

    for (const finding of findings) {
      if (addedLines.has(-1) || addedLines.has(finding.line)) {
        allFindings.push(finding);
      }
    }
  }

  return {
    status: allFindings.length > 0 ? 'FINDINGS' : 'CLEAN',
    findings: allFindings,
    skippedFiles,
    filesScanned,
  };
}

/**
 * Asynchronous staged changes scanner for the VS Code extension host.
 */
export async function scanStagedChangesAsync(workspaceRoot: string, options?: ScannerOptions): Promise<StagedScanResult> {
  // Use synchronous batch implementation offloaded or non-blocking
  return new Promise((resolve) => {
    try {
      const res = scanStagedChangesSync(workspaceRoot, options);
      resolve(res);
    } catch (err: any) {
      resolve({
        status: 'ERROR',
        findings: [],
        error: err.message || String(err),
      });
    }
  });
}
