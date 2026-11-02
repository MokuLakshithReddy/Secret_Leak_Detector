import { execFileSync, execFile, spawn, spawnSync } from 'child_process';
import { promisify } from 'util';
import * as path from 'path';
import * as zlib from 'zlib';
import { scanContent, ScannerOptions } from '../core/scanner/scanner';
import { SecretFinding } from '../core/types';
import {
  loadIgnorePatterns,
  matchesIgnorePattern,
  DEFAULT_IGNORE_PATTERNS,
  BINARY_EXTENSIONS,
  NON_TEXT_EXTENSIONS,
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
  ignoredFiles?: { path: string; pattern: string }[];
  error?: string;
  filesScanned?: number;
}

const GIT_BASE_ARGS = [
  '--literal-pathspecs',
  '-c', 'core.quotepath=false',
  '-c', 'diff.noprefix=false',
  '-c', 'diff.mnemonicPrefix=false',
  '-c', 'color.diff=never',
];

const MAX_STAGED_FILE_SIZE = 50 * 1024 * 1024; // 50 MB (lenient limit)

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

import { decodeTextBuffer } from '../core/encoding/textDecoder';
export { decodeTextBuffer };

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

  if (res.error) {
    throw new Error(`git cat-file --batch-check failed: ${res.error.message}`);
  }
  if (res.status !== 0) {
    throw new Error(`git cat-file --batch-check exited with code ${res.status}: ${res.stderr || ''}`);
  }

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

  if (res.error) {
    throw new Error(`git cat-file --batch failed: ${res.error.message}`);
  }
  if (res.status !== 0) {
    throw new Error(`git cat-file --batch exited with code ${res.status}: ${res.stderr ? res.stderr.toString('utf8') : ''}`);
  }

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
    } else if (chunk.includes('rename to ') || chunk.includes('new file mode ') || chunk.includes('Binary files ')) {
      // Scored rename, new file mode, or binary diff with no text hunks: scan whole file (fail closed)
      filesWithAdditions.set(bPath, new Set([-1]));
    }
  }

  return filesWithAdditions;
}

/**
 * Checks whether any line in a finding's source range intersects with the added diff lines.
 * Prevents multiline secrets (such as PEM private keys) from escaping detection when only
 * their body lines are staged while the header already existed in the repository.
 */
export function findingIntersectsAddedLines(finding: SecretFinding, addedLines: Set<number>): boolean {
  if (addedLines.has(-1)) return true;
  const raw = finding.rawSecret || '';
  const newlineCount = (raw.match(/\r?\n/g) || []).length;
  const startLine = finding.line;
  const endLine = startLine + newlineCount;

  for (let l = startLine; l <= endLine; l++) {
    if (addedLines.has(l)) {
      return true;
    }
  }
  return false;
}

/**
 * Collects staged submodule links (git mode 160000).
 * Submodule commit bumps point to commits, not blobs in the parent repo,
 * so they must be filtered out before cat-file --batch-check to prevent false missing errors.
 */
function getStagedSubmodulesSync(gitRoot: string): Set<string> {
  const submodules = new Set<string>();
  try {
    const out = execFileSync('git', [...GIT_BASE_ARGS, 'ls-files', '--stage', '-z'], {
      cwd: gitRoot,
      maxBuffer: 64 * 1024 * 1024,
    });
    const entries = out.toString('utf8').split('\0');
    for (const entry of entries) {
      if (!entry) continue;
      const [meta, relPath] = entry.split('\t');
      if (meta && relPath && meta.startsWith('160000')) {
        submodules.add(relPath.replace(/\\/g, '/'));
      }
    }
  } catch {}
  return submodules;
}

async function getStagedSubmodulesAsync(gitRoot: string): Promise<Set<string>> {
  const submodules = new Set<string>();
  try {
    const { stdout } = await execFileAsync('git', [...GIT_BASE_ARGS, 'ls-files', '--stage', '-z'], {
      cwd: gitRoot,
      maxBuffer: 64 * 1024 * 1024,
    });
    const entries = stdout.split('\0');
    for (const entry of entries) {
      if (!entry) continue;
      const [meta, relPath] = entry.split('\t');
      if (meta && relPath && meta.startsWith('160000')) {
        submodules.add(relPath.replace(/\\/g, '/'));
      }
    }
  } catch {}
  return submodules;
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
  const submodules = getStagedSubmodulesSync(gitRoot);
  // Filter deletions and submodule bumps (mode 160000)
  const activeEntries = stagedEntries.filter((e) => e.status !== 'D' && !submodules.has(e.path));

  if (activeEntries.length === 0) {
    return { status: 'CLEAN', findings: [], skippedFiles: [], filesScanned: 0 };
  }

  const ignorePatterns = [...DEFAULT_IGNORE_PATTERNS, ...loadIgnorePatterns(gitRoot)];
  const skippedFiles: SkippedFile[] = [];
  const ignoredFiles: { path: string; pattern: string }[] = [];
  const candidatePaths: string[] = [];

  for (const entry of activeEntries) {
    const relPath = entry.path;

    // Honor ignore patterns (.sldignore and standard defaults) and track them to avoid silent skips
    const matchedIgnore = ignorePatterns.find((pattern) => matchesIgnorePattern(relPath, pattern));
    if (matchedIgnore) {
      ignoredFiles.push({ path: relPath, pattern: matchedIgnore });
      continue;
    }

    // Inspect content with decodeTextBuffer to protect credentials even in compiled/binary formats
    candidatePaths.push(relPath);
  }

  if (candidatePaths.length === 0) {
    return { status: 'CLEAN', findings: [], skippedFiles, ignoredFiles, filesScanned: 0 };
  }

  // 2. Batch size check via single git cat-file --batch-check
  let sizes: Map<string, number>;
  try {
    sizes = batchCheckSizesSync(gitRoot, candidatePaths);
  } catch (err: any) {
    return {
      status: 'ERROR',
      findings: [],
      error: err.message || String(err),
    };
  }

  const readablePaths: string[] = [];
  const effectiveLimit = options?.maxFileSize ?? MAX_STAGED_FILE_SIZE;

  for (const p of candidatePaths) {
    const size = sizes.get(p);
    if (size === undefined) {
      return {
        status: 'ERROR',
        findings: [],
        error: `Could not inspect staged blob size for '${p}': buffer truncated or process failed.`,
      };
    }
    if (size > effectiveLimit) {
      const maxMb = (effectiveLimit / (1024 * 1024)).toFixed(0);
      if (options?.ignoreSkipped === true) {
        skippedFiles.push({
          path: p,
          reason: `File size (${(size / (1024 * 1024)).toFixed(1)}MB) exceeds ${maxMb}MB limit`,
        });
        continue;
      }
      return {
        status: 'ERROR',
        findings: [],
        error: `File '${p}' (${(size / (1024 * 1024)).toFixed(1)}MB) exceeds ${maxMb}MB limit. Use --ignore-skipped to bypass.`,
      };
    }
    readablePaths.push(p);
  }

  if (readablePaths.length === 0) {
    if (options?.failOnSkipped && skippedFiles.length > 0) {
      return {
        status: 'ERROR',
        findings: [],
        skippedFiles,
        ignoredFiles,
        filesScanned: 0,
        error: `Strict mode (failOnSkipped): ${skippedFiles.length} file(s) were skipped during staged scan: ${skippedFiles.map((s) => s.path).join(', ')}`,
      };
    }
    return { status: 'CLEAN', findings: [], skippedFiles, ignoredFiles, filesScanned: 0 };
  }

  // 3. Batch read blobs in a single spawn
  let blobs: Map<string, Buffer>;
  try {
    blobs = batchReadBlobsSync(gitRoot, readablePaths);
  } catch (err: any) {
    return {
      status: 'ERROR',
      findings: [],
      error: err.message || String(err),
    };
  }

  // 4. Decode contents & detect binary/encoding
  const textByPath = new Map<string, string>();
  for (const p of readablePaths) {
    const rawBuf = blobs.get(p);
    if (!rawBuf) {
      return {
        status: 'ERROR',
        findings: [],
        error: `Could not read staged blob for '${p}': buffer truncated or read failed.`,
      };
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
    if (options?.failOnSkipped && skippedFiles.length > 0) {
      return {
        status: 'ERROR',
        findings: [],
        skippedFiles,
        ignoredFiles,
        filesScanned: 0,
        error: `Strict mode (failOnSkipped): ${skippedFiles.length} file(s) were skipped during staged scan: ${skippedFiles.map((s) => s.path).join(', ')}`,
      };
    }
    return { status: 'CLEAN', findings: [], skippedFiles, ignoredFiles, filesScanned: 0 };
  }

  // 5. Parse added line numbers from unified diff (chunked to 50 pathspecs to prevent ARG_MAX overflow)
  let diffOutput = '';
  const CHUNK_SIZE = 50;
  for (let i = 0; i < scannablePaths.length; i += CHUNK_SIZE) {
    const chunk = scannablePaths.slice(i, i + CHUNK_SIZE);
    try {
      const chunkDiff = execFileSync(
        'git',
        [
          ...GIT_BASE_ARGS,
          'diff',
          '--cached',
          '-U0',
          '--no-color',
          '--no-ext-diff',
          '--no-textconv',
          '--src-prefix=a/',
          '--dst-prefix=b/',
          '--',
          ...chunk,
        ],
        { cwd: gitRoot, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }
      );
      diffOutput += '\n' + chunkDiff;
    } catch (err: any) {
      // If diff fails, fail closed by scanning all lines of every scannable file
      diffOutput = '';
      break;
    }
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

    const fileFindings: SecretFinding[] = [];
    for (const finding of findings) {
      if (findingIntersectsAddedLines(finding, addedLines)) {
        fileFindings.push(finding);
      }
    }
    if (fileFindings.length > 0) {
      allFindings.push(...fileFindings);
    }
  }

  if (options?.failOnSkipped && skippedFiles.length > 0) {
    return {
      status: 'ERROR',
      findings: allFindings,
      skippedFiles,
      ignoredFiles,
      filesScanned,
      error: `Strict mode (failOnSkipped): ${skippedFiles.length} file(s) were skipped during staged scan: ${skippedFiles.map((s) => s.path).join(', ')}`,
    };
  }

  return {
    status: allFindings.length > 0 ? 'FINDINGS' : 'CLEAN',
    findings: allFindings,
    skippedFiles,
    ignoredFiles,
    filesScanned,
  };
}

/**
 * Asynchronous staged changes scanner for the VS Code extension host.
 * Completely non-blocking using child_process streams.
 */
export async function scanStagedChangesAsync(workspaceRoot: string, options?: ScannerOptions): Promise<StagedScanResult> {
  const gitRoot = await getGitTopLevelAsync(workspaceRoot);

  let statusBuf: Buffer;
  try {
    const { stdout } = await execFileAsync(
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
      { cwd: gitRoot, maxBuffer: 64 * 1024 * 1024, encoding: 'buffer' }
    );
    statusBuf = Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout);
  } catch (diffErr: any) {
    return {
      status: 'ERROR',
      findings: [],
      error: `git diff --cached failed: ${diffErr.message || String(diffErr)}`,
    };
  }

  const stagedEntries = parseNameStatusZ(statusBuf);
  const submodules = await getStagedSubmodulesAsync(gitRoot);
  // Filter deletions and submodule bumps (mode 160000)
  const activeEntries = stagedEntries.filter((e) => e.status !== 'D' && !submodules.has(e.path));

  if (activeEntries.length === 0) {
    return { status: 'CLEAN', findings: [], skippedFiles: [], filesScanned: 0 };
  }

  const ignorePatterns = [...DEFAULT_IGNORE_PATTERNS, ...loadIgnorePatterns(gitRoot)];
  const skippedFiles: SkippedFile[] = [];
  const ignoredFiles: { path: string; pattern: string }[] = [];
  const candidatePaths: string[] = [];

  for (const entry of activeEntries) {
    const relPath = entry.path;

    const matchedIgnore = ignorePatterns.find((pattern) => matchesIgnorePattern(relPath, pattern));
    if (matchedIgnore) {
      ignoredFiles.push({ path: relPath, pattern: matchedIgnore });
      continue;
    }

    candidatePaths.push(relPath);
  }

  if (candidatePaths.length === 0) {
    return { status: 'CLEAN', findings: [], skippedFiles, ignoredFiles, filesScanned: 0 };
  }

  // 2. Async batch size check
  const sizes = new Map<string, number>();
  try {
    const input = candidatePaths.map((p) => `:${p}\n`).join('');
    const child = spawn('git', [...GIT_BASE_ARGS, 'cat-file', '--batch-check'], {
      cwd: gitRoot,
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d.toString('utf8')));
    child.stderr.on('data', (d) => (err += d.toString('utf8')));
    child.stdin.write(input);
    child.stdin.end();

    await new Promise<void>((resolve, reject) => {
      child.on('error', reject);
      child.on('close', (code) => {
        if (code !== 0) reject(new Error(`git cat-file --batch-check exited with code ${code}: ${err}`));
        else resolve();
      });
    });

    const lines = out.split(/\r?\n/);
    for (let i = 0; i < candidatePaths.length; i++) {
      const line = lines[i];
      if (!line) continue;
      const parts = line.split(' ');
      if (parts.length >= 3 && parts[1] === 'blob') {
        sizes.set(candidatePaths[i], parseInt(parts[2], 10) || 0);
      }
    }
  } catch (err: any) {
    return {
      status: 'ERROR',
      findings: [],
      error: err.message || String(err),
    };
  }

  const readablePaths: string[] = [];
  const effectiveAsyncLimit = options?.maxFileSize ?? MAX_STAGED_FILE_SIZE;

  for (const p of candidatePaths) {
    const size = sizes.get(p);
    if (size === undefined) {
      return {
        status: 'ERROR',
        findings: [],
        error: `Could not inspect staged blob size for '${p}': buffer truncated or process failed.`,
      };
    }
    if (size > effectiveAsyncLimit) {
      const maxMb = (effectiveAsyncLimit / (1024 * 1024)).toFixed(0);
      if (options?.ignoreSkipped === true) {
        skippedFiles.push({
          path: p,
          reason: `File size (${(size / (1024 * 1024)).toFixed(1)}MB) exceeds ${maxMb}MB limit`,
        });
        continue;
      }
      return {
        status: 'ERROR',
        findings: [],
        error: `File '${p}' (${(size / (1024 * 1024)).toFixed(1)}MB) exceeds ${maxMb}MB limit. Use --ignore-skipped to bypass.`,
      };
    }
    readablePaths.push(p);
  }

  if (readablePaths.length === 0) {
    if (options?.failOnSkipped && skippedFiles.length > 0) {
      return {
        status: 'ERROR',
        findings: [],
        skippedFiles,
        ignoredFiles,
        filesScanned: 0,
        error: `Strict mode (failOnSkipped): ${skippedFiles.length} file(s) were skipped during staged scan: ${skippedFiles.map((s) => s.path).join(', ')}`,
      };
    }
    return { status: 'CLEAN', findings: [], skippedFiles, ignoredFiles, filesScanned: 0 };
  }

  // 3. Async batch read blobs
  const blobs = new Map<string, Buffer>();
  try {
    const input = readablePaths.map((p) => `:${p}\n`).join('');
    const child = spawn('git', [...GIT_BASE_ARGS, 'cat-file', '--batch'], {
      cwd: gitRoot,
    });
    const chunks: Buffer[] = [];
    let err = '';
    child.stdout.on('data', (d) => chunks.push(d));
    child.stderr.on('data', (d) => (err += d.toString('utf8')));
    child.stdin.write(input);
    child.stdin.end();

    await new Promise<void>((resolve, reject) => {
      child.on('error', reject);
      child.on('close', (code) => {
        if (code !== 0) reject(new Error(`git cat-file --batch exited with code ${code}: ${err}`));
        else resolve();
      });
    });

    const buf = Buffer.concat(chunks);
    let offset = 0;
    let pathIdx = 0;
    while (offset < buf.length && pathIdx < readablePaths.length) {
      const newlineIdx = buf.indexOf(10, offset);
      if (newlineIdx === -1) break;
      const header = buf.toString('utf8', offset, newlineIdx).trim();
      offset = newlineIdx + 1;

      const parts = header.split(' ');
      if (parts.length >= 3 && parts[1] === 'blob') {
        const size = parseInt(parts[2], 10);
        const content = buf.subarray(offset, offset + size);
        blobs.set(readablePaths[pathIdx++], content);
        offset += size;
        if (offset < buf.length && buf[offset] === 10) offset++;
      } else {
        pathIdx++;
      }
    }
  } catch (err: any) {
    return {
      status: 'ERROR',
      findings: [],
      error: err.message || String(err),
    };
  }

  // 4. Decode
  const textByPath = new Map<string, string>();
  for (const p of readablePaths) {
    const rawBuf = blobs.get(p);
    if (!rawBuf) {
      return {
        status: 'ERROR',
        findings: [],
        error: `Could not read staged blob for '${p}': buffer truncated or read failed.`,
      };
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
    if (options?.failOnSkipped && skippedFiles.length > 0) {
      return {
        status: 'ERROR',
        findings: [],
        skippedFiles,
        ignoredFiles,
        filesScanned: 0,
        error: `Strict mode (failOnSkipped): ${skippedFiles.length} file(s) were skipped during staged scan: ${skippedFiles.map((s) => s.path).join(', ')}`,
      };
    }
    return { status: 'CLEAN', findings: [], skippedFiles, ignoredFiles, filesScanned: 0 };
  }

  // 5. Async chunked diff
  let diffOutput = '';
  const CHUNK_SIZE = 50;
  for (let i = 0; i < scannablePaths.length; i += CHUNK_SIZE) {
    const chunk = scannablePaths.slice(i, i + CHUNK_SIZE);
    try {
      const { stdout } = await execFileAsync(
        'git',
        [
          ...GIT_BASE_ARGS,
          'diff',
          '--cached',
          '-U0',
          '--no-color',
          '--no-ext-diff',
          '--no-textconv',
          '--src-prefix=a/',
          '--dst-prefix=b/',
          '--',
          ...chunk,
        ],
        { cwd: gitRoot, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }
      );
      diffOutput += '\n' + stdout;
    } catch {
      // Chunk diff failed, fail closed
    }
  }

  const hunksMap = parseDiffHunks(diffOutput);
  const allFindings: SecretFinding[] = [];
  let filesScanned = 0;

  for (const relPath of scannablePaths) {
    const text = textByPath.get(relPath);
    if (!text) continue;

    const addedLines = hunksMap.get(relPath) || new Set([-1]);

    const scanOpts: ScannerOptions = {
      workspaceRoot: gitRoot,
      disallowInlineIgnore: options?.disallowInlineIgnore,
    };

    const findings = scanContent(text, relPath, scanOpts);
    filesScanned++;

    const fileFindings: SecretFinding[] = [];
    for (const finding of findings) {
      if (findingIntersectsAddedLines(finding, addedLines)) {
        fileFindings.push(finding);
      }
    }
    if (fileFindings.length > 0) {
      allFindings.push(...fileFindings);
    }
  }

  if (options?.failOnSkipped && skippedFiles.length > 0) {
    return {
      status: 'ERROR',
      findings: allFindings,
      skippedFiles,
      ignoredFiles,
      filesScanned,
      error: `Strict mode (failOnSkipped): ${skippedFiles.length} file(s) were skipped during staged scan: ${skippedFiles.map((s) => s.path).join(', ')}`,
    };
  }

  return {
    status: allFindings.length > 0 ? 'FINDINGS' : 'CLEAN',
    findings: allFindings,
    skippedFiles,
    ignoredFiles,
    filesScanned,
  };
}
