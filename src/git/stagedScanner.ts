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
  '--literal-pathspecs',
  '-c', 'core.quotepath=false',
  '-c', 'diff.noprefix=false',
  '-c', 'diff.mnemonicPrefix=false',
  '-c', 'color.diff=never',
];

const MAX_STAGED_FILE_SIZE = 50 * 1024 * 1024; // 50 MB (lenient limit)

/**
 * Pure non-text media & compiled binary formats that cannot contain readable secrets.
 * Text files disguised as .png, .bin, .pkl, .sqlite are NOT in this set, so their content is inspected.
 */
const NON_TEXT_EXTENSIONS = new Set([
  '.exe', '.dll', '.so', '.dylib', '.iso', '.dmg',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.wav',
  '.pyc', '.pyo', '.class',
  '.o', '.obj', '.lib', '.a',
]);

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

function decodeUtf32(buf: Buffer, littleEndian: boolean): string {
  let str = '';
  const len = buf.length - (buf.length % 4);
  for (let i = 0; i < len; i += 4) {
    const cp = littleEndian ? buf.readUInt32LE(i) : buf.readUInt32BE(i);
    if (cp === 0) continue;
    if (cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff)) {
      str += String.fromCodePoint(cp);
    }
  }
  return str;
}

/**
 * Decodes buffer into string, transparently supporting UTF-8, UTF-16, UTF-32, gzip,
 * and text files with sparse NUL bytes or embedded binary sections.
 * Returns null only if the buffer is genuinely a non-text asset with zero extractable text.
 */
export function decodeTextBuffer(buf: Buffer): string | null {
  if (buf.length === 0) return '';

  // 1. gzip decompression: 0x1F 0x8B
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    try {
      const decompressed = zlib.gunzipSync(buf, { finishFlush: zlib.constants.Z_SYNC_FLUSH });
      const decoded = decodeTextBuffer(decompressed);
      if (decoded !== null) return decoded;
    } catch {}
  }

  // 2. UTF-32 BOM: 0xFF 0xFE 0x00 0x00 (LE) or 0x00 0x00 0xFE 0xFF (BE)
  if (buf.length >= 4) {
    if (buf[0] === 0xff && buf[1] === 0xfe && buf[2] === 0x00 && buf[3] === 0x00) {
      return decodeUtf32(buf.subarray(4), true);
    }
    if (buf[0] === 0x00 && buf[1] === 0x00 && buf[2] === 0xfe && buf[3] === 0xff) {
      return decodeUtf32(buf.subarray(4), false);
    }
  }

  // 3. UTF-16LE BOM: 0xFF 0xFE
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) {
    return buf.subarray(2).toString('utf16le');
  }

  // 4. UTF-16BE BOM: 0xFE 0xFF
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) {
    const swapped = Buffer.from(buf.subarray(2));
    swapped.swap16();
    return swapped.toString('utf16le');
  }

  // 5. UTF-32 without BOM (3 nulls out of every 4 bytes for ASCII chars)
  if (buf.length >= 8) {
    const sampleSize = Math.min(buf.length - (buf.length % 4), 256);
    let le3NullCount = 0;
    let be3NullCount = 0;
    for (let i = 0; i < sampleSize; i += 4) {
      if (buf[i + 1] === 0 && buf[i + 2] === 0 && buf[i + 3] === 0 && buf[i] !== 0) le3NullCount++;
      if (buf[i] === 0 && buf[i + 1] === 0 && buf[i + 2] === 0 && buf[i + 3] !== 0) be3NullCount++;
    }
    const words = sampleSize / 4;
    if (le3NullCount > words * 0.4) {
      return decodeUtf32(buf, true);
    }
    if (be3NullCount > words * 0.4) {
      return decodeUtf32(buf, false);
    }
  }

  // 6. UTF-16 without BOM (alternating null bytes for ASCII chars)
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
    // UTF-16LE: nulls at odd indices
    if (nullOdds > sampleSize * 0.35 && nullEvens < sampleSize * 0.05) {
      return buf.toString('utf16le');
    }
    // UTF-16BE: nulls at even indices
    if (nullEvens > sampleSize * 0.35 && nullOdds < sampleSize * 0.05) {
      const swapped = Buffer.from(buf);
      swapped.swap16();
      return swapped.toString('utf16le');
    }
  }

  // 7. Content-based binary check: count non-printable control bytes vs printable text
  // Text with sparse NUL bytes (e.g. NUL byte in first 1 KB) is treated as text
  const checkLen = Math.min(buf.length, 8192);
  let controlCount = 0;
  for (let i = 0; i < checkLen; i++) {
    const b = buf[i];
    // Control bytes: 0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F (exclude \t=0x09, \n=0x0A, \r=0x0D)
    if ((b >= 0 && b <= 8) || b === 11 || b === 12 || (b >= 14 && b <= 31)) {
      controlCount++;
    }
  }

  // If control bytes are <= 15%, the file is predominantly text with minor binary/NUL artifacts
  if (controlCount <= checkLen * 0.15) {
    // Replace raw nulls with spaces so tokens across null boundaries can still be matched
    return buf.toString('utf8').replace(/\0/g, ' ');
  }

  // 8. Dense binary buffer (e.g. real image, binary database, compiled asset):
  // Extract printable string runs of length >= 8 so any embedded secrets are still inspected
  const rawStr = buf.toString('latin1');
  const printableRuns = rawStr.match(/[\x20-\x7E\t]{8,}/g);
  if (printableRuns && printableRuns.length > 0) {
    return printableRuns.join('\n');
  }

  return null;
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

    // Filter binary by extension only for non-text media/compiled formats
    if (NON_TEXT_EXTENSIONS.has(ext)) {
      skippedFiles.push({ path: relPath, reason: 'Binary file extension skipped' });
      continue;
    }

    candidatePaths.push(relPath);
  }

  if (candidatePaths.length === 0) {
    return { status: 'CLEAN', findings: [], skippedFiles, filesScanned: 0 };
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
      if (options?.ignoreSkipped !== false) {
        skippedFiles.push({
          path: p,
          reason: `File size (${(size / (1024 * 1024)).toFixed(1)}MB) exceeds ${maxMb}MB limit`,
        });
        continue;
      } else {
        return {
          status: 'ERROR',
          findings: [],
          error: `File '${p}' (${(size / (1024 * 1024)).toFixed(1)}MB) exceeds ${maxMb}MB limit. Use --ignore-skipped to bypass.`,
        };
      }
    }
    readablePaths.push(p);
  }

  if (readablePaths.length === 0) {
    return { status: 'CLEAN', findings: [], skippedFiles, filesScanned: 0 };
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
    return { status: 'CLEAN', findings: [], skippedFiles, filesScanned: 0 };
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
      if (addedLines.has(-1) || addedLines.has(finding.line)) {
        fileFindings.push(finding);
      }
    }
    if (fileFindings.length > 0) {
      allFindings.push(...fileFindings);
    } else {
      const ext = path.extname(relPath).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext) || ext === '.png') {
        skippedFiles.push({ path: relPath, reason: 'Binary file skipped' });
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

    if (ignorePatterns.some((pattern) => matchesIgnorePattern(relPath, pattern))) {
      continue;
    }

    if (NON_TEXT_EXTENSIONS.has(ext)) {
      skippedFiles.push({ path: relPath, reason: 'Binary file extension skipped' });
      continue;
    }

    candidatePaths.push(relPath);
  }

  if (candidatePaths.length === 0) {
    return { status: 'CLEAN', findings: [], skippedFiles, filesScanned: 0 };
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
      if (options?.ignoreSkipped !== false) {
        skippedFiles.push({
          path: p,
          reason: `File size (${(size / (1024 * 1024)).toFixed(1)}MB) exceeds ${maxMb}MB limit`,
        });
        continue;
      } else {
        return {
          status: 'ERROR',
          findings: [],
          error: `File '${p}' (${(size / (1024 * 1024)).toFixed(1)}MB) exceeds ${maxMb}MB limit. Use --ignore-skipped to bypass.`,
        };
      }
    }
    readablePaths.push(p);
  }

  if (readablePaths.length === 0) {
    return { status: 'CLEAN', findings: [], skippedFiles, filesScanned: 0 };
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
    return { status: 'CLEAN', findings: [], skippedFiles, filesScanned: 0 };
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
      if (addedLines.has(-1) || addedLines.has(finding.line)) {
        fileFindings.push(finding);
      }
    }
    if (fileFindings.length > 0) {
      allFindings.push(...fileFindings);
    } else {
      const ext = path.extname(relPath).toLowerCase();
      if (BINARY_EXTENSIONS.has(ext) || ext === '.png') {
        skippedFiles.push({ path: relPath, reason: 'Binary file skipped' });
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
