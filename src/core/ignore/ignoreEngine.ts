import * as fs from 'fs';
import * as path from 'path';

/**
 * Extensions for pure non-text binary formats that cannot hold readable text.
 * Files with ambiguous extensions (e.g. .png, .bin, .pkl, .sqlite) are NOT skipped
 * by extension; their actual contents are inspected so text disguised as binary is caught.
 */
export const BINARY_EXTENSIONS = new Set([
  '.exe', '.dll', '.so', '.dylib', '.iso', '.dmg',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.wav',
  '.pyc', '.pyo', '.class',
  '.o', '.obj', '.lib', '.a',
  '.wasm', '.pkl', '.npy', '.parquet', '.onnx', '.safetensors',
]);

export const DEFAULT_IGNORE_PATTERNS = [
  '**/node_modules/**',
  'node_modules/**',
  '**/.git/**',
  '.git/**',
  'dist/**',
  'build/**',
  'package-lock.json',
  '**/package-lock.json',
  'pnpm-lock.yaml',
  '**/pnpm-lock.yaml',
  'yarn.lock',
  '**/yarn.lock',
  'bun.lockb',
  '**/bun.lockb',
];

const ignorePatternsCache = new Map<string, string[]>();

export function clearIgnorePatternsCache(): void {
  ignorePatternsCache.clear();
}

/**
 * Loads .sldignore patterns safely.
 *
 * Anti-Tamper CI Guardrail:
 * In CI environments (e.g. GitHub Actions / GitLab CI), ignore patterns MUST be loaded
 * from the trusted base branch ref (e.g. origin/main) so PR authors cannot introduce a
 * rogue .sldignore or bypass scanner gates. In CI, we NEVER fall back to HEAD or working tree.
 */
export function loadIgnorePatterns(rootDir: string): string[] {
  const normalizedRoot = path.resolve(rootDir).replace(/\\/g, '/');
  if (ignorePatternsCache.has(normalizedRoot)) {
    return ignorePatternsCache.get(normalizedRoot)!;
  }

  const isCI = !!(process.env.CI || process.env.GITHUB_ACTIONS || process.env.GITLAB_CI);

  if (isCI) {
    try {
      const { execFileSync } = require('child_process');
      const baseRef = process.env.GITHUB_BASE_REF || process.env.CI_MERGE_REQUEST_TARGET_BRANCH_NAME;
      // In CI, only trust base branch refs. NEVER fall back to HEAD or working tree.
      const candidateRefs = baseRef
        ? [`origin/${baseRef}`, `refs/remotes/origin/${baseRef}`, baseRef]
        : ['origin/main', 'origin/master'];

      for (const ref of candidateRefs) {
        try {
          const content = execFileSync('git', ['show', `${ref}:.sldignore`], {
            cwd: rootDir,
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore'],
          });
          if (content) {
            const patterns = content
              .split(/\r?\n/)
              .map((line: string) => line.trim())
              .filter((line: string) => line.length > 0 && !line.startsWith('#'));
            ignorePatternsCache.set(normalizedRoot, patterns);
            return patterns;
          }
        } catch {}
      }
      // If base branch lacks .sldignore in CI, no custom ignores are trusted
      ignorePatternsCache.set(normalizedRoot, []);
      return [];
    } catch {
      ignorePatternsCache.set(normalizedRoot, []);
      return [];
    }
  }

  // Local development: read from working tree
  const sldIgnorePath = path.join(rootDir, '.sldignore');
  if (fs.existsSync(sldIgnorePath)) {
    try {
      const content = fs.readFileSync(sldIgnorePath, 'utf8');
      const patterns = content
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line.length > 0 && !line.startsWith('#'));
      ignorePatternsCache.set(normalizedRoot, patterns);
      return patterns;
    } catch {}
  }
  ignorePatternsCache.set(normalizedRoot, []);
  return [];
}

/**
 * Compiles a glob pattern into a regular expression adhering to gitignore semantics.
 * Tokenizes patterns to avoid regex corruption of '**' vs '*'.
 */
export function globToRegex(pattern: string): RegExp {
  let p = pattern.trim().replace(/\\/g, '/');

  // Handle directory-only patterns: e.g. 'dist/' or 'build/'
  let matchDir = false;
  if (p.endsWith('/')) {
    matchDir = true;
    p = p.slice(0, -1);
  }

  // Track if pattern is anchored to root
  const hadLeadingSlash = p.startsWith('/');
  if (hadLeadingSlash) {
    p = p.slice(1);
  }

  let regex = '';
  let i = 0;
  while (i < p.length) {
    if (p.slice(i, i + 4) === '/**/') {
      regex += '(?:/|/.*/)';
      i += 4;
    } else if (p.slice(i, i + 3) === '/**') {
      regex += '(/.*)?';
      i += 3;
    } else if (p.slice(i, i + 3) === '**/') {
      regex += '(?:^|.*/)';
      i += 3;
    } else if (p.slice(i, i + 2) === '**') {
      regex += '.*';
      i += 2;
    } else if (p[i] === '*') {
      regex += '[^/]*';
      i += 1;
    } else if (p[i] === '?') {
      regex += '[^/]';
      i += 1;
    } else if (['.', '+', '^', '$', '(', ')', '[', ']', '{', '}', '|'].includes(p[i])) {
      regex += '\\' + p[i];
      i += 1;
    } else {
      regex += p[i];
      i += 1;
    }
  }

  if (matchDir) {
    if (hadLeadingSlash || p.includes('/')) {
      return new RegExp('^' + regex + '(/.*)?$');
    }
    return new RegExp('(?:^|/)' + regex + '(/.*)?$');
  }

  if (!p.includes('/') && !hadLeadingSlash) {
    return new RegExp('(?:^|/)' + regex + '$');
  }

  return new RegExp('^' + regex + '$');
}

/**
 * Checks if a relative path matches a glob pattern or path segment.
 */
export function matchesIgnorePattern(relPath: string, pattern: string): boolean {
  const normRel = relPath.replace(/\\/g, '/').replace(/^\/+/, '');
  let normPat = pattern.trim().replace(/\\/g, '/');
  if (!normPat || normPat.startsWith('#')) return false;

  // Exact relative path match
  if (normRel === normPat) return true;

  // Directory prefix match: e.g. "dist" or "dist/" matches "dist/bundle.js"
  const isAnchored = normPat.startsWith('/');
  const cleanPat = isAnchored ? normPat.slice(1) : normPat;
  const dirPat = cleanPat.endsWith('/') ? cleanPat.slice(0, -1) : cleanPat;

  if (!cleanPat.includes('*')) {
    if (isAnchored || cleanPat.includes('/')) {
      if (normRel === dirPat || normRel.startsWith(dirPat + '/')) return true;
    } else {
      if (normRel === dirPat || normRel.startsWith(dirPat + '/') || normRel.includes('/' + dirPat + '/')) return true;
    }
  }

  try {
    const re = globToRegex(normPat);
    return re.test(normRel);
  } catch {
    return false;
  }
}
