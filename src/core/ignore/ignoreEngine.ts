import * as fs from 'fs';
import * as path from 'path';

export const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.webp', '.tiff', '.tif',
  '.pdf', '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.iso', '.dmg',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv',
  '.pyc', '.pyo', '.class', '.jar', '.war',
  '.sqlite', '.db', '.dat',
]);

export const DEFAULT_IGNORE_PATTERNS = [
  '**/node_modules/**',
  'node_modules/**',
  '**/.git/**',
  '.git/**',
  '**/dist/**',
  'dist/**',
  '**/build/**',
  'build/**',
  '**/*.min.js',
  '*.min.js',
  '**/*.lock',
  '*.lock',
  '**/package-lock.json',
  'package-lock.json',
  '**/pnpm-lock.yaml',
  'pnpm-lock.yaml',
];

/**
 * Loads .sldignore patterns safely.
 *
 * Anti-Tamper CI Guardrail:
 * In CI environments (e.g. GitHub Actions / GitLab CI), ignore patterns MUST be loaded
 * from the trusted base branch ref (e.g. origin/main) so PR authors cannot introduce a
 * rogue .sldignore or bypass scanner gates. In CI, we NEVER fall back to HEAD or working tree.
 */
export function loadIgnorePatterns(rootDir: string): string[] {
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
            return content
              .split(/\r?\n/)
              .map((line: string) => line.trim())
              .filter((line: string) => line.length > 0 && !line.startsWith('#'));
          }
        } catch {}
      }
      // If base branch lacks .sldignore in CI, no custom ignores are trusted
      return [];
    } catch {
      return [];
    }
  }

  // Local development: read from working tree
  const sldIgnorePath = path.join(rootDir, '.sldignore');
  if (fs.existsSync(sldIgnorePath)) {
    try {
      const content = fs.readFileSync(sldIgnorePath, 'utf8');
      return content
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter((line) => line.length > 0 && !line.startsWith('#'));
    } catch {}
  }
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

  // Strip leading slash if any
  if (p.startsWith('/')) {
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
    return new RegExp('(?:^|/)' + regex + '(/.*)?$');
  }

  if (!p.includes('/')) {
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

  // Directory prefix match: e.g. "dist" matches "dist/bundle.js"
  const dirPat = normPat.endsWith('/') ? normPat.slice(0, -1) : normPat;
  if (normRel === dirPat || normRel.startsWith(dirPat + '/')) return true;

  try {
    const re = globToRegex(normPat);
    return re.test(normRel);
  } catch {
    return false;
  }
}
