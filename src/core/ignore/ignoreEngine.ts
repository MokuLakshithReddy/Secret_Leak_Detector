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
  '**/.git/**',
  '**/dist/**',
  '**/build/**',
  '**/*.min.js',
  '**/*.lock',
  '**/package-lock.json',
  '**/pnpm-lock.yaml',
];

export function loadIgnorePatterns(rootDir: string): string[] {
  const sldIgnorePath = path.join(rootDir, '.sldignore');

  if (process.env.CI) {
    try {
      const { execFileSync } = require('child_process');
      const baseRef = process.env.GITHUB_BASE_REF || process.env.CI_MERGE_REQUEST_TARGET_BRANCH_NAME;
      const candidateRefs = [
        ...(baseRef ? [`origin/${baseRef}`, baseRef, `refs/remotes/origin/${baseRef}`] : []),
        'HEAD',
      ];
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
    } catch {}
  }

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

export function matchesIgnorePattern(relPath: string, pattern: string): boolean {
  const normRel = relPath.replace(/\\/g, '/').replace(/^\/+/, '');
  let normPat = pattern.trim().replace(/\\/g, '/');
  if (!normPat || normPat.startsWith('#')) return false;

  const isDirOnly = normPat.endsWith('/');
  if (isDirOnly) {
    normPat = normPat.slice(0, -1);
  }

  // Exact relative path match
  if (normRel === normPat) return true;

  // Directory prefix match: e.g. "dist" matches "dist/bundle.js"
  if (normRel.startsWith(normPat + '/')) return true;

  // Wildcard glob match: *.ts, test/**, etc.
  if (normPat.includes('*') || normPat.includes('?')) {
    if (!normPat.includes('/')) {
      const filename = path.basename(normRel);
      const regexStr = '^' + normPat
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*/g, '.*')
        .replace(/\?/g, '.') + '$';
      return new RegExp(regexStr).test(filename);
    } else {
      const regexStr = '^' + normPat
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*\*/g, '.*')
        .replace(/\*/g, '[^/]*')
        .replace(/\?/g, '[^/]') + '$';
      return new RegExp(regexStr).test(normRel);
    }
  }

  // Exact segment match: e.g. "env" matches segment "env" in "config/env/file"
  const segments = normRel.split('/');
  if (!normPat.includes('/')) {
    return segments.includes(normPat);
  }

  return false;
}
