import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import * as cp from 'child_process';

/**
 * Historical v1 baseline fingerprints used this source-controlled salt.
 * It is retained only to recognize old baselines during migration; new
 * fingerprints never use it.
 */
const LEGACY_PUBLIC_FINGERPRINT_SALT = 'sld_fingerprint_salt_v1_d8e9f2a1b4c3e7f0';
const PRIVATE_SALT_BYTES = 32;

function validatePrivateSalt(value: string, source: string): string {
  const normalized = value.trim();
  if (normalized.length < PRIVATE_SALT_BYTES * 2) {
    throw new Error(source + ' must contain at least 64 characters (32 bytes of key material). Generate a new 256-bit salt with "secret-leak-detector salt init".');
  }
  return normalized;
}

export interface PrivateSaltInitialization {
  path: string;
  created: boolean;
}

/**
 * Creates or verifies a repository-local private salt at .sld/salt.
 * The directory and file are owner-only on POSIX; Windows ACL inheritance is
 * removed and full control is granted only to the current account.
 */
export function initializePrivateSalt(workspaceRoot: string): PrivateSaltInitialization {
  const envSalt = process.env.SLD_SALT || process.env.SLD_FINGERPRINT_SALT;
  if (envSalt) {
    validatePrivateSalt(envSalt, 'SLD_SALT');
    return { path: 'SLD_SALT environment variable', created: false };
  }

  const root = path.resolve(workspaceRoot || process.cwd());
  const saltDir = path.join(root, '.sld');
  const saltPath = path.join(saltDir, 'salt');

  let rootReal: string;
  try {
    rootReal = fs.realpathSync(root);
  } catch (error: any) {
    throw new Error('Cannot resolve workspace root for private fingerprint salt: ' + (error.message || error));
  }

  // Never follow repository-controlled symlinks for key storage: a malicious
  // checkout must not redirect key creation, reading, or chmod outside the repo.
  try {
    const dirStat = fs.lstatSync(saltDir);
    if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
      throw new Error("The '.sld' fingerprint directory must be a real directory, not a symlink.");
    }
  } catch (error: any) {
    if (error?.code !== 'ENOENT') {
      throw new Error('Unsafe private fingerprint directory: ' + (error.message || error));
    }
    try {
      fs.mkdirSync(saltDir, { recursive: false, mode: 0o700 });
    } catch (mkdirError: any) {
      throw new Error('Cannot create private fingerprint directory ' + saltDir + ': ' + (mkdirError.message || mkdirError));
    }
  }

  let saltDirStat: fs.Stats;
  let saltDirReal: string;
  try {
    saltDirStat = fs.lstatSync(saltDir);
    saltDirReal = fs.realpathSync(saltDir);
  } catch (error: any) {
    throw new Error('Cannot validate private fingerprint directory: ' + (error.message || error));
  }
  if (saltDirStat.isSymbolicLink() || !saltDirStat.isDirectory()) {
    throw new Error("The '.sld' fingerprint directory must not be a symlink.");
  }
  const dirRelative = path.relative(rootReal, saltDirReal);
  if (dirRelative === '..' || dirRelative.startsWith('..' + path.sep) || path.isAbsolute(dirRelative)) {
    throw new Error('Private fingerprint directory resolves outside the workspace root.');
  }

  // Harden the containing directory before creating any key material. On
  // Windows a new directory otherwise inherits the parent ACL until changed.
  try {
    if (process.platform === 'win32') {
      const identity = cp.execFileSync('whoami', [], { encoding: 'utf8', windowsHide: true }).trim();
      if (!identity) throw new Error('Could not identify the current Windows account.');
      cp.execFileSync('icacls', [saltDir, '/reset'], {
        encoding: 'utf8',
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      cp.execFileSync('icacls', [saltDir, '/inheritance:r', '/grant:r', identity + ':(OI)(CI)F'], {
        encoding: 'utf8',
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } else {
      fs.chmodSync(saltDir, 0o700);
      const dirMode = fs.statSync(saltDir).mode & 0o777;
      if ((dirMode & 0o077) !== 0) {
        throw new Error('Unsafe permissions remain on salt directory (mode ' + dirMode.toString(8) + ').');
      }
    }
  } catch (error: any) {
    throw new Error('Cannot enforce private fingerprint directory permissions: ' + (error.message || error));
  }

  let saltStat: fs.Stats | null = null;
  try {
    saltStat = fs.lstatSync(saltPath);
    if (saltStat.isSymbolicLink() || !saltStat.isFile() || saltStat.nlink > 1) {
      throw new Error('The private fingerprint salt must be a regular, non-symlink file with a single hard link.');
    }
  } catch (error: any) {
    if (error?.code !== 'ENOENT') {
      throw new Error('Unsafe private fingerprint salt path: ' + (error.message || error));
    }
  }

  let created = false;
  if (!saltStat) {
    const generated = crypto.randomBytes(PRIVATE_SALT_BYTES).toString('hex');
    try {
      fs.writeFileSync(saltPath, generated + '\n', {
        encoding: 'utf8',
        flag: 'wx',
        mode: 0o600,
      });
      created = true;
    } catch (error: any) {
      // Another process may have initialized the repository salt concurrently.
      if (error?.code !== 'EEXIST') {
        throw new Error('Cannot write private fingerprint salt ' + saltPath + ': ' + (error.message || error));
      }
    }
  }

  // Restrict both the directory and key before reading key material. On Windows,
  // reset existing explicit/inherited entries first, then grant access only to the
  // current account; the key file receives its own non-inheriting ACL.
  try {
    if (process.platform === 'win32') {
      const identity = cp.execFileSync('whoami', [], { encoding: 'utf8', windowsHide: true }).trim();
      if (!identity) throw new Error('Could not identify the current Windows account.');
      cp.execFileSync('icacls', [saltPath, '/reset'], {
        encoding: 'utf8',
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      cp.execFileSync('icacls', [saltPath, '/inheritance:r', '/grant:r', identity + ':F'], {
        encoding: 'utf8',
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } else {
      fs.chmodSync(saltPath, 0o600);
      const fileMode = fs.statSync(saltPath).mode & 0o777;
      if ((fileMode & 0o077) !== 0) {
        throw new Error('Unsafe permissions remain on salt file (mode ' + fileMode.toString(8) + ').');
      }
    }
  } catch (error: any) {
    throw new Error('Cannot enforce private fingerprint salt permissions: ' + (error.message || error));
  }

  let value = '';
  let saltFileStat: fs.Stats;
  try {
    saltFileStat = fs.lstatSync(saltPath);
    if (saltFileStat.isSymbolicLink() || !saltFileStat.isFile() || saltFileStat.nlink > 1) {
      throw new Error('The private fingerprint salt must be a regular, non-symlink file with a single hard link.');
    }
    const saltReal = fs.realpathSync(saltPath);
    const saltRelative = path.relative(saltDirReal, saltReal);
    if (saltRelative !== 'salt') {
      throw new Error('Private fingerprint salt resolves outside its expected workspace path.');
    }

    // O_NOFOLLOW prevents a final-component symlink swap on POSIX platforms.
    const noFollow = process.platform === 'win32' ? 0 : (fs.constants.O_NOFOLLOW || 0);
    const fd = fs.openSync(saltPath, fs.constants.O_RDONLY | noFollow);
    try {
      const openedStat = fs.fstatSync(fd);
      if (!openedStat.isFile() || openedStat.nlink > 1) {
        throw new Error('Opened fingerprint salt is not a private regular file.');
      }
      value = fs.readFileSync(fd, 'utf8').trim();
      saltFileStat = openedStat;
    } finally {
      fs.closeSync(fd);
    }
  } catch (error: any) {
    throw new Error('Cannot safely read private fingerprint salt ' + saltPath + ': ' + (error.message || error));
  }
  validatePrivateSalt(value, 'Private fingerprint salt ' + saltPath);

  return { path: saltPath, created };
}

/**
 * Resolves the private fingerprint key: explicit key > SLD_SALT env > ignored
 * repository-local .sld/salt file. A private random salt is initialized when
 * no key is configured; the legacy public salt is never used for new hashes.
 */
export function resolveSalt(customSalt?: string, workspaceRoot?: string): string {
  if (customSalt) return validatePrivateSalt(customSalt, 'Custom fingerprint salt');
  const envSalt = process.env.SLD_SALT || process.env.SLD_FINGERPRINT_SALT;
  if (envSalt) return validatePrivateSalt(envSalt, 'SLD_SALT');

  const root = workspaceRoot || process.cwd();
  const initialized = initializePrivateSalt(root);
  return fs.readFileSync(initialized.path, 'utf8').trim();
}

/** A non-secret key identifier used to reject baselines created with another private key. */
export function getFingerprintKeyId(workspaceRoot?: string): string {
  return crypto.createHash('sha256').update(resolveSalt(undefined, workspaceRoot)).digest('hex').substring(0, 16);
}

/**
 * Computes an old v1 fingerprint only for matching baselines that predate
 * fingerprintScheme metadata. Never use this function to create new findings.
 */
export function generateLegacyFingerprint(secret: string, canonicalizeLineEndings = true): string {
  const candidate = canonicalizeLineEndings ? secret.replace(/\r\n/g, '\n') : secret;
  return crypto
    .createHmac('sha256', LEGACY_PUBLIC_FINGERPRINT_SALT)
    .update(candidate)
    .digest('hex')
    .substring(0, 16);
}

/**
 * Masks a secret string to prevent secondary leakage in logs, terminals, or dashboards.
 * Strict privacy rule:
 * - Secrets <= 12 characters are masked completely (0% revealed).
 * - Secrets > 12 characters reveal at most 20% of total characters, split between prefix and suffix.
 */
export function redactSecret(secret: string): string {
  if (!secret) return '';

  const len = secret.length;
  if (len <= 12) {
    return '••••••••';
  }

  const maxExposed = Math.max(2, Math.floor(len * 0.20));
  const prefixLen = Math.min(4, Math.max(1, Math.floor(maxExposed / 2)));
  const suffixLen = Math.min(3, Math.max(1, maxExposed - prefixLen));
  const maskLen = Math.max(6, Math.min(16, len - prefixLen - suffixLen));

  const prefix = secret.substring(0, prefixLen);
  const suffix = secret.substring(len - suffixLen);
  const mask = '•'.repeat(maskLen);

  return prefix + mask + suffix;
}

/** Computes a deterministic fingerprint using the private repository key. */
export function generateFingerprint(secret: string, customSalt?: string, workspaceRoot?: string): string {
  const salt = resolveSalt(customSalt, workspaceRoot);
  const canonicalSecret = secret.replace(/\r\n/g, '\n');
  return crypto.createHmac('sha256', salt).update(canonicalSecret).digest('hex').substring(0, 16);
}
