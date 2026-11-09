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
  if (process.env.SLD_SALT || process.env.SLD_FINGERPRINT_SALT) {
    return { path: 'SLD_SALT environment variable', created: false };
  }

  const root = path.resolve(workspaceRoot || process.cwd());
  const saltDir = path.join(root, '.sld');
  const saltPath = path.join(saltDir, 'salt');

  try {
    fs.mkdirSync(saltDir, { recursive: true, mode: 0o700 });
  } catch (error: any) {
    throw new Error('Cannot create private fingerprint directory ' + saltDir + ': ' + (error.message || error));
  }

  let created = false;
  if (!fs.existsSync(saltPath)) {
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

  let value = '';
  try {
    value = fs.readFileSync(saltPath, 'utf8').trim();
  } catch (error: any) {
    throw new Error('Cannot read private fingerprint salt ' + saltPath + ': ' + (error.message || error));
  }
  if (value.length < PRIVATE_SALT_BYTES * 2) {
    throw new Error(
      'Private fingerprint salt ' + saltPath +
      ' must contain at least 32 random bytes (64 hex characters). Back up and replace the existing value.'
    );
  }

  try {
    if (process.platform === 'win32') {
      const identity = cp.execFileSync('whoami', [], { encoding: 'utf8', windowsHide: true }).trim();
      if (!identity) throw new Error('Could not identify the current Windows account.');
      cp.execFileSync('icacls', [saltPath, '/inheritance:r', '/grant:r', identity + ':(F)'], {
        encoding: 'utf8',
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } else {
      fs.chmodSync(saltDir, 0o700);
      fs.chmodSync(saltPath, 0o600);
      const mode = fs.statSync(saltPath).mode & 0o777;
      if ((mode & 0o077) !== 0) {
        throw new Error('Unsafe permissions remain on salt file (mode ' + mode.toString(8) + ').');
      }
    }
  } catch (error: any) {
    throw new Error('Cannot enforce private fingerprint salt permissions: ' + (error.message || error));
  }

  return { path: saltPath, created };
}

/**
 * Resolves the private fingerprint key: explicit key > SLD_SALT env > ignored
 * repository-local .sld/salt file. A private random salt is initialized when
 * no key is configured; the legacy public salt is never used for new hashes.
 */
export function resolveSalt(customSalt?: string, workspaceRoot?: string): string {
  if (customSalt) return customSalt;
  const envSalt = process.env.SLD_SALT || process.env.SLD_FINGERPRINT_SALT;
  if (envSalt) return envSalt;

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
