import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

const FINGERPRINT_DOMAIN_SALT = 'sld_fingerprint_salt_v1_d8e9f2a1b4c3e7f0';

/**
 * Resolves HMAC salt using hierarchy: explicit salt > SLD_SALT env > .sld/salt file > default domain salt.
 */
export function resolveSalt(customSalt?: string, workspaceRoot?: string): string {
  if (customSalt) return customSalt;
  if (process.env.SLD_SALT || process.env.SLD_FINGERPRINT_SALT) {
    return process.env.SLD_SALT || process.env.SLD_FINGERPRINT_SALT!;
  }
  const root = workspaceRoot || process.cwd();
  try {
    const saltFile = path.join(root, '.sld', 'salt');
    if (fs.existsSync(saltFile)) {
      const readSalt = fs.readFileSync(saltFile, 'utf8').trim();
      if (readSalt) return readSalt;
    }
  } catch {}
  return FINGERPRINT_DOMAIN_SALT;
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

  // Cap total exposed characters to at most 20% of secret length
  const maxExposed = Math.max(2, Math.floor(len * 0.20));
  const prefixLen = Math.min(4, Math.max(1, Math.floor(maxExposed / 2)));
  const suffixLen = Math.min(3, Math.max(1, maxExposed - prefixLen));
  const maskLen = Math.max(6, Math.min(16, len - prefixLen - suffixLen));

  const prefix = secret.substring(0, prefixLen);
  const suffix = secret.substring(len - suffixLen);
  const mask = '•'.repeat(maskLen);

  return `${prefix}${mask}${suffix}`;
}

/**
 * Computes an anonymous deterministic HMAC-SHA-256 fingerprint for a credential.
 *
 * Security & Guessability Design Note:
 * Baseline fingerprints are deterministic identifiers used for tracking and cross-scan
 * deduplication across developer machines and CI pipelines. Because the default domain salt
 * is standardized across installations so that team-committed baseline files remain portable,
 * fingerprints for known low-entropy strings (e.g. "password123") could theoretically be
 * dictionary-guessed if an attacker accesses both the source code and baseline file.
 *
 * For high-security environments requiring non-guessable private tracking, configure an optional
 * per-repository private salt via the `SLD_SALT` environment variable.
 */
export function generateFingerprint(secret: string, customSalt?: string, workspaceRoot?: string): string {
  const salt = resolveSalt(customSalt, workspaceRoot);
  // Canonicalize line endings (CRLF -> LF) to ensure deterministic fingerprints
  // for multiline secrets (e.g. PEM private keys) across Windows, macOS, and Linux.
  const canonicalSecret = secret.replace(/\r\n/g, '\n');
  return crypto
    .createHmac('sha256', salt)
    .update(canonicalSecret)
    .digest('hex')
    .substring(0, 16);
}
