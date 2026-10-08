import * as crypto from 'crypto';

/**
 * Masks a secret string to prevent secondary leakage in logs, terminals, or dashboards.
 * Preserves initial prefix (e.g. 'AKIA', 'ghp_') and trailing characters when safe.
 */
export function redactSecret(secret: string): string {
  if (!secret) return '';

  const len = secret.length;
  if (len <= 8) {
    return '••••••••';
  }

  // Preserve up to 4 chars at beginning and 3 chars at end
  const prefixLen = Math.min(4, Math.floor(len / 4));
  const suffixLen = Math.min(3, Math.floor(len / 4));
  const maskLen = Math.max(4, len - prefixLen - suffixLen);

  const prefix = secret.substring(0, prefixLen);
  const suffix = secret.substring(len - suffixLen);
  const mask = '•'.repeat(Math.min(12, maskLen));

  return `${prefix}${mask}${suffix}`;
}

/**
 * Computes an anonymous deterministic SHA-256 fingerprint for a credential.
 * Allows tracking secrets across files, commits, and baselines without persisting plaintext.
 */
export function generateFingerprint(secret: string): string {
  return crypto.createHash('sha256').update(secret).digest('hex').substring(0, 16);
}
