import * as crypto from 'crypto';

const FINGERPRINT_DOMAIN_SALT = 'sld_fingerprint_salt_v1_d8e9f2a1b4c3e7f0';

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
 * Computes an anonymous deterministic HMAC-SHA-256 fingerprint for a credential
 * using a fixed domain salt. This prevents rainbow table or dictionary reconstruction
 * of weak secrets from baseline files while maintaining stable identity across scans.
 */
export function generateFingerprint(secret: string): string {
  return crypto
    .createHmac('sha256', FINGERPRINT_DOMAIN_SALT)
    .update(secret)
    .digest('hex')
    .substring(0, 16);
}
