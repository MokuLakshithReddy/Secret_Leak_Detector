import * as crypto from 'crypto';

/**
 * Safely masks secret values so they never appear unredacted in UI or terminal logs.
 * Example: "AKIA1234567890ABCDEF" -> "AKIA************CDEF"
 */
export function redactSecret(secret: string): string {
  if (!secret) return '[EMPTY]';
  const len = secret.length;

  if (len <= 8) {
    return '***[REDACTED]***';
  }

  // Preserve prefix if known
  const prefixLength = Math.min(4, Math.floor(len * 0.25));
  const suffixLength = Math.min(4, Math.floor(len * 0.25));
  const maskedLength = len - prefixLength - suffixLength;

  return (
    secret.substring(0, prefixLength) +
    '*'.repeat(Math.max(4, maskedLength)) +
    secret.substring(len - suffixLength)
  );
}

/**
 * Creates an anonymous HMAC/SHA-256 fingerprint of the secret
 * to track blast radius across git commits and files without storing plaintext.
 */
export function generateFingerprint(secret: string): string {
  const hash = crypto.createHash('sha256').update(secret).digest('hex');
  return `fp:${hash.substring(0, 16)}`;
}
