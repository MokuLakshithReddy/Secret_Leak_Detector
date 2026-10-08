/**
 * Shannon Entropy and Character Distribution Engine
 * Evaluates the unpredictability and cryptographic randomness of strings.
 */

/**
 * Calculates raw Shannon entropy in bits per character.
 * Formula: H = -sum(p_i * log2(p_i))
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const frequencies: Record<string, number> = {};
  for (const char of str) {
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;

  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }

  return Math.round(entropy * 100) / 100;
}

/**
 * Determines the character set family of a credential candidate.
 */
export function detectCharacterSet(str: string): {
  setName: 'HEX' | 'BASE64' | 'ALPHANUMERIC' | 'ASCII_PRINTABLE' | 'SPECIAL';
  baseSize: number;
} {
  if (/^[0-9a-fA-F]+$/.test(str)) {
    return { setName: 'HEX', baseSize: 16 };
  }
  if (/^[A-Za-z0-9+/=_-]+$/.test(str)) {
    return { setName: 'BASE64', baseSize: 64 };
  }
  if (/^[A-Za-z0-9]+$/.test(str)) {
    return { setName: 'ALPHANUMERIC', baseSize: 62 };
  }
  if (/^[\x20-\x7E]+$/.test(str)) {
    return { setName: 'ASCII_PRINTABLE', baseSize: 95 };
  }
  return { setName: 'SPECIAL', baseSize: 128 };
}

/**
 * Calculates normalized Shannon entropy relative to maximum possible entropy
 * for the string's character set. (Returns 0.0 - 1.0).
 */
export function calculateNormalizedEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const rawEntropy = calculateShannonEntropy(str);
  const { baseSize } = detectCharacterSet(str);
  const maxPossible = Math.log2(baseSize);

  if (maxPossible <= 0) return 0;
  const normalized = Math.min(1, rawEntropy / maxPossible);
  return Math.round(normalized * 100) / 100;
}

/**
 * Tests if string has sufficient entropy to be considered an authentic credential.
 */
export function isHighEntropy(str: string, threshold = 3.4): boolean {
  return calculateShannonEntropy(str) >= threshold;
}
