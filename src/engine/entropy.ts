/**
 * Calculates Shannon Entropy of a string in bits per character.
 * High entropy indicates random strings (like cryptographic secrets or API tokens),
 * while low entropy indicates predictable English words or simple variable names.
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) {
    return 0;
  }

  const frequencies: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
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
 * Evaluates whether a string meets secret randomness criteria.
 */
export function isHighEntropy(str: string, threshold = 3.4): boolean {
  return calculateShannonEntropy(str) >= threshold;
}
