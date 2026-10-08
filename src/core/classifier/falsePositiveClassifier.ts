/**
 * False-Positive & Placeholder Suppression Engine
 * Filters out benign documentation examples, test mocks, repetitive filler, and UUIDs.
 */

const KNOWN_PLACEHOLDER_REGEXES = [
  /example/i,
  /placeholder/i,
  /your[_-]?(?:api)?[_-]?key/i,
  /your[_-]?secret/i,
  /your[_-]?token/i,
  /insert[_-]?here/i,
  /replace[_-]?me/i,
  /enter[_-]?your/i,
  /change[_-]?me/i,
  /dummy/i,
  /fake[_-]?token/i,
  /xxxx+/i,
  /test[_-]?value/i,
  /AKIAIOSFODNN7EXAMPLE/i,
  /wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY/i,
  /^123456789[0-9]*$/,
  /^abcdef[a-z0-9]*$/i,
  /00000000[0-9]*/,
  /sk_live_example/i,
  /ghp_example/i,
];

// Pure UUID v4 regex: e7b1a290-2c3d-4e5f-8a1b-9c8d7e6f5a4b
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface FalsePositiveCheck {
  isFalsePositive: boolean;
  reason?: string;
  confidencePenalty: number;
}

/**
 * Checks if a candidate secret is an explicit placeholder or benign dummy value.
 */
export function evaluateFalsePositive(
  secret: string,
  inferredVarName?: string,
  filePath?: string
): FalsePositiveCheck {
  // Check exact placeholders in secret value
  for (const pattern of KNOWN_PLACEHOLDER_REGEXES) {
    if (pattern.test(secret)) {
      return {
        isFalsePositive: true,
        reason: `Matched known documentation/placeholder pattern: ${pattern.source}`,
        confidencePenalty: 100,
      };
    }
  }

  // Check if variable name indicates an example or placeholder
  if (inferredVarName) {
    for (const pattern of KNOWN_PLACEHOLDER_REGEXES) {
      if (pattern.test(inferredVarName)) {
        return {
          isFalsePositive: true,
          reason: `Variable identifier indicates placeholder: ${inferredVarName}`,
          confidencePenalty: 100,
        };
      }
    }
  }

  // Check for repetitive characters (e.g. "aaaaaaaaaaaa" or "0000000000")
  const uniqueChars = new Set(secret.split('')).size;
  if (secret.length >= 10 && uniqueChars <= 3) {
    return {
      isFalsePositive: true,
      reason: 'Low character diversity (repetitive filler characters)',
      confidencePenalty: 95,
    };
  }

  // Pure UUID without sensitive variable context
  if (UUID_REGEX.test(secret) && !inferredVarName?.match(/secret|token|api_?key/i)) {
    return {
      isFalsePositive: true,
      reason: 'Standard UUID identifier without credential context',
      confidencePenalty: 90,
    };
  }

  // Check file context penalties
  if (filePath) {
    const isDoc = /(?:docs|documentation|tutorials|guides)\/|readme\.md/i.test(filePath);
    const isExampleFile = /(?:example|sample|\.example|\.sample)/i.test(filePath);
    if (isExampleFile && /example|your_/i.test(secret)) {
      return {
        isFalsePositive: true,
        reason: 'Sample configuration value inside template/example file',
        confidencePenalty: 90,
      };
    }
    if (isDoc && !secret.startsWith('ghp_') && !secret.startsWith('AKIA')) {
      return {
        isFalsePositive: false,
        confidencePenalty: 25,
      };
    }
  }

  return {
    isFalsePositive: false,
    confidencePenalty: 0,
  };
}
