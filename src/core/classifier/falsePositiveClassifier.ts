import { calculateShannonEntropy } from '../entropy/entropy';

/**
 * False-Positive & Placeholder Suppression Engine
 * Filters out benign documentation examples, test mocks, repetitive filler, and UUIDs.
 */

const KNOWN_PLACEHOLDER_REGEXES = [
  /\bplaceholder\b/i,
  /\byour[_-]?(?:api)?[_-]?key\b/i,
  /\byour[_-]?secret\b/i,
  /\byour[_-]?token\b/i,
  /\binsert[_-]?here\b/i,
  /\breplace[_-]?me\b/i,
  /\benter[_-]?your\b/i,
  /\bchange[_-]?me\b/i,
  /\bdummy\b/i,
  /\bfake[_-]?token\b/i,
  /xxxx+/i,
  /\btest[_-]?value\b/i,
  /AKIAIOSFODNN7EXAMPLE/i,
  /wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY/i,
  /^123456789[0-9]*$/,
  /^abcdef[a-z0-9]*$/i,
  /00000000[0-9]*/,
  /sk_live_example/i,
  /ghp_example/i,
  /:\/\/[^:]+:(?:password|secret|changeme|pass|admin|test|postgres|root)@(?:localhost|127\.0\.0\.1)(?::\d+)?\b/i,
  /:\/\/(?:postgres|root):(postgres|root)@(?:localhost|127\.0\.0\.1)(?::\d+)?\b/i,
];

// Pure UUID v4 regex: e7b1a290-2c3d-4e5f-8a1b-9c8d7e6f5a4b
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const MOCK_VAR_REGEX = /^(?:mock|dummy|placeholder|fake|sample)_(?:key|token|secret|password|pwd|cred)$/i;

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
  if (/(?:process\.env|import\.meta\.env|os\.environ|ENV[\[\.])/.test(secret)) {
    return {
      isFalsePositive: true,
      reason: 'Environment variable lookup expression, not a hard-coded credential literal',
      confidencePenalty: 100,
    };
  }

  if (/^(?:passwordRequired|required_field|required|optional|placeholder|changeme|default|test|dummy|example|string|undefined|null)$/i.test(secret)) {
    return {
      isFalsePositive: true,
      reason: 'Common non-secret schema or form attribute value',
      confidencePenalty: 100,
    };
  }

  for (const pattern of KNOWN_PLACEHOLDER_REGEXES) {
    if (pattern.test(secret)) {
      return {
        isFalsePositive: true,
        reason: `Matched known documentation/placeholder pattern: ${pattern.source}`,
        confidencePenalty: 100,
      };
    }
  }

  // Check if variable name indicates an explicit mock/dummy key (not generic words in identifiers).
  // CRITICAL SECURITY FIX: Never suppress live-format tokens (Stripe, Slack, GitHub, AWS, etc.)
  // or high-entropy credentials just because a developer or adversary named the variable "mock_*" or "fake_*".
  if (inferredVarName && MOCK_VAR_REGEX.test(inferredVarName)) {
    const isRealTokenFormat =
      secret.startsWith('AKIA') ||
      secret.startsWith('ASIA') ||
      secret.startsWith('ghp_') ||
      secret.startsWith('gho_') ||
      secret.startsWith('ghu_') ||
      secret.startsWith('ghs_') ||
      secret.startsWith('ghr_') ||
      secret.startsWith('github_pat_') ||
      secret.startsWith('glpat-') ||
      secret.startsWith('sk_live_') ||
      secret.startsWith('rk_live_') ||
      secret.startsWith('xoxb-') ||
      secret.startsWith('xoxp-') ||
      secret.startsWith('xoxa-') ||
      secret.startsWith('xoxr-') ||
      secret.startsWith('pypi-') ||
      secret.startsWith('dop_v1_') ||
      secret.startsWith('shpat_') ||
      secret.startsWith('shpca_') ||
      secret.startsWith('shppa_') ||
      secret.startsWith('ya29.') ||
      secret.startsWith('key-') ||
      secret.startsWith('sq0atp-') ||
      secret.startsWith('sq0csp-') ||
      /^SK[0-9a-fA-F]{32}$/.test(secret) ||
      secret.includes('-----BEGIN') ||
      (secret.length >= 14 && calculateShannonEntropy(secret) >= 3.6);

    if (!isRealTokenFormat) {
      return {
        isFalsePositive: true,
        reason: `Variable identifier indicates placeholder: ${inferredVarName}`,
        confidencePenalty: 100,
      };
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
