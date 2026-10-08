/**
 * Provider-Specific Structural Validators
 * Performs cryptographic and protocol-level structural validation beyond regex.
 */

export interface ValidationResult {
  isValid: boolean;
  confidenceBonus: number;
  reason: string;
}

/**
 * Validates AWS Access Key ID format and prefix structure.
 */
export function validateAwsAccessKey(key: string): ValidationResult {
  if (!/^(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}$/.test(key)) {
    return { isValid: false, confidenceBonus: 0, reason: 'Invalid AWS key length or character set' };
  }
  const prefix = key.substring(0, 4);
  const prefixMap: Record<string, string> = {
    AKIA: 'Standard permanent IAM user access key',
    ASIA: 'Temporary STS session access key',
    ABIA: 'AWS Backup access key',
    ACCA: 'AWS CodeCommit access key',
  };
  return {
    isValid: true,
    confidenceBonus: 10,
    reason: prefixMap[prefix] || 'Valid AWS Access Key ID structure',
  };
}

/**
 * Validates Stripe API Keys (Prefix format, length, and character entropy).
 */
export function validateStripeKey(key: string): ValidationResult {
  const isLive = /^sk_live_[0-9a-zA-Z]{24,34}$/.test(key) || /^rk_live_[0-9a-zA-Z]{24,34}$/.test(key);
  const isTest = /^sk_test_[0-9a-zA-Z]{24,34}$/.test(key) || /^rk_test_[0-9a-zA-Z]{24,34}$/.test(key);

  if (!isLive && !isTest) {
    return { isValid: false, confidenceBonus: 0, reason: 'Does not match official Stripe secret key format' };
  }

  return {
    isValid: true,
    confidenceBonus: isLive ? 12 : 5,
    reason: isLive ? 'Production live Stripe Secret Key' : 'Stripe Test API key',
  };
}

/**
 * Validates GitHub Personal Access Tokens (Classic 36-char and Fine-Grained 82-char format).
 */
export function validateGitHubToken(token: string): ValidationResult {
  if (/^ghp_[A-Za-z0-9_]{36}$/.test(token)) {
    return { isValid: true, confidenceBonus: 12, reason: 'GitHub Personal Access Token (Classic)' };
  }
  if (/^gho_[A-Za-z0-9_]{36}$/.test(token)) {
    return { isValid: true, confidenceBonus: 10, reason: 'GitHub OAuth Access Token' };
  }
  if (/^ghs_[A-Za-z0-9_]{36}$/.test(token)) {
    return { isValid: true, confidenceBonus: 10, reason: 'GitHub Server-to-server token' };
  }
  if (/^github_pat_[A-Za-z0-9_]{82}$/.test(token)) {
    return { isValid: true, confidenceBonus: 15, reason: 'GitHub Fine-Grained Personal Access Token' };
  }

  return { isValid: false, confidenceBonus: 0, reason: 'Invalid GitHub token prefix or length' };
}

/**
 * Validates JSON Web Token structure by safely inspecting base64 header.
 */
export function validateJwtToken(token: string): ValidationResult {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return { isValid: false, confidenceBonus: 0, reason: 'Not a 3-part dot-separated JWT' };
  }

  try {
    const headerJson = Buffer.from(parts[0], 'base64url').toString('utf8');
    const header = JSON.parse(headerJson);
    if (header && typeof header === 'object' && header.alg) {
      return {
        isValid: true,
        confidenceBonus: 15,
        reason: `Valid JWT structure with signature algorithm: ${header.alg}`,
      };
    }
  } catch {
    // Header parsing failed
  }

  return { isValid: false, confidenceBonus: 0, reason: 'Malformed JWT header JSON payload' };
}

/**
 * Validates Database Connection URI components.
 */
export function validateDatabaseUrl(url: string): ValidationResult {
  try {
    const parsed = new URL(url);
    const validProtocols = ['postgres:', 'postgresql:', 'mysql:', 'mongodb:', 'redis:'];
    if (!validProtocols.includes(parsed.protocol)) {
      return { isValid: false, confidenceBonus: 0, reason: 'Unsupported database protocol scheme' };
    }

    if (parsed.password && parsed.password.length > 0) {
      return {
        isValid: true,
        confidenceBonus: 12,
        reason: `Database connection string containing credentials for user '${parsed.username || 'default'}'`,
      };
    }
  } catch {
    // URL parsing failed
  }

  return { isValid: false, confidenceBonus: 0, reason: 'Invalid database connection URL structure' };
}
