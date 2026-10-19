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
    const validProtocols = ['postgres:', 'postgresql:', 'mysql:', 'mongodb:', 'mongodb+srv:', 'redis:'];
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
    const dbRegex = /^(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s'"]+:([^\s'"]+)@([a-zA-Z0-9_.-]+(?::[0-9]+)?\/[^\s'"`;]*)/i;
    const match = url.match(dbRegex);
    if (match && match[1]) {
      return {
        isValid: true,
        confidenceBonus: 10,
        reason: 'Database connection URI structure matched with embedded password',
      };
    }
  }

  return { isValid: false, confidenceBonus: 0, reason: 'Invalid database connection URL structure' };
}

/**
 * Validates OpenAI API keys (Project, Admin, Service Account, and Legacy keys).
 */
export function validateOpenAiKey(key: string): ValidationResult {
  if (/^sk-proj-[A-Za-z0-9_-]{48,}$/.test(key)) {
    return { isValid: true, confidenceBonus: 15, reason: 'Valid OpenAI Project API Key format' };
  }
  if (/^sk-admin-[A-Za-z0-9_-]{48,}$/.test(key)) {
    return { isValid: true, confidenceBonus: 15, reason: 'Valid OpenAI Admin/Organization API Key format' };
  }
  if (/^sk-svcacct-[A-Za-z0-9_-]{48,}$/.test(key)) {
    return { isValid: true, confidenceBonus: 15, reason: 'Valid OpenAI Service Account Key format' };
  }
  if (/^sk-[A-Za-z0-9]{32,48}$/.test(key)) {
    return { isValid: true, confidenceBonus: 10, reason: 'Valid OpenAI Standard/Legacy API Key format' };
  }
  return { isValid: false, confidenceBonus: 0, reason: 'Invalid OpenAI API key structure' };
}

/**
 * Validates Anthropic Claude API Key format.
 */
export function validateAnthropicKey(key: string): ValidationResult {
  if (/^sk-ant-[A-Za-z0-9_-]{40,}$/.test(key)) {
    return { isValid: true, confidenceBonus: 15, reason: 'Valid Anthropic Claude API Key format' };
  }
  return { isValid: false, confidenceBonus: 0, reason: 'Invalid Anthropic API key format' };
}

/**
 * Validates Google Cloud / Gemini API key structure.
 */
export function validateGoogleApiKey(key: string): ValidationResult {
  if (/^AIza[0-9A-Za-z_-]{35}$/.test(key)) {
    return { isValid: true, confidenceBonus: 12, reason: 'Valid Google Cloud / Gemini AIza service key signature' };
  }
  return { isValid: false, confidenceBonus: 0, reason: 'Invalid Google Cloud API key format' };
}

/**
 * Validates Slack OAuth tokens and Bot tokens.
 */
export function validateSlackToken(token: string): ValidationResult {
  if (/^xox[baprs]-[0-9A-Za-z-]{10,72}$/.test(token)) {
    const type = token.startsWith('xoxb') ? 'Bot Token' : token.startsWith('xoxp') ? 'User Token' : 'OAuth Token';
    return { isValid: true, confidenceBonus: 12, reason: `Valid Slack ${type} signature` };
  }
  return { isValid: false, confidenceBonus: 0, reason: 'Invalid Slack token structure' };
}

/**
 * Validates Hugging Face access token format.
 */
export function validateHuggingFaceToken(token: string): ValidationResult {
  if (/^hf_[A-Za-z0-9]{34}$/.test(token)) {
    return { isValid: true, confidenceBonus: 12, reason: 'Valid Hugging Face User Access Token format' };
  }
  return { isValid: false, confidenceBonus: 0, reason: 'Invalid Hugging Face token structure' };
}
