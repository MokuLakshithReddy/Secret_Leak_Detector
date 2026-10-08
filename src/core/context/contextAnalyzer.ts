import * as path from 'path';

export interface LexicalContext {
  inferredVariable?: string;
  isSensitiveIdentifier: boolean;
  isBenignIdentifier: boolean;
  isAssignment: boolean;
  isEnvOrConfigAccess: boolean;
  isHeaderOrBearer: boolean;
  isInComment: boolean;
  surroundingBefore: string[];
  matchedLine: string;
  surroundingAfter: string[];
}

export interface FileContext {
  fileExtension: string;
  isConfig: boolean;
  isTest: boolean;
  isDoc: boolean;
  isSensitiveName: boolean;
  isExampleOrSample: boolean;
}

const SENSITIVE_VAR_NAMES = [
  /api[_-]?key/i,
  /secret[_-]?key/i,
  /access[_-]?token/i,
  /auth[_-]?token/i,
  /private[_-]?key/i,
  /client[_-]?secret/i,
  /password/i,
  /credential/i,
  /session[_-]?token/i,
  /bearer/i,
  /aws[_-]?(?:access|secret)/i,
  /stripe[_-]?(?:secret|key)/i,
  /github[_-]?(?:token|pat)/i,
  /slack[_-]?token/i,
  /db[_-]?pass(?:word)?/i,
];

const BENIGN_VAR_NAMES = [
  /example/i,
  /placeholder/i,
  /mock/i,
  /dummy/i,
  /fake/i,
  /sample/i,
  /test[_-]?(?:key|token|id)/i,
  /demo/i,
  /insert[_-]?here/i,
];

export function analyzeFileContext(filePath: string): FileContext {
  const normalizedPath = filePath.replace(/\\/g, '/').toLowerCase();
  const baseName = path.basename(filePath).toLowerCase();
  const ext = path.extname(filePath).toLowerCase();

  const isTest = /(?:^|\/)(?:test|tests|spec|specs|__tests__|__mocks__|fixtures|mocks)\/|(?:test|spec)\.[a-z0-9]+$/i.test(
    normalizedPath
  );

  const isDoc = /(?:^|\/)(?:docs|doc|documentation|tutorials|guides)\/|readme\.md|contributing\.md|changelog\.md/i.test(
    normalizedPath
  );

  const isExampleOrSample = /(?:example|sample|\.example|\.sample)/i.test(normalizedPath);

  const isConfig =
    /^\.env(?:\.[a-z0-9]+)?$/.test(baseName) ||
    /(?:config|settings|secret|credential|database|deploy|production|staging|k8s|helm|tfvars)/i.test(
      normalizedPath
    ) ||
    ['.env', '.yaml', '.yml', '.json', '.toml', '.ini', '.tf'].includes(ext);

  const isSensitiveName =
    /^\.env/.test(baseName) ||
    /(?:secret|credential|id_rsa|private_key|keypair|auth_config)/i.test(baseName);

  return {
    fileExtension: ext,
    isConfig,
    isTest,
    isDoc,
    isSensitiveName,
    isExampleOrSample,
  };
}

export function analyzeLexicalContext(
  contentLines: string[],
  lineIndexZeroBased: number
): LexicalContext {
  const matchedLine = contentLines[lineIndexZeroBased] || '';

  // Extract surrounding lines (up to 3 before and after)
  const surroundingBefore: string[] = [];
  for (let i = Math.max(0, lineIndexZeroBased - 3); i < lineIndexZeroBased; i++) {
    surroundingBefore.push(contentLines[i]);
  }

  const surroundingAfter: string[] = [];
  for (
    let i = lineIndexZeroBased + 1;
    i <= Math.min(contentLines.length - 1, lineIndexZeroBased + 3);
    i++
  ) {
    surroundingAfter.push(contentLines[i]);
  }

  // Detect variable name
  const varMatch =
    matchedLine.match(/(?:const|let|var|val|\$|string|final)\s+([a-zA-Z0-9_]+)/i) ||
    matchedLine.match(/([a-zA-Z0-9_]+)\s*[:=]/i);

  const inferredVariable = varMatch ? varMatch[1] : undefined;

  let isSensitiveIdentifier = false;
  let isBenignIdentifier = false;

  if (inferredVariable) {
    isSensitiveIdentifier = SENSITIVE_VAR_NAMES.some((p) => p.test(inferredVariable));
    isBenignIdentifier = BENIGN_VAR_NAMES.some((p) => p.test(inferredVariable));
  } else {
    // Check if whole line has sensitive assignment
    isSensitiveIdentifier = SENSITIVE_VAR_NAMES.some((p) => p.test(matchedLine));
  }

  const isAssignment = /[:=]/.test(matchedLine);
  const isEnvOrConfigAccess = /(?:process\.env|os\.getenv|os\.environ|dotenv|config\.get)/i.test(
    matchedLine
  );
  const isHeaderOrBearer = /(?:authorization|bearer|x-api-key)/i.test(matchedLine);
  const isInComment = /^\s*(?:\/\/|#|\/\*|\*|--)/.test(matchedLine);

  return {
    inferredVariable,
    isSensitiveIdentifier,
    isBenignIdentifier,
    isAssignment,
    isEnvOrConfigAccess,
    isHeaderOrBearer,
    isInComment,
    surroundingBefore,
    matchedLine,
    surroundingAfter,
  };
}
