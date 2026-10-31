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

  // Robust test detection that avoids false matching on filenames like "latest.json"
  const isTest =
    /(?:^|\/)(?:tests?|specs?|__tests__|__mocks__|fixtures|mocks)\//i.test(normalizedPath) ||
    /[._-](?:test|spec)\.[a-z0-9]+$/i.test(baseName) ||
    /^(?:test|spec)\.[a-z0-9]+$/i.test(baseName);

  const isDoc = /(?:^|\/)(?:docs|doc|documentation|tutorials|guides)\/|readme\.md|contributing\.md|changelog\.md/i.test(
    normalizedPath
  );

  const isExampleOrSample = /(?:^|\/)(?:example|sample|\.example|\.sample)/i.test(normalizedPath) ||
    /[._-](?:example|sample)\.[a-z0-9]+$/i.test(baseName);

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
  for (let i = lineIndexZeroBased + 1; i < Math.min(contentLines.length, lineIndexZeroBased + 4); i++) {
    surroundingAfter.push(contentLines[i]);
  }

  // Infer variable / key identifier
  let inferredVariable: string | undefined;
  const assignmentMatch = matchedLine.match(/(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*[:=]/);
  const propertyMatch = matchedLine.match(/["']?([a-zA-Z0-9_$-]+)["']?\s*[:=]/);

  if (assignmentMatch) {
    inferredVariable = assignmentMatch[1];
  } else if (propertyMatch) {
    inferredVariable = propertyMatch[1];
  }

  const isSensitiveIdentifier = inferredVariable
    ? SENSITIVE_VAR_NAMES.some((r) => r.test(inferredVariable!))
    : false;

  const isBenignIdentifier = inferredVariable
    ? BENIGN_VAR_NAMES.some((r) => r.test(inferredVariable!))
    : false;

  const isAssignment = /[:=]/.test(matchedLine);
  const isEnvOrConfigAccess = /(?:process\.env|os\.environ|dotenv|config|getenv)/i.test(matchedLine);
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
