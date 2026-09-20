import { SECRET_RULES } from './patterns';
import { calculateShannonEntropy } from './entropy';
import { redactSecret } from './redactor';
import { SecretFinding, ScanResult } from '../types';

// Common placeholders and false-positive indicators
const PLACEHOLDER_PATTERNS = [
  /example/i,
  /placeholder/i,
  /your[_-]?api[_-]?key/i,
  /dummy/i,
  /test[_-]?token/i,
  /xxxx+/i,
  /^123456789[0-9]*$/,
  /AKIAIOSFODNN7EXAMPLE/i,
  /insert[_-]?here/i,
  /replace[_-]?me/i,
];

function isKnownPlaceholder(secret: string): boolean {
  return PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(secret));
}

/**
 * Scans a given text content against all secret rules and returns findings.
 */
export function scanContent(
  content: string,
  filePath: string,
  workspaceRoot?: string,
  minEntropyThreshold = 3.4
): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const lines = content.split(/\r?\n/);
  const isTestFile = /(test|spec|mock|fixture|sample)/i.test(filePath);

  for (const rule of SECRET_RULES) {
    // Reset regex index state
    rule.pattern.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = rule.pattern.exec(content)) !== null) {
      // If capturing group is present, that's the secret value, else entire match
      const rawSecret = match[1] || match[0];
      const matchIndex = match.index;

      // Filter out obvious placeholders
      if (isKnownPlaceholder(rawSecret)) {
        continue;
      }

      // Compute Shannon entropy
      const entropy = calculateShannonEntropy(rawSecret);

      // Apply rule entropy filter if defined
      const ruleMinEntropy = rule.minEntropy ?? (rule.risk === 'CRITICAL' ? 0 : minEntropyThreshold);
      if (ruleMinEntropy > 0 && entropy < ruleMinEntropy) {
        continue;
      }

      // Calculate line and column number
      const textBeforeMatch = content.substring(0, matchIndex);
      const linesBefore = textBeforeMatch.split(/\r?\n/);
      const lineNumber = linesBefore.length;
      const columnNumber = linesBefore[linesBefore.length - 1].length + 1;

      // Compute relative path
      let relativePath = filePath;
      if (workspaceRoot && filePath.startsWith(workspaceRoot)) {
        relativePath = filePath.substring(workspaceRoot.length).replace(/^[\\/]+/, '');
      }

      // Adjust confidence
      let confidence = rule.baseConfidence;
      if (isTestFile) {
        confidence = Math.max(50, confidence - 20);
      }
      if (entropy > 4.5) {
        confidence = Math.min(100, confidence + 5);
      }

      // Extract surrounding line text for variable context deduction
      const currentLineText = lines[lineNumber - 1] || '';
      const varNameMatch = currentLineText.match(/(?:const|let|var|val|\$)\s+([a-zA-Z0-9_]+)/i);
      const inferredVarName = varNameMatch ? varNameMatch[1] : undefined;

      const findingId = `sec_${Math.random().toString(36).substring(2, 9)}`;

      findings.push({
        id: findingId,
        type: rule.name,
        provider: rule.provider,
        file: relativePath,
        fullPath: filePath,
        line: lineNumber,
        column: columnNumber,
        length: rawSecret.length,
        rawSecret,
        redactedSecret: redactSecret(rawSecret),
        risk: rule.risk,
        confidence,
        entropy,
        signals: [...rule.signals, `Entropy: ${entropy} bits/char`],
        remediation: rule.remediation,
        exampleFix: rule.exampleFix(inferredVarName || ''),
        status: 'ACTIVE',
        detectedAt: new Date().toISOString(),
      });
    }
  }

  // Deduplicate overlapping findings (prefer specific provider over Generic Credential)
  const deduplicated: SecretFinding[] = [];
  for (const finding of findings) {
    const existingIndex = deduplicated.findIndex(
      (d) =>
        d.line === finding.line &&
        (d.rawSecret.includes(finding.rawSecret) || finding.rawSecret.includes(d.rawSecret))
    );

    if (existingIndex === -1) {
      deduplicated.push(finding);
    } else {
      const existing = deduplicated[existingIndex];
      // If new finding is from a specific provider and existing is generic, replace
      if (existing.provider === 'Generic Credential' && finding.provider !== 'Generic Credential') {
        deduplicated[existingIndex] = finding;
      } else if (finding.confidence > existing.confidence) {
        deduplicated[existingIndex] = finding;
      }
    }
  }

  return deduplicated;
}

/**
 * Executes a full scan summary over provided files.
 */
export function buildScanResult(findings: SecretFinding[], filesScanned: number, durationMs: number): ScanResult {
  const hasCriticalOrHigh = findings.some((f) => f.risk === 'CRITICAL' || f.risk === 'HIGH');

  return {
    findings,
    filesScanned,
    durationMs,
    timestamp: new Date().toISOString(),
    isClean: findings.length === 0,
    blocked: hasCriticalOrHigh,
  };
}
