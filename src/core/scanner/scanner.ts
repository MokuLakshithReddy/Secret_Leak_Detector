import * as fs from 'fs';
import { CORE_RULES } from '../detectors/rules';
import { analyzeFileContext, analyzeLexicalContext } from '../context/contextAnalyzer';
import { buildEvidenceModel } from '../evidence/evidenceEngine';
import { calculateRiskAssessment } from '../risk/riskEngine';
import { buildRemediationPlan } from '../remediation/remediationEngine';
import { redactSecret, generateFingerprint } from '../redactor/redactor';
import { SecretFinding, ScanResult, RuleDefinition } from '../types';

export interface ScannerOptions {
  rules?: RuleDefinition[];
  minEntropyThreshold?: number;
  workspaceRoot?: string;
}

export function scanContent(
  content: string,
  filePath: string,
  options: ScannerOptions | string = {}
): SecretFinding[] {
  const opts: ScannerOptions = typeof options === 'string' ? { workspaceRoot: options } : options;
  const rules = opts.rules || CORE_RULES;
  const workspaceRoot = opts.workspaceRoot;
  const lines = content.split(/\r?\n/);
  const fileContext = analyzeFileContext(filePath);

  const findings: SecretFinding[] = [];

  // Adversarial normalization: resolve split string concatenations (e.g. "ghp_" + "123...")
  let scanTargetContent = content;
  const concatRegex = /"([^"\r\n]{2,80})"\s*\+\s*"([^"\r\n]{10,120})"/g;
  let concatMatch: RegExpExecArray | null;
  while ((concatMatch = concatRegex.exec(content)) !== null) {
    const combined = concatMatch[1] + concatMatch[2];
    scanTargetContent += `\nconst _deobfuscated = "${combined}";`;
  }

  for (const rule of rules) {
    rule.pattern.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = rule.pattern.exec(scanTargetContent)) !== null) {
      const rawSecret = match[1] || match[0];
      const matchIndex = match.index;

      // Calculate line and column
      const textBefore = content.substring(0, matchIndex);
      const linesBefore = textBefore.split(/\r?\n/);
      const lineNumber = linesBefore.length;
      const columnNumber = linesBefore[linesBefore.length - 1].length + 1;

      // Extract lexical context
      const lexicalContext = analyzeLexicalContext(lines, lineNumber - 1);

      // Build Evidence Model & calculate confidence
      const evidenceResult = buildEvidenceModel(
        rule,
        rawSecret,
        fileContext,
        lexicalContext,
        filePath
      );

      // If classified as a false positive or placeholder, suppress it
      if (evidenceResult.isSuppressed) {
        continue;
      }

      // Check minimum entropy constraint
      if (
        rule.minEntropy &&
        evidenceResult.evidence.shannonEntropy < rule.minEntropy &&
        rule.baseRiskWeight < 90
      ) {
        continue;
      }

      // Calculate relative path
      let relativePath = filePath;
      if (workspaceRoot && filePath.startsWith(workspaceRoot)) {
        relativePath = filePath.substring(workspaceRoot.length).replace(/^[\\/]+/, '');
      }

      // Calculate dynamic Risk Assessment (0 - 100)
      const riskAssessment = calculateRiskAssessment(
        rule,
        evidenceResult.confidence,
        fileContext
      );

      // Build controlled Remediation Plan
      const remediation = buildRemediationPlan(
        rule,
        rawSecret,
        relativePath,
        lineNumber,
        lexicalContext.inferredVariable
      );

      const id = `sec_${generateFingerprint(rawSecret)}_${lineNumber}`;
      const fingerprint = generateFingerprint(rawSecret);
      const redacted = redactSecret(rawSecret);

      const finding: SecretFinding = {
        id,
        fingerprint,
        type: rule.name,
        provider: rule.provider,
        file: relativePath,
        fullPath: filePath,
        line: lineNumber,
        column: columnNumber,
        length: rawSecret.length,
        rawSecret,
        redactedSecret: redacted,
        confidence: evidenceResult.confidence,
        risk: riskAssessment.tier,
        riskAssessment,
        evidence: evidenceResult.evidence,
        remediation,
        status: 'ACTIVE',
        detectedAt: new Date().toISOString(),

        // Compatibility fields
        signals: evidenceResult.evidence.items.map((i) => i.description),
        exampleFix: remediation.replacementCode,
        entropy: evidenceResult.evidence.shannonEntropy,
      };

      findings.push(finding);
    }
  }

  // Deduplicate overlapping findings
  return deduplicateFindings(findings);
}

export function scanFile(filePath: string, options: ScannerOptions = {}): SecretFinding[] {
  try {
    if (!fs.existsSync(filePath)) return [];
    const stat = fs.statSync(filePath);
    if (stat.isDirectory() || stat.size > 5 * 1024 * 1024) {
      // Skip directories or files over 5MB
      return [];
    }
    const content = fs.readFileSync(filePath, 'utf8');
    return scanContent(content, filePath, options);
  } catch {
    return [];
  }
}

function deduplicateFindings(findings: SecretFinding[]): SecretFinding[] {
  const result: SecretFinding[] = [];

  for (const finding of findings) {
    const existingIndex = result.findIndex(
      (existing) =>
        existing.file === finding.file &&
        existing.line === finding.line &&
        (existing.rawSecret.includes(finding.rawSecret) ||
          finding.rawSecret.includes(existing.rawSecret))
    );

    if (existingIndex === -1) {
      result.push(finding);
    } else {
      const existing = result[existingIndex];
      // Prefer specific cloud provider over Generic Credential
      if (existing.provider === 'Generic Credential' && finding.provider !== 'Generic Credential') {
        result[existingIndex] = finding;
      } else if (finding.confidence > existing.confidence) {
        result[existingIndex] = finding;
      }
    }
  }

  return result;
}

export function buildScanResult(
  findings: SecretFinding[],
  filesScanned: number,
  durationMs: number
): ScanResult {
  const riskSummary = {
    critical: findings.filter((f) => f.risk === 'CRITICAL').length,
    high: findings.filter((f) => f.risk === 'HIGH').length,
    medium: findings.filter((f) => f.risk === 'MEDIUM').length,
    low: findings.filter((f) => f.risk === 'LOW').length,
  };

  const blocked = riskSummary.critical > 0 || riskSummary.high > 0;

  return {
    findings,
    filesScanned,
    durationMs,
    timestamp: new Date().toISOString(),
    isClean: findings.length === 0,
    blocked,
    riskSummary,
  };
}
