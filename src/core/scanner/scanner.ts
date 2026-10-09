import * as fs from 'fs';
import { CORE_RULES } from '../detectors/rules';
import { analyzeFileContext, analyzeLexicalContext } from '../context/contextAnalyzer';
import { analyzeAstContext } from '../context/astAnalyzer';
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
  const fileContext = analyzeFileContext(filePath);
  const findings: SecretFinding[] = [];

  // Zero-allocation line & column offset index (instantiated lazily on first match)
  let lineOffsets: number[] | null = null;
  function getLineOffsets(): number[] {
    if (!lineOffsets) {
      lineOffsets = [0];
      for (let i = 0; i < content.length; i++) {
        if (content.charCodeAt(i) === 10) { // '\n'
          lineOffsets.push(i + 1);
        }
      }
    }
    return lineOffsets;
  }

  function getPosition(offset: number): { line: number; column: number } {
    const offsets = getLineOffsets();
    let low = 0;
    let high = offsets.length - 1;
    while (low <= high) {
      const mid = (low + high) >> 1;
      if (offsets[mid] <= offset) {
        if (mid === offsets.length - 1 || offsets[mid + 1] > offset) {
          return {
            line: mid + 1,
            column: offset - offsets[mid] + 1,
          };
        }
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    return { line: 1, column: offset + 1 };
  }

  // Memory-efficient context extractor: windows lines to avoid multi-megabyte string array allocations
  let cachedFullLines: string[] | null = null;
  function getContextWindow(targetLine1Based: number): { lines: string[]; relativeTargetIdx: number } {
    if (content.length <= 1024 * 1024) {
      if (!cachedFullLines) cachedFullLines = content.split(/\r?\n/);
      return { lines: cachedFullLines, relativeTargetIdx: targetLine1Based - 1 };
    }
    const offsets = getLineOffsets();
    const targetIdx0 = targetLine1Based - 1;
    const windowStartIdx = Math.max(0, targetIdx0 - 30);
    const windowEndIdx = Math.min(offsets.length - 1, targetIdx0 + 30);

    const startByte = offsets[windowStartIdx];
    const endByte = windowEndIdx + 1 < offsets.length ? offsets[windowEndIdx + 1] : content.length;
    const windowText = content.substring(startByte, endByte);
    const windowLines = windowText.split(/\r?\n/);
    return { lines: windowLines, relativeTargetIdx: targetIdx0 - windowStartIdx };
  }

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

      // Calculate line and column via binary search on line offsets (0 heap allocation)
      const { line: lineNumber, column: columnNumber } = getPosition(matchIndex);

      // Extract lexical context and AST assignment semantics with windowed lines
      const ctxWindow = getContextWindow(lineNumber);
      const lexicalContext = analyzeLexicalContext(ctxWindow.lines, ctxWindow.relativeTargetIdx);
      const astContext = analyzeAstContext(ctxWindow.lines, ctxWindow.relativeTargetIdx, filePath);

      // Build Evidence Model & calculate confidence
      const evidenceResult = buildEvidenceModel(
        rule,
        rawSecret,
        fileContext,
        lexicalContext,
        filePath,
        astContext
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
