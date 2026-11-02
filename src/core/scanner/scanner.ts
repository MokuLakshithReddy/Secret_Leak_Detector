import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { SecretFinding, ScanResult, RuleDefinition } from '../types';
import { CORE_RULES } from '../detectors/rules';
import { analyzeFileContext, analyzeLexicalContext } from '../context/contextAnalyzer';
import { analyzeAstContext } from '../context/astAnalyzer';
import { buildEvidenceModel } from '../evidence/evidenceEngine';
import { calculateRiskAssessment } from '../risk/riskEngine';
import { buildRemediationPlan } from '../remediation/remediationEngine';
import { redactSecret, generateFingerprint } from '../redactor/redactor';
import { decodeTextBuffer } from '../encoding/textDecoder';

export interface ScannerOptions {
  rules?: RuleDefinition[];
  minEntropyThreshold?: number;
  workspaceRoot?: string;
  onSkippedFile?: (filePath: string, reason: string) => void;
  disallowInlineIgnore?: boolean;
  ignoreSkipped?: boolean;
  failOnSkipped?: boolean;
  maxFileSize?: number;
}

function getFileIdPart(relativePath: string): string {
  return crypto.createHash('sha256').update(relativePath.replace(/\\/g, '/')).digest('hex').slice(0, 8);
}

interface LineMap {
  text: string;
  origLine: number[];
  colOffset: number[];
}

/**
 * Bounds line length to prevent ReDoS on minified or adversarial single-line files,
 * while strictly preserving original file line numbers and column coordinates.
 */
function normalizeLongLinesWithMap(raw: string, maxLineLen = 4000): LineMap {
  const lines = raw.split(/\r?\n/);
  let hasLongLine = false;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].length > maxLineLen) {
      hasLongLine = true;
      break;
    }
  }

  if (!hasLongLine) {
    const origLine = lines.map((_, idx) => idx + 1);
    const colOffset = new Array(lines.length).fill(0);
    return { text: raw, origLine, colOffset };
  }

  const chunks: string[] = [];
  const origLine: number[] = [];
  const colOffset: number[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    if (line.length <= maxLineLen) {
      chunks.push(line);
      origLine.push(lineNum);
      colOffset.push(0);
    } else {
      // Raised chunk overlap to 512 chars so OpenAI project keys (160+ chars),
      // JWTs, and multi-line PEM boundaries straddling chunks are never truncated or missed
      const OVERLAP = 512;
      for (let pos = 0; pos < line.length; pos += maxLineLen - OVERLAP) {
        chunks.push(line.substring(pos, pos + maxLineLen));
        origLine.push(lineNum);
        colOffset.push(pos);
        if (pos + maxLineLen >= line.length) break;
      }
    }
  }

  return { text: chunks.join('\n'), origLine, colOffset };
}

interface DeobfuscationCandidate {
  combined: string;
  matchOffset: number;
  matchLength: number;
  description: string;
}

function hasInlineSuppression(currentLine: string, prevLine: string): boolean {
  const inlineRegex = /(?:\/\/|#|\/\*|--)\s*(?:sld-ignore|secret-leak-ignore)/i;
  if (inlineRegex.test(currentLine)) return true;
  const standaloneRegex = /^\s*(?:\/\/|#|\/\*|--)\s*(?:sld-ignore|secret-leak-ignore)(?:\s*\*\/)?\s*$/i;
  return standaloneRegex.test(prevLine);
}

export function scanContent(
  rawContent: string,
  filePath: string,
  options: ScannerOptions | string = {}
): SecretFinding[] {
  const opts: ScannerOptions = typeof options === 'string' ? { workspaceRoot: options } : options;
  const { text: content, origLine, colOffset } = normalizeLongLinesWithMap(rawContent);
  const rules = opts.rules || CORE_RULES;
  const workspaceRoot = opts.workspaceRoot;
  const fileContext = analyzeFileContext(filePath, workspaceRoot);
  const rawLines = rawContent.split(/\r?\n/);
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
          const chunkLine0 = mid;
          const chunkCol = offset - offsets[mid] + 1;
          const realLine = origLine[chunkLine0] !== undefined ? origLine[chunkLine0] : chunkLine0 + 1;
          const realCol = (colOffset[chunkLine0] || 0) + chunkCol;
          return {
            line: realLine,
            column: realCol,
          };
        }
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    const realLine = origLine[0] !== undefined ? origLine[0] : 1;
    const realCol = (colOffset[0] || 0) + offset + 1;
    return { line: realLine, column: realCol };
  }

  // Memory-efficient context extractor: windows lines from real rawLines to ensure inline ignore,
  // AST assignments, and lexical context strictly align with true reported coordinate numbers
  function getContextWindow(targetLine1Based: number): { lines: string[]; relativeTargetIdx: number } {
    const targetIdx0 = targetLine1Based - 1;
    if (rawLines.length <= 1000) {
      return { lines: rawLines, relativeTargetIdx: targetIdx0 };
    }
    const windowStartIdx = Math.max(0, targetIdx0 - 30);
    const windowEndIdx = Math.min(rawLines.length - 1, targetIdx0 + 30);
    const windowLines = rawLines.slice(windowStartIdx, windowEndIdx + 1);
    return { lines: windowLines, relativeTargetIdx: targetIdx0 - windowStartIdx };
  }

  // 1. Direct rule scanning across content
  for (const rule of rules) {
    rule.pattern.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = rule.pattern.exec(content)) !== null) {
      const rawSecret = match[1] !== undefined ? match[1] : match[0];
      const secretOffset = match[1] !== undefined ? match[0].indexOf(match[1]) : 0;
      const secretIndex = match.index + (secretOffset >= 0 ? secretOffset : 0);

      // Calculate line and column via binary search on line offsets (0 heap allocation)
      const { line: lineNumber, column: columnNumber } = getPosition(secretIndex);

      // Check for inline suppression comments (e.g. // sld-ignore, # sld-ignore) using real raw coordinates
      const currentLineText = rawLines[lineNumber - 1] || '';
      const prevLineText = lineNumber > 1 ? rawLines[lineNumber - 2] : '';
      if (!opts?.disallowInlineIgnore && hasInlineSuppression(currentLineText, prevLineText)) {
        continue;
      }

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

      // Check minimum entropy constraint:
      // Structured rules without an entropy requirement are never filtered by global minEntropy.
      // Only apply custom minEntropyThreshold to generic API key rules; preserve password and provider rule floors
      let effectiveMinEntropy: number | undefined;
      if (rule.minEntropy !== undefined) {
        if (rule.id === 'generic-api-key' && opts.minEntropyThreshold !== undefined) {
          effectiveMinEntropy = opts.minEntropyThreshold;
        } else {
          effectiveMinEntropy = rule.minEntropy;
        }
      }
      if (
        effectiveMinEntropy !== undefined &&
        evidenceResult.evidence.shannonEntropy < effectiveMinEntropy
      ) {
        continue;
      }

      // Calculate relative path
      let relativePath = filePath;
      if (workspaceRoot) {
        const rel = path.relative(workspaceRoot, filePath);
        if (!rel.startsWith('..') && !path.isAbsolute(rel)) {
          relativePath = rel;
        }
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

      const fileIdPart = getFileIdPart(relativePath);
      const fingerprint = generateFingerprint(rawSecret, undefined, workspaceRoot);
      const id = `sec_${fingerprint}_${fileIdPart}`;
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

  // 2. Adversarial normalization & evasion detection:
  // Handles: split string concatenation ("a" + "b"), array .join(''), template literals `a${'b'}`, and base64 payloads
  const candidates: DeobfuscationCandidate[] = [];

  // A. Split string concatenation: "ghp_" + "12345..."
  const concatRegex = /["']([^"'\r\n]{2,80})["']\s*\+\s*["']([^"'\r\n]{8,120})["']/g;
  let concatMatch: RegExpExecArray | null;
  while ((concatMatch = concatRegex.exec(content)) !== null) {
    candidates.push({
      combined: concatMatch[1] + concatMatch[2],
      matchOffset: concatMatch.index,
      matchLength: concatMatch[0].length,
      description: 'Resolved split string concatenation',
    });
  }

  // B. Array .join(''): ['sk_live_', '12345...', 'part3', 'part4'].join('')
  const arrayJoinRegex = /\[([^\]\r\n]{4,300})\]\s*\.\s*join\s*\(\s*["']\s*["']\s*\)/g;
  let arrayJoinMatch: RegExpExecArray | null;
  while ((arrayJoinMatch = arrayJoinRegex.exec(content)) !== null) {
    const itemRegex = /["']([^"'\r\n]*)["']/g;
    const parts: string[] = [];
    let itemMatch: RegExpExecArray | null;
    while ((itemMatch = itemRegex.exec(arrayJoinMatch[1])) !== null) {
      parts.push(itemMatch[1]);
    }
    if (parts.length >= 2) {
      candidates.push({
        combined: parts.join(''),
        matchOffset: arrayJoinMatch.index,
        matchLength: arrayJoinMatch[0].length,
        description: 'Resolved split array join expression',
      });
    }
  }

  // C. Template literals: `sk_live_${'12345...'}`
  const templateRegex = /`([^`\r\n]{2,80})\$\{\s*["']([^"'\r\n]{8,120})["']\s*\}([^`\r\n]*?)`/g;
  let templateMatch: RegExpExecArray | null;
  while ((templateMatch = templateRegex.exec(content)) !== null) {
    candidates.push({
      combined: templateMatch[1] + templateMatch[2] + (templateMatch[3] || ''),
      matchOffset: templateMatch.index,
      matchLength: templateMatch[0].length,
      description: 'Resolved template literal interpolation',
    });
  }

  // D. Base64 encoded payload: Buffer.from("c2tfbGl2ZV8...", "base64"), atob("..."), or standalone base64 string literals
  const b64Regex = /(?:(?:Buffer\.from|atob|b64decode|b64_decode|base64_decode|DecodeString)\s*\(\s*(?:b)?["']([A-Za-z0-9+/=_-]{20,300})["']|["']([A-Za-z0-9+/_-]{20,}={0,2})["']|(?:=|\:)\s*([A-Za-z0-9+/_-]{20,}={0,2})|(?:^|[\r\n\s])([A-Za-z0-9+/_-]{24,}={0,2})(?:[\r\n\s]|$))/g;
  let b64Match: RegExpExecArray | null;
  while ((b64Match = b64Regex.exec(content)) !== null) {
    const rawB64 = b64Match[1] || b64Match[2] || b64Match[3] || b64Match[4];
    if (!rawB64) continue;
    try {
      const normalizedB64 = rawB64.replace(/-/g, '+').replace(/_/g, '/');
      const padLen = (4 - (normalizedB64.length % 4)) % 4;
      const paddedB64 = normalizedB64 + '='.repeat(padLen);
      const decoded = Buffer.from(paddedB64, 'base64').toString('utf8');
      if (decoded.length >= 10 && /^[\x20-\x7E\r\n\t]+$/.test(decoded)) {
        candidates.push({
          combined: decoded,
          matchOffset: b64Match.index,
          matchLength: b64Match[0].length,
          description: 'Resolved base64-encoded credential payload',
        });
      }
    } catch {}
  }

  for (const candidate of candidates) {
    for (const rule of rules) {
      rule.pattern.lastIndex = 0;
      let ruleMatch: RegExpExecArray | null;

      while ((ruleMatch = rule.pattern.exec(candidate.combined)) !== null) {
        const rawSecret = ruleMatch[1] || ruleMatch[0];
        const { line: lineNumber, column: columnNumber } = getPosition(candidate.matchOffset);

        const currentLineText = rawLines[lineNumber - 1] || '';
        const prevLineText = lineNumber > 1 ? rawLines[lineNumber - 2] : '';
        if (!opts?.disallowInlineIgnore && hasInlineSuppression(currentLineText, prevLineText)) {
          continue;
        }

        const ctxWindow = getContextWindow(lineNumber);
        const lexicalContext = analyzeLexicalContext(ctxWindow.lines, ctxWindow.relativeTargetIdx);
        const astContext = analyzeAstContext(ctxWindow.lines, ctxWindow.relativeTargetIdx, filePath);

        const evidenceResult = buildEvidenceModel(
          rule,
          rawSecret,
          fileContext,
          lexicalContext,
          filePath,
          astContext
        );

        if (evidenceResult.isSuppressed) continue;

        let effectiveMinEntropy: number | undefined;
        if (rule.minEntropy !== undefined) {
          if (rule.id === 'generic-api-key' && opts.minEntropyThreshold !== undefined) {
            effectiveMinEntropy = opts.minEntropyThreshold;
          } else {
            effectiveMinEntropy = rule.minEntropy;
          }
        }
        if (
          effectiveMinEntropy !== undefined &&
          evidenceResult.evidence.shannonEntropy < effectiveMinEntropy
        ) {
          continue;
        }

        let relativePath = filePath;
        if (workspaceRoot) {
          const rel = path.relative(workspaceRoot, filePath);
          if (!rel.startsWith('..') && !path.isAbsolute(rel)) {
            relativePath = rel;
          }
        }

        const riskAssessment = calculateRiskAssessment(
          rule,
          evidenceResult.confidence,
          fileContext
        );

        const remediation = buildRemediationPlan(
          rule,
          rawSecret,
          relativePath,
          lineNumber,
          lexicalContext.inferredVariable
        );

        evidenceResult.evidence.items.unshift({
          signal: 'ADVERSARIAL_DEOBFUSCATION_RESOLVED',
          description: candidate.description,
          confidenceImpact: +10,
        });

        const fileIdPart = getFileIdPart(relativePath);
        const fingerprint = generateFingerprint(rawSecret, undefined, workspaceRoot);
        const id = `sec_${fingerprint}_${fileIdPart}`;
        const redacted = redactSecret(rawSecret);

        findings.push({
          id,
          fingerprint,
          type: rule.name,
          provider: rule.provider,
          file: relativePath,
          fullPath: filePath,
          line: lineNumber,
          column: columnNumber,
          length: candidate.matchLength,
          rawSecret,
          redactedSecret: redacted,
          confidence: Math.min(100, evidenceResult.confidence + 5),
          risk: riskAssessment.tier,
          riskAssessment,
          evidence: evidenceResult.evidence,
          remediation,
          status: 'ACTIVE',
          detectedAt: new Date().toISOString(),
          signals: evidenceResult.evidence.items.map((i) => i.description),
          exampleFix: remediation.replacementCode,
          entropy: evidenceResult.evidence.shannonEntropy,
        });
      }
    }
  }

  // Deduplicate overlapping findings
  return deduplicateFindings(findings);
}

export function scanFile(filePath: string, options: ScannerOptions = {}): SecretFinding[] {
  try {
    if (!fs.existsSync(filePath)) {
      options.onSkippedFile?.(filePath, 'File does not exist');
      return [];
    }
    const stat = fs.statSync(filePath);
    if (stat.isDirectory()) {
      return [];
    }
    const effectiveLimit = options.maxFileSize ?? (50 * 1024 * 1024);
    if (stat.size > effectiveLimit) {
      const maxMb = Math.round(effectiveLimit / (1024 * 1024));
      options.onSkippedFile?.(filePath, `File exceeds ${maxMb}MB limit (${(stat.size / 1024 / 1024).toFixed(1)}MB)`);
      return [];
    }
    const rawBuf = fs.readFileSync(filePath);
    const decoded = decodeTextBuffer(rawBuf);
    if (decoded === null) {
      options.onSkippedFile?.(filePath, 'Dense binary content with no extractable text');
      return [];
    }
    return scanContent(decoded, filePath, options);
  } catch (err: any) {
    options.onSkippedFile?.(filePath, err.message || 'File read error');
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
