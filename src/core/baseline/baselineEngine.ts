import * as fs from 'fs';
import * as path from 'path';
import { SecretFinding, BaselineFile, BaselineFinding } from '../types';

export const DEFAULT_BASELINE_FILENAME = '.secretleak-baseline.json';

/**
 * Normalise a repository-relative path so a baseline generated on one platform
 * (e.g. Windows, backslashes) still matches findings produced on another
 * (e.g. Linux CI, forward slashes).
 */
function normalizeBaselinePath(p: string): string {
  return String(p).replace(/\\/g, '/');
}

export class BaselineValidationError extends Error {
  constructor(message: string) {
    super(`Baseline file validation error: ${message}`);
    this.name = 'BaselineValidationError';
  }
}

/**
 * Validates that an unparsed or deserialized object strictly complies with the BaselineFile schema.
 * Rejects malformed structures or missing required fields explicitly.
 */
export function validateBaselineSchema(parsed: unknown): BaselineFile {
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new BaselineValidationError('Root of baseline file must be a JSON object.');
  }

  const obj = parsed as Record<string, unknown>;

  if (typeof obj.version !== 'number' || isNaN(obj.version) || obj.version < 1) {
    throw new BaselineValidationError(`'version' must be a positive number (got ${obj.version}).`);
  }

  if (typeof obj.generatedAt !== 'string' || obj.generatedAt.trim().length === 0) {
    throw new BaselineValidationError(`'generatedAt' must be a non-empty string.`);
  }

  if (!Array.isArray(obj.findings)) {
    throw new BaselineValidationError(`'findings' must be an array.`);
  }

  for (let i = 0; i < obj.findings.length; i++) {
    const item = obj.findings[i];
    if (typeof item !== 'object' || item === null || Array.isArray(item)) {
      throw new BaselineValidationError(`findings[${i}] must be an object.`);
    }

    if (typeof item.fingerprint !== 'string' || item.fingerprint.trim().length === 0) {
      throw new BaselineValidationError(`findings[${i}].fingerprint must be a non-empty string.`);
    }

    if (typeof item.file !== 'string' || item.file.trim().length === 0) {
      throw new BaselineValidationError(`findings[${i}].file must be a non-empty string.`);
    }

    if (typeof item.ruleId !== 'string') {
      throw new BaselineValidationError(`findings[${i}].ruleId must be a string.`);
    }

    if (typeof item.line !== 'number' || isNaN(item.line)) {
      throw new BaselineValidationError(`findings[${i}].line must be a number.`);
    }
  }

  return parsed as BaselineFile;
}

export class BaselineEngine {
  private baselinePath: string;

  constructor(workspaceRoot: string, customFilename = DEFAULT_BASELINE_FILENAME) {
    this.baselinePath = path.isAbsolute(customFilename)
      ? customFilename
      : path.join(workspaceRoot, customFilename);
  }

  public exists(): boolean {
    return fs.existsSync(this.baselinePath);
  }

  public getPath(): string {
    return this.baselinePath;
  }

  /**
   * Loads and schema-validates the baseline file.
   * Returns null only if the baseline file does not exist.
   * Throws BaselineValidationError if the file is malformed, invalid JSON, or fails schema validation.
   */
  public loadBaseline(): BaselineFile | null {
    if (!this.exists()) return null;

    let data: string;
    try {
      data = fs.readFileSync(this.baselinePath, 'utf8');
    } catch (err: any) {
      throw new BaselineValidationError(`Could not read baseline file at '${this.baselinePath}': ${err.message}`);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(data);
    } catch (err: any) {
      throw new BaselineValidationError(`Malformed JSON in baseline file '${this.baselinePath}': ${err.message}`);
    }

    return validateBaselineSchema(parsed);
  }

  public saveBaseline(findings: SecretFinding[]): BaselineFile {
    const baselineFindings: BaselineFinding[] = findings.map((f) => ({
      id: f.id,
      fingerprint: f.fingerprint,
      ruleId: f.type,
      file: normalizeBaselinePath(f.file),
      line: f.line,
      firstSeen: f.detectedAt,
    }));

    const file: BaselineFile = {
      version: 1,
      generatedAt: new Date().toISOString(),
      generator: 'Secret Leak Detector v1.0.0',
      findings: baselineFindings,
    };

    fs.writeFileSync(this.baselinePath, JSON.stringify(file, null, 2), 'utf8');
    return file;
  }

  public filterAgainstBaseline(currentFindings: SecretFinding[]): {
    newFindings: SecretFinding[];
    existingFindings: SecretFinding[];
    resolvedCount: number;
    totalBaseline: number;
  } {
    const baseline = this.loadBaseline();
    if (!baseline) {
      return {
        newFindings: currentFindings,
        existingFindings: [],
        resolvedCount: 0,
        totalBaseline: 0,
      };
    }

    const baselineMap = new Map<string, BaselineFinding>();
    for (const b of baseline.findings) {
      // Key by fingerprint or file+rule (normalised so the key is portable).
      baselineMap.set(b.fingerprint, b);
      baselineMap.set(`${normalizeBaselinePath(b.file)}:${b.ruleId}:${b.line}`, b);
    }

    const newFindings: SecretFinding[] = [];
    const existingFindings: SecretFinding[] = [];
    const matchedFingerprints = new Set<string>();

    for (const finding of currentFindings) {
      const match =
        baselineMap.get(finding.fingerprint) ||
        baselineMap.get(`${normalizeBaselinePath(finding.file)}:${finding.type}:${finding.line}`);

      if (match) {
        finding.status = 'BASELINE';
        existingFindings.push(finding);
        matchedFingerprints.add(match.fingerprint);
      } else {
        newFindings.push(finding);
      }
    }

    const resolvedCount = Math.max(0, baseline.findings.length - matchedFingerprints.size);

    return {
      newFindings,
      existingFindings,
      resolvedCount,
      totalBaseline: baseline.findings.length,
    };
  }
}
