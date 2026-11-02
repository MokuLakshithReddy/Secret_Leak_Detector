import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { SecretFinding, BaselineFile, BaselineFinding } from '../types';
import { getPackageVersion } from '../version';
import { resolveSalt } from '../redactor/redactor';

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
  private workspaceRoot: string;
  private baselinePath: string;

  constructor(workspaceRoot: string, customFilename = DEFAULT_BASELINE_FILENAME) {
    this.workspaceRoot = workspaceRoot;
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

  /**
   * In CI or Git environments, loads baseline from a trusted Git ref (e.g. PR target branch, or push event's prior commit).
   * Ensures that PRs or pushed commits cannot tamper with .secretleak-baseline.json to bypass checks.
   *
   * In CI:
   *  - For pull_request: loads from trusted PR base (GITHUB_BASE_REF / origin/main).
   *  - For push: loads from the push event's previous commit SHA (SLD_BASE_REF / GITHUB_EVENT_BEFORE / HEAD~1).
   *  - NEVER trusts the current commit (HEAD) as its own baseline.
   *
   * Malformed baseline files throw BaselineValidationError (never silently swallowed).
   */
  public loadBaselineFromGit(gitRef?: string): BaselineFile | null {
    const { execFileSync } = require('child_process');
    let gitPath = this.baselinePath;
    let gitRoot = this.workspaceRoot;
    try {
      gitRoot = execFileSync('git', ['rev-parse', '--show-toplevel'], {
        cwd: this.workspaceRoot,
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'ignore'],
      }).trim();
      const absBaseline = path.isAbsolute(this.baselinePath)
        ? this.baselinePath
        : path.resolve(this.workspaceRoot, this.baselinePath);
      let canonicalGitRoot = gitRoot;
      let canonicalAbsBaseline = absBaseline;
      try {
        if (fs.existsSync(gitRoot)) canonicalGitRoot = fs.realpathSync(gitRoot);
        if (fs.existsSync(absBaseline)) canonicalAbsBaseline = fs.realpathSync(absBaseline);
      } catch {}
      gitPath = path.relative(canonicalGitRoot, canonicalAbsBaseline).replace(/\\/g, '/');
      if (gitPath.startsWith('../') || path.isAbsolute(gitPath) || !gitPath) {
        gitPath = path.basename(this.baselinePath);
      }
      gitPath = gitPath.replace(/^\.?\//, '');
    } catch {
      gitPath = path.isAbsolute(this.baselinePath)
        ? path.basename(this.baselinePath)
        : this.baselinePath.replace(/\\/g, '/').replace(/^\.?\//, '');
    }

    const isCI = !!(process.env.CI || process.env.GITHUB_ACTIONS || process.env.GITLAB_CI);
    let candidateRefs: string[] = [];

    // Get current HEAD sha to ensure we never trust the commit being scanned in CI
    let headSha = '';
    try {
      headSha = execFileSync('git', ['rev-parse', 'HEAD'], {
        cwd: gitRoot,
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'ignore'],
      }).trim();
    } catch {}

    if (gitRef) {
      candidateRefs.push(gitRef);
    } else if (isCI) {
      const explicitBase =
        process.env.SLD_BASE_REF ||
        process.env.GITHUB_BASE_REF ||
        process.env.CI_MERGE_REQUEST_TARGET_BRANCH_NAME;
      const beforeSha = process.env.GITHUB_EVENT_BEFORE || process.env.CI_COMMIT_BEFORE_SHA;

      if (explicitBase && explicitBase !== '0000000000000000000000000000000000000000') {
        candidateRefs.push(`origin/${explicitBase}`, `refs/remotes/origin/${explicitBase}`, explicitBase);
      }
      if (beforeSha && beforeSha !== '0000000000000000000000000000000000000000') {
        candidateRefs.push(beforeSha);
      }

      if (candidateRefs.length === 0) {
        candidateRefs.push('HEAD~1');
      }
    } else {
      candidateRefs.push('HEAD');
    }

    for (const ref of candidateRefs) {
      if (!gitRef && isCI && headSha) {
        try {
          const resolvedSha = execFileSync('git', ['rev-parse', ref], {
            cwd: gitRoot,
            encoding: 'utf8',
            stdio: ['pipe', 'pipe', 'ignore'],
          }).trim();
          if (resolvedSha === headSha) {
            // Ref points to the newly pushed commit itself; skip self-trust!
            continue;
          }
        } catch {
          continue;
        }
      }

      let data: string | null = null;
      try {
        data = execFileSync('git', ['show', `${ref}:${gitPath}`], {
          cwd: gitRoot,
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'ignore'],
        });
      } catch {
        // Ref or file not found in ref -> try next candidate ref
        continue;
      }

      if (data !== null) {
        let parsed: unknown;
        try {
          parsed = JSON.parse(data);
        } catch (err: any) {
          throw new BaselineValidationError(
            `Malformed JSON in baseline file from Git ref '${ref}:${gitPath}': ${err.message}`
          );
        }
        return validateBaselineSchema(parsed);
      }
    }
    return null;
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

    const pkgVersion = getPackageVersion();

    const file: BaselineFile = {
      version: 1,
      generatedAt: new Date().toISOString(),
      generator: `Secret Leak Detector v${pkgVersion}`,
      findings: baselineFindings,
    };

    fs.writeFileSync(this.baselinePath, JSON.stringify(file, null, 2), 'utf8');
    return file;
  }

  public filterAgainstBaseline(
    currentFindings: SecretFinding[],
    options?: { forceFile?: boolean }
  ): {
    newFindings: SecretFinding[];
    existingFindings: SecretFinding[];
    resolvedCount: number;
    totalBaseline: number;
  } {
    const isCI = !!(process.env.CI || process.env.GITHUB_ACTIONS || process.env.GITLAB_CI);
    let baseline: BaselineFile | null = null;

    if (isCI && !options?.forceFile && !process.env.SLD_ISOLATE_BASELINE_TESTS) {
      // In CI, load baseline from trusted Git ref (PR base or event's before sha); NEVER fall back to working tree
      baseline = this.loadBaselineFromGit();
    } else {
      baseline = this.loadBaseline();
    }
    if (!baseline) {
      return {
        newFindings: currentFindings,
        existingFindings: [],
        resolvedCount: 0,
        totalBaseline: 0,
      };
    }

    const baselineByFileAndFp = new Map<string, BaselineFinding>();

    for (const b of baseline.findings) {
      const normFile = normalizeBaselinePath(b.file);
      // Key strictly by file + fingerprint so a different real secret at that line is NOT hidden
      baselineByFileAndFp.set(`${normFile}:${b.fingerprint}`, b);
    }

    const newFindings: SecretFinding[] = [];
    const existingFindings: SecretFinding[] = [];
    const matchedKeys = new Set<string>();

    for (const finding of currentFindings) {
      const normFile = normalizeBaselinePath(finding.file);
      let key = `${normFile}:${finding.fingerprint}`;
      let match = baselineByFileAndFp.get(key);

      // Backwards compatibility for multiline secrets:
      // If no match with canonical fingerprint, try alternative line endings (CRLF/LF)
      // in case the trusted baseline was generated prior to CRLF/LF canonicalization.
      if (!match && finding.rawSecret && (finding.rawSecret.includes('\n') || finding.rawSecret.includes('\r'))) {
        const salt = resolveSalt(undefined, this.workspaceRoot);
        const crlfSecret = finding.rawSecret.replace(/\r?\n/g, '\r\n');
        const crlfFp = crypto.createHmac('sha256', salt).update(crlfSecret).digest('hex').substring(0, 16);
        const crlfKey = `${normFile}:${crlfFp}`;
        if (baselineByFileAndFp.has(crlfKey)) {
          match = baselineByFileAndFp.get(crlfKey);
          key = crlfKey;
        } else {
          const lfSecret = finding.rawSecret.replace(/\r?\n/g, '\n');
          const lfFp = crypto.createHmac('sha256', salt).update(lfSecret).digest('hex').substring(0, 16);
          const lfKey = `${normFile}:${lfFp}`;
          if (baselineByFileAndFp.has(lfKey)) {
            match = baselineByFileAndFp.get(lfKey);
            key = lfKey;
          }
        }
      }

      if (match) {
        finding.status = 'BASELINE';
        existingFindings.push(finding);
        matchedKeys.add(key);
      } else {
        newFindings.push(finding);
      }
    }

    const resolvedCount = Math.max(0, baseline.findings.length - matchedKeys.size);

    return {
      newFindings,
      existingFindings,
      resolvedCount,
      totalBaseline: baseline.findings.length,
    };
  }
}
