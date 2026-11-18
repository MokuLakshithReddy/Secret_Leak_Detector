import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { SecretFinding, BaselineFile, BaselineFinding } from '../types';
import { getPackageVersion } from '../version';
import { generateLegacyFingerprint, getFingerprintKeyId, generateFingerprint } from '../redactor/redactor';
import { scanFile } from '../scanner/scanner';

export const DEFAULT_BASELINE_FILENAME = '.secretleak-baseline.json';

export interface BaselineMigrationResult {
  migratedCount: number;
  totalFindings: number;
  unmigratedFindings: BaselineFinding[];
  previousScheme: string;
  newScheme: string;
  backupPath?: string;
  keyId: string;
}

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

  if (
    obj.fingerprintScheme !== undefined &&
    obj.fingerprintScheme !== 'hmac-sha256-private-v2' &&
    obj.fingerprintScheme !== 'hmac-sha256-public-v1'
  ) {
    throw new BaselineValidationError(`'fingerprintScheme' is not supported.`);
  }
  if (obj.fingerprintScheme === 'hmac-sha256-private-v2') {
    if (typeof obj.fingerprintKeyId !== 'string' || !/^[a-f0-9]{16}$/.test(obj.fingerprintKeyId)) {
      throw new BaselineValidationError(`Private fingerprint baselines require a valid 'fingerprintKeyId'.`);
    }
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
    if (
      obj.fingerprintScheme === 'hmac-sha256-private-v2' &&
      !/^[a-f0-9]{64}$/.test(item.fingerprint) &&
      !/^[a-f0-9]{16}$/.test(item.fingerprint)
    ) {
      throw new BaselineValidationError(
        `findings[${i}].fingerprint must be a valid hexadecimal hash (64-character private HMAC or 16-character legacy).`
      );
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

/**
 * Verifies that the baseline destination file and its parent hierarchy are safe:
 * not a symlink, not a hard link redirect (nlink <= 1), and resolve inside the workspace root.
 */
export function assertSafeBaselineDestination(
  baselinePath: string,
  workspaceRoot: string,
  purpose: 'read' | 'write' = 'write'
): void {
  let rootReal: string;
  try {
    rootReal = fs.realpathSync(workspaceRoot);
  } catch (err: any) {
    throw new BaselineValidationError(`Cannot resolve workspace root for baseline: ${err.message || err}`);
  }

  const parentDir = path.dirname(path.resolve(baselinePath));
  let parentStat: fs.Stats;
  let parentReal: string;
  try {
    parentStat = fs.lstatSync(parentDir);
    if (parentStat.isSymbolicLink() || !parentStat.isDirectory()) {
      throw new BaselineValidationError(
        `Refusing to ${purpose} baseline: parent directory '${parentDir}' must be a real directory, not a symlink.`
      );
    }
    parentReal = fs.realpathSync(parentDir);
  } catch (err: any) {
    if (err instanceof BaselineValidationError) throw err;
    throw new BaselineValidationError(`Cannot safely resolve baseline parent directory '${parentDir}': ${err.message || err}`);
  }

  const parentRelative = path.relative(rootReal, parentReal);
  if (parentRelative === '..' || parentRelative.startsWith('..' + path.sep) || path.isAbsolute(parentRelative)) {
    throw new BaselineValidationError(
      `Refusing to ${purpose} baseline: parent directory '${parentReal}' is outside the workspace root '${rootReal}'.`
    );
  }

  if (!fs.existsSync(baselinePath)) {
    if (purpose === 'read') {
      throw new BaselineValidationError(`Cannot read baseline: file '${baselinePath}' does not exist.`);
    }
    return;
  }

  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(baselinePath);
  } catch (err: any) {
    throw new BaselineValidationError(`Cannot stat baseline file '${baselinePath}': ${err.message || err}`);
  }

  if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink > 1) {
    throw new BaselineValidationError(
      `Refusing to ${purpose} baseline '${baselinePath}': expected a regular, non-symlink file with a single hard link (got nlink=${stat.nlink}, isSymlink=${stat.isSymbolicLink()}).`
    );
  }

  let fileReal: string;
  try {
    fileReal = fs.realpathSync(baselinePath);
  } catch (err: any) {
    throw new BaselineValidationError(`Cannot resolve canonical path for baseline '${baselinePath}': ${err.message || err}`);
  }

  const fileRelative = path.relative(rootReal, fileReal);
  if (fileRelative === '..' || fileRelative.startsWith('..' + path.sep) || path.isAbsolute(fileRelative)) {
    throw new BaselineValidationError(
      `Refusing to ${purpose} baseline: resolved path '${fileReal}' is outside the workspace root '${rootReal}'.`
    );
  }
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

    assertSafeBaselineDestination(this.baselinePath, this.workspaceRoot, 'read');

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

    const isCI = !process.env.SLD_ISOLATE_BASELINE_TESTS && !!(process.env.CI || process.env.GITHUB_ACTIONS || process.env.GITLAB_CI);
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
      if (isCI && headSha) {
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

  /**
   * Safely and atomically writes a baseline file to disk, validating that the target and parent
   * are not redirected via symlinks or hard links, writing to a temp file, fsyncing, and renaming.
   */
  public writeBaselineFileAtomically(file: BaselineFile, targetPath: string = this.baselinePath): BaselineFile {
    assertSafeBaselineDestination(targetPath, this.workspaceRoot, 'write');
    const parentDir = path.dirname(path.resolve(targetPath));
    let parentReal: string;
    try {
      parentReal = fs.realpathSync(parentDir);
    } catch (err: any) {
      throw new BaselineValidationError(`Cannot resolve baseline parent directory: ${err.message || err}`);
    }
    const destination = path.join(parentReal, path.basename(targetPath));
    assertSafeBaselineDestination(destination, this.workspaceRoot, 'write');

    const tempPath = path.join(
      parentReal,
      `.${path.basename(targetPath)}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`
    );
    const noFollow = process.platform === 'win32' ? 0 : (fs.constants.O_NOFOLLOW || 0);
    let fd: number | null = null;

    try {
      fd = fs.openSync(
        tempPath,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollow,
        0o600
      );
      const openedStat = fs.fstatSync(fd);
      if (!openedStat.isFile() || openedStat.nlink > 1) {
        throw new BaselineValidationError(
          `Temporary baseline file '${tempPath}' is not a regular file with a single hard link (nlink=${openedStat.nlink}).`
        );
      }

      fs.writeFileSync(fd, JSON.stringify(file, null, 2) + '\n', 'utf8');
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = null;

      const tempStat = fs.lstatSync(tempPath);
      if (tempStat.isSymbolicLink() || !tempStat.isFile() || tempStat.nlink > 1) {
        throw new BaselineValidationError('Temporary baseline file failed post-write safety verification.');
      }

      // Re-check the canonical parent immediately before replacement.
      if (fs.realpathSync(parentDir) !== parentReal) {
        throw new BaselineValidationError('Baseline parent directory changed during write; refusing to replace the baseline.');
      }
      assertSafeBaselineDestination(destination, this.workspaceRoot, 'write');
      fs.renameSync(tempPath, destination);

      const postStat = fs.lstatSync(destination);
      if (postStat.isSymbolicLink() || !postStat.isFile() || postStat.nlink > 1) {
        throw new BaselineValidationError(
          'Post-write baseline verification failed: expected a regular non-symlink file with a single hard link.'
        );
      }
      const postReal = fs.realpathSync(destination);
      const postRelative = path.relative(fs.realpathSync(this.workspaceRoot), postReal);
      if (postRelative === '..' || postRelative.startsWith('..' + path.sep) || path.isAbsolute(postRelative)) {
        throw new BaselineValidationError('Post-write baseline resolves outside the workspace root.');
      }

      try {
        const dirFd = fs.openSync(parentReal, fs.constants.O_RDONLY);
        try { fs.fsyncSync(dirFd); } finally { fs.closeSync(dirFd); }
      } catch {}
    } catch (err: any) {
      if (fd !== null) {
        try { fs.closeSync(fd); } catch {}
      }
      try { fs.unlinkSync(tempPath); } catch {}
      if (err instanceof BaselineValidationError) throw err;
      throw new BaselineValidationError(`Atomic baseline write failed: ${err.message || err}`);
    }

    return file;
  }

  public saveBaseline(findings: SecretFinding[]): BaselineFile {
    assertSafeBaselineDestination(this.baselinePath, this.workspaceRoot, 'write');

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
      fingerprintScheme: 'hmac-sha256-private-v2',
      fingerprintKeyId: getFingerprintKeyId(this.workspaceRoot),
      findings: baselineFindings,
    };

    return this.writeBaselineFileAtomically(file);
  }

  /**
   * Upgrades a baseline file to the modern hmac-sha256-private-v2 fingerprint scheme.
   * Scans referenced files in workspaceRoot to locate original credentials and recompute
   * fingerprints using the private repository salt. Only exact cryptographic legacy matches
   * are migrated; proximity heuristics are strictly prohibited to prevent newly introduced
   * secrets from being inadvertently whitelisted. Unresolved entries require explicit
   * manual reconciliation or allowPartial: true.
   */
  public migrateBaseline(options?: {
    customSalt?: string;
    dryRun?: boolean;
    createBackup?: boolean;
    allowPartial?: boolean;
    dropUnresolved?: boolean;
  }): BaselineMigrationResult {
    const baseline = this.loadBaseline();
    if (!baseline) {
      throw new BaselineValidationError(`Cannot migrate baseline: file '${this.baselinePath}' does not exist.`);
    }

    const previousScheme = baseline.fingerprintScheme || 'hmac-sha256-public-v1';
    const targetKeyId = options?.customSalt
      ? crypto.createHash('sha256').update(options.customSalt.trim()).digest('hex').substring(0, 16)
      : getFingerprintKeyId(this.workspaceRoot);

    const fileScanCache = new Map<string, SecretFinding[]>();
    const unmigratedFindings: BaselineFinding[] = [];
    let migratedCount = 0;

    const updatedFindings: BaselineFinding[] = [];

    for (const f of baseline.findings) {
      if (
        previousScheme === 'hmac-sha256-private-v2' &&
        baseline.fingerprintKeyId === targetKeyId &&
        /^[a-f0-9]{64}$/.test(f.fingerprint)
      ) {
        migratedCount++;
        updatedFindings.push({ ...f });
        continue;
      }

      const normRelFile = normalizeBaselinePath(f.file);
      const fullPath = path.resolve(this.workspaceRoot, normRelFile);

      let scannedFindings: SecretFinding[] | undefined = fileScanCache.get(fullPath);
      if (!scannedFindings) {
        if (fs.existsSync(fullPath)) {
          try {
            scannedFindings = scanFile(fullPath, { workspaceRoot: this.workspaceRoot });
          } catch {
            scannedFindings = [];
          }
        } else {
          scannedFindings = [];
        }
        fileScanCache.set(fullPath, scannedFindings);
      }

      const match = scannedFindings.find((sf) => {
        if (!sf.rawSecret) return false;
        const legCandidates = [
          generateLegacyFingerprint(sf.rawSecret),
          generateLegacyFingerprint(sf.rawSecret.replace(/\r?\n/g, '\r\n'), false),
          generateLegacyFingerprint(sf.rawSecret.replace(/\r?\n/g, '\n'), false),
        ];
        return legCandidates.includes(f.fingerprint);
      });

      if (match && match.rawSecret) {
        const newFingerprint = options?.customSalt
          ? generateFingerprint(match.rawSecret, options.customSalt, this.workspaceRoot)
          : match.fingerprint;

        updatedFindings.push({
          ...f,
          fingerprint: newFingerprint,
          line: match.line,
        });
        migratedCount++;
      } else {
        unmigratedFindings.push(f);
      }
    }

    if (unmigratedFindings.length > 0 && !options?.allowPartial && !options?.dryRun) {
      throw new BaselineValidationError(
        `Migration aborted: ${unmigratedFindings.length} baseline finding(s) could not be resolved by exact cryptographic legacy match in the workspace. Pass allowPartial: true (--allow-partial) to proceed with partial migration, or reconcile these findings manually.`
      );
    }

    // Explicit handling for partial migrations: preserve unresolved findings
    // unless dropUnresolved is explicitly true.
    const finalFindings: BaselineFinding[] = [...updatedFindings];
    if (unmigratedFindings.length > 0 && options?.allowPartial && !options?.dropUnresolved) {
      for (const uf of unmigratedFindings) {
        finalFindings.push({ ...uf });
      }
    }

    const backupPath = this.baselinePath + '.bak';
    if (!options?.dryRun && options?.createBackup !== false) {
      this.writeBaselineFileAtomically(baseline, backupPath);
    }

    const migratedFile: BaselineFile = {
      version: 1,
      generatedAt: new Date().toISOString(),
      generator: `Secret Leak Detector v${getPackageVersion()}`,
      fingerprintScheme: 'hmac-sha256-private-v2',
      fingerprintKeyId: targetKeyId,
      findings: finalFindings,
    };

    if (!options?.dryRun) {
      this.writeBaselineFileAtomically(migratedFile);
    }

    return {
      migratedCount,
      totalFindings: baseline.findings.length,
      unmigratedFindings,
      previousScheme,
      newScheme: 'hmac-sha256-private-v2',
      backupPath: options?.createBackup !== false ? backupPath : undefined,
      keyId: targetKeyId,
    };
  }

  /**
   * Restores a baseline file from its .bak backup file, verifying backup safety and
   * replacing the active baseline atomically.
   */
  public rollbackBaseline(): { restored: boolean; backupPath: string } {
    const backupPath = this.baselinePath + '.bak';
    if (!fs.existsSync(backupPath)) {
      throw new BaselineValidationError(`Cannot rollback baseline: backup file '${backupPath}' does not exist.`);
    }

    assertSafeBaselineDestination(backupPath, this.workspaceRoot, 'read');

    let backupData: string;
    try {
      backupData = fs.readFileSync(backupPath, 'utf8');
    } catch (err: any) {
      throw new BaselineValidationError(`Could not read baseline backup at '${backupPath}': ${err.message || err}`);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(backupData);
    } catch (err: any) {
      throw new BaselineValidationError(`Malformed JSON in baseline backup '${backupPath}': ${err.message || err}`);
    }

    const validFile = validateBaselineSchema(parsed);
    this.writeBaselineFileAtomically(validFile);

    return { restored: true, backupPath };
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
    const isCI = !process.env.SLD_ISOLATE_BASELINE_TESTS && !!(process.env.CI || process.env.GITHUB_ACTIONS || process.env.GITLAB_CI);
    let baseline: BaselineFile | null = null;

    if (isCI && !options?.forceFile && !process.env.SLD_ISOLATE_BASELINE_TESTS) {
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

    const isLegacyBaseline =
      baseline.fingerprintScheme === undefined ||
      baseline.fingerprintScheme === 'hmac-sha256-public-v1';

    if (baseline.fingerprintScheme === 'hmac-sha256-private-v2') {
      const currentKeyId = getFingerprintKeyId(this.workspaceRoot);
      if (currentKeyId !== baseline.fingerprintKeyId) {
        throw new BaselineValidationError(
          'Fingerprint key mismatch: this baseline was created with a different private salt. Configure the same SLD_SALT value in this environment, or initialize a new baseline after coordinating the key with your team.'
        );
      }
    }

    const baselineByFileAndFp = new Map<string, BaselineFinding>();
    for (const entry of baseline.findings) {
      const normFile = normalizeBaselinePath(entry.file);
      baselineByFileAndFp.set(`${normFile}:${entry.fingerprint}`, entry);
    }

    const newFindings: SecretFinding[] = [];
    const existingFindings: SecretFinding[] = [];
    const matchedKeys = new Set<string>();

    for (const finding of currentFindings) {
      const normFile = normalizeBaselinePath(finding.file);
      let key = `${normFile}:${finding.fingerprint}`;
      let match = baselineByFileAndFp.get(key);

      // Legacy public-salt fingerprints are consulted when finding did not match directly,
      // supporting pre-v2 baselines as well as unmigrated entries in partially-migrated baselines.
      if (!match && finding.rawSecret) {
        const legacyCandidates = [
          generateLegacyFingerprint(finding.rawSecret),
          generateLegacyFingerprint(finding.rawSecret.replace(/\r?\n/g, '\r\n'), false),
          generateLegacyFingerprint(finding.rawSecret.replace(/\r?\n/g, '\n'), false),
        ];
        for (const legacyFingerprint of legacyCandidates) {
          const legacyKey = `${normFile}:${legacyFingerprint}`;
          const legacyMatch = baselineByFileAndFp.get(legacyKey);
          if (legacyMatch) {
            match = legacyMatch;
            key = legacyKey;
            break;
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
