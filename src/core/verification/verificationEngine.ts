import * as fs from 'fs';
import { SecretFinding, VerificationResult } from '../types';
import { scanFile } from '../scanner/scanner';
import { GitHistoryEngine } from '../history/gitHistoryEngine';

export interface RescanComparison {
  beforeCount: number;
  afterCount: number;
  resolvedFindings: SecretFinding[];
  remainingFindings: SecretFinding[];
  newFindings: SecretFinding[];
  isFullyClean: boolean;
  summary: string;
}

export class VerificationEngine {
  private workspaceRoot: string;
  private historyEngine: GitHistoryEngine;

  constructor(workspaceRoot: string) {
    this.workspaceRoot = workspaceRoot;
    this.historyEngine = new GitHistoryEngine(workspaceRoot);
  }

  /**
   * Verifies whether a specific finding has been successfully remediated in the file and repository.
   */
  public async verifyFindingFix(finding: SecretFinding): Promise<VerificationResult> {
    const filePath = finding.fullPath;
    const now = new Date().toISOString();

    if (!fs.existsSync(filePath)) {
      return {
        isResolved: true,
        targetFileClean: true,
        workingTreeClean: true,
        historyStatus: 'HEAD_AND_HISTORY_CLEAN',
        details: 'Offending file was removed from working tree.',
        timestamp: now,
      };
    }

    const currentFindings = scanFile(filePath, { workspaceRoot: this.workspaceRoot });
    const isStillInFile = currentFindings.some(
      (f) => f.fingerprint === finding.fingerprint || f.rawSecret === finding.rawSecret
    );

    if (isStillInFile) {
      return {
        isResolved: false,
        targetFileClean: false,
        workingTreeClean: false,
        historyStatus: 'NOT_FIXED',
        details: `Secret string is still present on line ${finding.line} in ${finding.file}.`,
        timestamp: now,
      };
    }

    // Check Git history status
    const gitExposure = await this.historyEngine.traceSecret(finding.rawSecret);

    if (gitExposure.isPresentInHistory) {
      return {
        isResolved: true,
        targetFileClean: true,
        workingTreeClean: true,
        historyStatus: 'REMOVED_FROM_HEAD_STILL_IN_HISTORY',
        details: `Secret removed from active working tree! WARNING: Secret still exists in commit history (${gitExposure.introducedCommit?.sha.substring(0, 7)}). Credential revocation is mandatory.`,
        timestamp: now,
      };
    }

    return {
      isResolved: true,
      targetFileClean: true,
      workingTreeClean: true,
      historyStatus: 'HEAD_AND_HISTORY_CLEAN',
      details: 'Secret completely eliminated from file and no historical commits detected.',
      timestamp: now,
    };
  }

  /**
   * Compares before and after scan states to generate an audit-ready verification delta.
   */
  public compareScans(before: SecretFinding[], after: SecretFinding[]): RescanComparison {
    const afterFingerprints = new Set(after.map((f) => f.fingerprint));
    const beforeFingerprints = new Set(before.map((f) => f.fingerprint));

    const resolvedFindings = before.filter((f) => !afterFingerprints.has(f.fingerprint));
    const remainingFindings = after.filter((f) => beforeFingerprints.has(f.fingerprint));
    const newFindings = after.filter((f) => !beforeFingerprints.has(f.fingerprint));

    const isFullyClean = after.length === 0;
    const summary = `Before: ${before.length} finding(s) ➔ After: ${after.length} finding(s) (Resolved: ${resolvedFindings.length}, New: ${newFindings.length})`;

    return {
      beforeCount: before.length,
      afterCount: after.length,
      resolvedFindings,
      remainingFindings,
      newFindings,
      isFullyClean,
      summary,
    };
  }
}
