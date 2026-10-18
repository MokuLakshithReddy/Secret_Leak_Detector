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

    const fileExists = fs.existsSync(filePath);
    let isStillInFile = false;

    if (fileExists) {
      const currentFindings = scanFile(filePath, { workspaceRoot: this.workspaceRoot });
      isStillInFile = currentFindings.some(
        (f) => f.fingerprint === finding.fingerprint || f.rawSecret === finding.rawSecret
      );
    }

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

    // File is either deleted or no longer contains the secret in the working tree.
    // Check Git history independently of current file existence.
    let gitExposure;
    let historyCheckFailed = false;

    try {
      const isGit = await this.historyEngine.isGitRepo();
      if (!isGit) {
        historyCheckFailed = true;
      } else {
        gitExposure = await this.historyEngine.traceSecret(finding.rawSecret);
      }
    } catch {
      historyCheckFailed = true;
    }

    if (historyCheckFailed || !gitExposure) {
      return {
        isResolved: true,
        targetFileClean: true,
        workingTreeClean: true,
        historyStatus: 'UNKNOWN',
        details: fileExists
          ? 'Secret removed from working tree, but Git repository history could not be verified.'
          : 'Offending file removed from working tree, but Git repository history could not be verified.',
        timestamp: now,
      };
    }

    if (gitExposure.isPresentInHistory) {
      const commitSha = gitExposure.introducedCommit?.sha ? gitExposure.introducedCommit.sha.substring(0, 7) : 'historical';
      return {
        isResolved: true,
        targetFileClean: true,
        workingTreeClean: true,
        historyStatus: 'REMOVED_FROM_HEAD_STILL_IN_HISTORY',
        details: fileExists
          ? `Secret removed from active working tree! WARNING: Secret still exists in commit history (${commitSha}). Credential revocation is mandatory.`
          : `Offending file removed from working tree, but secret still exists in commit history (${commitSha}). Credential revocation is mandatory.`,
        timestamp: now,
      };
    }

    return {
      isResolved: true,
      targetFileClean: true,
      workingTreeClean: true,
      historyStatus: 'HEAD_AND_HISTORY_CLEAN',
      details: fileExists
        ? 'Secret completely eliminated from file and no historical commits detected.'
        : 'Offending file removed from working tree and no historical commits detected in repository.',
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
