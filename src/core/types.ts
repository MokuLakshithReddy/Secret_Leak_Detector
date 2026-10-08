export type Risk = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type Status = 'BLOCKED' | 'RESOLVED' | 'ACTIVE' | 'BASELINE';

export type SignalType =
  | 'KNOWN_PATTERN_MATCH'
  | 'HIGH_ENTROPY'
  | 'MODERATE_ENTROPY'
  | 'LOW_ENTROPY'
  | 'SENSITIVE_IDENTIFIER'
  | 'PRODUCTION_CONFIG_FILE'
  | 'TEST_FILE_PENALTY'
  | 'DOCUMENTATION_PENALTY'
  | 'KNOWN_PLACEHOLDER_REJECTED'
  | 'GIT_HISTORICAL_EXPOSURE'
  | 'BRANCH_SPREAD_DETECTED'
  | 'REMOTE_PUSH_DETECTED';

export interface EvidenceItem {
  signal: SignalType | string;
  description: string;
  confidenceImpact: number;
  details?: Record<string, unknown>;
}

export interface EvidenceModel {
  items: EvidenceItem[];
  shannonEntropy: number;
  normalizedEntropy: number;
  characterSet: string;
  surroundingCode: {
    before: string[];
    targetLine: string;
    after: string[];
    inferredVariable?: string;
  };
  fileContext: {
    fileExtension: string;
    isConfig: boolean;
    isTest: boolean;
    isDoc: boolean;
    isSensitiveName: boolean;
    isExampleOrSample: boolean;
  };
}

export interface BlastRadius {
  level: 'CONTAINED' | 'MODERATE' | 'EXTENSIVE' | 'SEVERE';
  score: number; // 0 - 100
  workingTreeExposed: boolean;
  gitHistoryExposed: boolean;
  commitCount: number;
  branchCount: number;
  branches: string[];
  remoteExposed: boolean;
  exposureDurationDays: number;
  summary: string;
  factors: string[];
}

export interface RiskFactor {
  factor: string;
  weight: number;
  scoreContribution: number;
  explanation: string;
}

export interface RiskAssessment {
  score: number; // 0 - 100
  tier: Risk;
  factors: RiskFactor[];
  blastRadius: BlastRadius;
  summary: string;
}

export interface GitCommitInfo {
  sha: string;
  author: string;
  date: string;
  message: string;
}

export interface GitExposure {
  introducedCommit?: GitCommitInfo;
  lastModifiedCommit?: GitCommitInfo;
  removedCommit?: GitCommitInfo;
  isPresentInHead: boolean;
  isPresentInHistory: boolean;
  exposureDurationDays: number;
  branches: string[];
  isRemote: boolean;
  statusDescription: string;
}

export interface RemediationPlan {
  steps: string[];
  envVarName: string;
  replacementCode: string;
  envFileSnippet: string;
  envExampleSnippet: string;
  gitHistoryPurgeCommand: string;
  diffPreview: string;
}

export interface VerificationResult {
  isResolved: boolean;
  targetFileClean: boolean;
  workingTreeClean: boolean;
  historyStatus: 'HEAD_AND_HISTORY_CLEAN' | 'REMOVED_FROM_HEAD_STILL_IN_HISTORY' | 'NOT_FIXED';
  details: string;
  timestamp: string;
}

export interface SecretFinding {
  id: string;
  fingerprint: string;
  type: string;
  provider: string;
  file: string;
  fullPath: string;
  line: number;
  column: number;
  length: number;
  rawSecret: string;
  redactedSecret: string;
  confidence: number; // 0 - 100
  risk: Risk;
  riskAssessment: RiskAssessment;
  evidence: EvidenceModel;
  gitExposure?: GitExposure;
  remediation: RemediationPlan;
  status: Status;
  detectedAt: string;

  // Backwards-compatibility aliases
  signals?: string[];
  exampleFix?: string;
  entropy?: number;
}

export interface ScanResult {
  findings: SecretFinding[];
  filesScanned: number;
  durationMs: number;
  timestamp: string;
  isClean: boolean;
  blocked: boolean;
  riskSummary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  baselineStats?: {
    total: number;
    existing: number;
    newFindings: number;
    resolved: number;
  };
}

export interface RuleDefinition {
  id: string;
  name: string;
  provider: string;
  pattern: RegExp;
  baseConfidence: number;
  baseRiskWeight: number; // 0 - 100
  minEntropy?: number;
  signals: string[];
  suggestedEnvName: (varName?: string) => string;
  remediationInstructions: string[];
}

export interface BaselineFinding {
  id: string;
  fingerprint: string;
  ruleId: string;
  file: string;
  line: number;
  firstSeen: string;
}

export interface BaselineFile {
  version: number;
  generatedAt: string;
  generator: string;
  findings: BaselineFinding[];
}
