export type Risk = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type Status = 'BLOCKED' | 'RESOLVED' | 'ACTIVE';

export interface SecretFinding {
  id: string;
  type: string;
  provider: string;
  file: string;
  fullPath: string;
  line: number;
  column: number;
  length: number;
  rawSecret: string;
  redactedSecret: string;
  risk: Risk;
  confidence: number;
  entropy: number;
  signals: string[];
  remediation: string;
  exampleFix: string;
  status: Status;
  detectedAt: string;
}

export interface ScanResult {
  findings: SecretFinding[];
  filesScanned: number;
  durationMs: number;
  timestamp: string;
  isClean: boolean;
  blocked: boolean;
}

export interface RuleDefinition {
  id: string;
  name: string;
  provider: string;
  pattern: RegExp;
  risk: Risk;
  minEntropy?: number;
  baseConfidence: number;
  signals: string[];
  remediation: string;
  exampleFix: (varName: string) => string;
}
