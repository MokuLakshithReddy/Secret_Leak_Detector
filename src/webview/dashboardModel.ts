import { SecretFinding } from '../core/types';

export interface RedactedFindingView {
  id: string;
  type: string;
  provider: string;
  file: string;
  fullPath: string;
  line: number;
  column: number;
  redactedSecret: string;
  confidence: number;
  entropy: number;
  risk: string;
  remediationText: string;
  exampleFix: string;
}

/**
 * Strips rawSecret and produces a clean, redacted data model for UI rendering.
 */
export function toRedactedFindingView(f: SecretFinding): RedactedFindingView {
  const remediationText =
    typeof f.remediation === 'string'
      ? f.remediation
      : f.remediation?.steps?.join('; ') || 'Rotate and move to .env';
  const exampleFix = f.exampleFix || f.remediation?.replacementCode || '';
  return {
    id: f.id,
    type: f.type,
    provider: f.provider,
    file: f.file,
    fullPath: f.fullPath,
    line: f.line,
    column: f.column,
    redactedSecret: f.redactedSecret,
    confidence: f.confidence,
    entropy: f.entropy ?? 0,
    risk: f.risk,
    remediationText,
    exampleFix,
  };
}
