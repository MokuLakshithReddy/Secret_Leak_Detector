import * as fs from 'fs';
import * as path from 'path';
import { SecretFinding, BaselineFile, BaselineFinding } from '../types';

export const DEFAULT_BASELINE_FILENAME = '.secretleak-baseline.json';

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

  public loadBaseline(): BaselineFile | null {
    try {
      if (!this.exists()) return null;
      const data = fs.readFileSync(this.baselinePath, 'utf8');
      return JSON.parse(data) as BaselineFile;
    } catch {
      return null;
    }
  }

  public saveBaseline(findings: SecretFinding[]): BaselineFile {
    const baselineFindings: BaselineFinding[] = findings.map((f) => ({
      id: f.id,
      fingerprint: f.fingerprint,
      ruleId: f.type,
      file: f.file,
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
      // Key by fingerprint or file+rule
      baselineMap.set(b.fingerprint, b);
      baselineMap.set(`${b.file}:${b.ruleId}:${b.line}`, b);
    }

    const newFindings: SecretFinding[] = [];
    const existingFindings: SecretFinding[] = [];
    const matchedFingerprints = new Set<string>();

    for (const finding of currentFindings) {
      const match =
        baselineMap.get(finding.fingerprint) ||
        baselineMap.get(`${finding.file}:${finding.type}:${finding.line}`);

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
