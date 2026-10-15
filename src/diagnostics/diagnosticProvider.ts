import * as vscode from 'vscode';
import { scanContent } from '../core/scanner/scanner';
import { SecretFinding } from '../core/types';

export class DiagnosticProvider {
  private diagnosticCollection: vscode.DiagnosticCollection;
  private currentFindings: Map<string, SecretFinding[]> = new Map();
  private ignoredFindings: Set<string> = new Set();
  private onFindingsChangedEmitter = new vscode.EventEmitter<SecretFinding[]>();
  public readonly onFindingsChanged = this.onFindingsChangedEmitter.event;

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('secret-leak-detector');
  }

  public getDiagnosticCollection(): vscode.DiagnosticCollection {
    return this.diagnosticCollection;
  }

  public getAllFindings(): SecretFinding[] {
    const findings: SecretFinding[] = [];
    for (const fileFindings of this.currentFindings.values()) {
      findings.push(...fileFindings);
    }
    return findings;
  }

  public clear(): void {
    this.diagnosticCollection.clear();
    this.currentFindings.clear();
    this.onFindingsChangedEmitter.fire([]);
  }

  public ignoreFinding(findingId: string): void {
    this.ignoredFindings.add(findingId);

    for (const [filePath, findings] of this.currentFindings.entries()) {
      const remaining = findings.filter((f) => f.id !== findingId);
      if (remaining.length !== findings.length) {
        this.currentFindings.set(filePath, remaining);

        const uri = vscode.Uri.file(filePath);
        const currentDiags = this.diagnosticCollection.get(uri);
        if (currentDiags) {
          const filteredDiags = currentDiags.filter((d) => {
            const codeVal = typeof d.code === 'object' ? d.code?.value : d.code;
            return codeVal !== findingId;
          });
          this.diagnosticCollection.set(uri, filteredDiags);
        }
      }
    }

    this.onFindingsChangedEmitter.fire(this.getAllFindings());
  }

  public scanDocument(document: vscode.TextDocument): SecretFinding[] {
    // Skip virtual or output documents
    if (document.uri.scheme !== 'file') {
      return [];
    }

    const text = document.getText();
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
    const workspaceRoot = workspaceFolder ? workspaceFolder.uri.fsPath : undefined;

    const allDetected = scanContent(text, document.uri.fsPath, workspaceRoot);
    const findings = allDetected.filter((f) => !this.ignoredFindings.has(f.id));
    this.currentFindings.set(document.uri.fsPath, findings);

    const diagnostics: vscode.Diagnostic[] = [];

    for (const finding of findings) {
      const line = Math.max(0, finding.line - 1);
      const startCol = Math.max(0, finding.column - 1);
      const endCol = startCol + finding.length;
      const range = new vscode.Range(line, startCol, line, endCol);

      let severity = vscode.DiagnosticSeverity.Warning;
      if (finding.risk === 'CRITICAL' || finding.risk === 'HIGH') {
        severity = vscode.DiagnosticSeverity.Error;
      } else if (finding.risk === 'LOW') {
        severity = vscode.DiagnosticSeverity.Information;
      }

      const remediationSummary =
        typeof finding.remediation === 'string'
          ? finding.remediation
          : finding.remediation?.steps?.[0] || 'Migrate to .env';

      const diagnostic = new vscode.Diagnostic(
        range,
        `[Secret Leak Detector] ${finding.type} detected! Confidence: ${finding.confidence}%. ${remediationSummary}`,
        severity
      );

      diagnostic.code = {
        value: finding.id,
        target: vscode.Uri.parse('https://github.com/MokuLakshithReddy/Secret_Leak_Detector'),
      };
      diagnostic.source = 'Secret Leak Detector';

      diagnostics.push(diagnostic);
    }

    this.diagnosticCollection.set(document.uri, diagnostics);
    this.onFindingsChangedEmitter.fire(this.getAllFindings());
    return findings;
  }

  public removeDocument(uri: vscode.Uri): void {
    this.diagnosticCollection.delete(uri);
    this.currentFindings.delete(uri.fsPath);
    this.onFindingsChangedEmitter.fire(this.getAllFindings());
  }

  public dispose(): void {
    this.diagnosticCollection.dispose();
    this.onFindingsChangedEmitter.dispose();
  }
}
