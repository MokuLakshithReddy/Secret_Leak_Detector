import * as vscode from 'vscode';
import { DiagnosticProvider } from './diagnosticProvider';
import { SecretFinding } from '../core/types';
import { applyControlledRemediation } from '../core/remediation/remediationEngine';

export class SecretCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];
  private diagnosticProvider: DiagnosticProvider;

  constructor(diagnosticProvider: DiagnosticProvider) {
    this.diagnosticProvider = diagnosticProvider;
  }

  public provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    // Check if any diagnostics are from Secret Leak Detector
    const secretDiagnostics = context.diagnostics.filter(
      (d) => d.source === 'Secret Leak Detector'
    );

    if (secretDiagnostics.length === 0) {
      return actions;
    }

    const allFindings = this.diagnosticProvider.getAllFindings();

    for (const diagnostic of secretDiagnostics) {
      const codeVal = typeof diagnostic.code === 'object' ? diagnostic.code?.value : diagnostic.code;
      const finding = allFindings.find((f) => f.id === codeVal);

      if (!finding) continue;

      // Ensure the diagnostic range still matches the detected rawSecret or sourceExpression
      const docTextAtRange = document.getText(diagnostic.range);
      if (
        docTextAtRange !== finding.rawSecret &&
        docTextAtRange !== finding.sourceExpression
      ) {
        continue;
      }

      // QuickFix 1: Move to .env (only for saved workspace files on disk)
      const hasWorkspaceFolder = !!vscode.workspace.getWorkspaceFolder(document.uri);
      const isRealFile = !document.isUntitled && document.uri.scheme === 'file';
      if (hasWorkspaceFolder && isRealFile) {
        const moveToEnvAction = this.createMoveToEnvAction(document, diagnostic.range, finding);
        actions.push(moveToEnvAction);
      }

      // QuickFix 2: Ignore this finding (False Positive)
      const ignoreAction = new vscode.CodeAction(
        'Ignore this finding (False Positive)',
        vscode.CodeActionKind.QuickFix
      );
      ignoreAction.command = {
        command: 'secret-leak-detector.ignoreFinding',
        title: 'Ignore Finding',
        arguments: [finding.id],
      };
      actions.push(ignoreAction);
    }

    return actions;
  }

  private createMoveToEnvAction(
    document: vscode.TextDocument,
    range: vscode.Range,
    finding: SecretFinding
  ): vscode.CodeAction {
    const action = new vscode.CodeAction(
      `🛡️ Move ${finding.type} to .env and replace with environment variable`,
      vscode.CodeActionKind.QuickFix
    );
    action.isPreferred = true;

    action.command = {
      command: 'secret-leak-detector.remediateFinding',
      title: 'Move to .env',
      arguments: [document.uri, range, finding],
    };

    return action;
  }

  /**
   * Performs automated, transactional extraction to .env with collision avoidance and rollback safety.
   */
  public static async executeRemediation(
    documentUri: vscode.Uri,
    range: vscode.Range,
    finding: SecretFinding
  ): Promise<void> {
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(documentUri);
    if (!workspaceFolder) {
      vscode.window.showErrorMessage('No workspace folder found to save .env file.');
      return;
    }

    const workspaceRoot = workspaceFolder.uri.fsPath;
    const document = await vscode.workspace.openTextDocument(documentUri);
    const docTextAtRange = document.getText(range);
    const expected = finding.sourceExpression || finding.rawSecret;
    if (docTextAtRange !== expected && docTextAtRange !== finding.rawSecret) {
      vscode.window.showErrorMessage('The secret at the target location has changed or was already removed.');
      return;
    }

    // Atomic, transactional remediation: snapshots source and .env, ensures .gitignore,
    // writes .env with 0600 mode FIRST, updates source, and rolls back cleanly on any failure.
    const result = applyControlledRemediation(finding, workspaceRoot);
    if (!result.success) {
      vscode.window.showErrorMessage(`Remediation aborted: ${result.message}`);
      return;
    }

    if (result.degradedSecurity || result.warning) {
      vscode.window.showWarningMessage(`⚠️ ${result.message}`);
    } else {
      vscode.window.showInformationMessage(`🛡️ ${result.message}`);
    }
  }
}
