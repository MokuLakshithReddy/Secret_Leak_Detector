import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { DiagnosticProvider } from './diagnosticProvider';
import { SecretFinding } from '../core/types';
import {
  escapeEnvValue,
  resolveUniqueEnvVarName,
  ensureGitignoreProtectsEnv,
} from '../core/remediation/remediationEngine';

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
      // Find matching finding
      const finding = allFindings.find(
        (f) =>
          f.fullPath === document.uri.fsPath &&
          f.line === diagnostic.range.start.line + 1
      );

      if (!finding) continue;

      // QuickFix 1: Move to .env
      const moveToEnvAction = this.createMoveToEnvAction(document, diagnostic.range, finding);
      actions.push(moveToEnvAction);

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
    const envPath = path.join(workspaceRoot, '.env');

    // 1. Generate suggested environment variable name
    let suggestedName = finding.remediation?.envVarName;
    if (!suggestedName) {
      if (finding.type.includes('AWS Access Key')) suggestedName = 'AWS_ACCESS_KEY_ID';
      else if (finding.type.includes('AWS Secret')) suggestedName = 'AWS_SECRET_ACCESS_KEY';
      else if (finding.type.includes('GitHub')) suggestedName = 'GITHUB_TOKEN';
      else if (finding.type.includes('OpenAI')) suggestedName = 'OPENAI_API_KEY';
      else if (finding.type.includes('Anthropic')) suggestedName = 'ANTHROPIC_API_KEY';
      else if (finding.type.includes('Stripe')) suggestedName = 'STRIPE_SECRET_KEY';
      else if (finding.type.includes('Slack')) suggestedName = 'SLACK_TOKEN';
      else if (finding.type.includes('Database')) suggestedName = 'DATABASE_URL';
      else {
        suggestedName = `${finding.provider.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()}_API_KEY`;
      }
    }

    // 2. Read existing .env if present and determine unique non-colliding variable name
    let existingEnvContent = '';
    let hadExistingEnv = false;
    if (fs.existsSync(envPath)) {
      hadExistingEnv = true;
      try {
        existingEnvContent = fs.readFileSync(envPath, 'utf8');
      } catch (err) {
        vscode.window.showErrorMessage(`Failed to read .env file: ${err}`);
        return;
      }
    }

    const { varName, isReused } = resolveUniqueEnvVarName(
      existingEnvContent,
      suggestedName,
      finding.rawSecret
    );

    // 3. Ensure .gitignore protects .env BEFORE any credentials are saved to disk
    try {
      ensureGitignoreProtectsEnv(workspaceRoot);
    } catch (err) {
      vscode.window.showErrorMessage(`Failed to verify .gitignore security: ${err}`);
      return;
    }

    // 4. Apply WorkspaceEdit to replace the secret with process.env.<VAR_NAME>
    const replacement = `process.env.${varName}`;
    const edit = new vscode.WorkspaceEdit();
    edit.replace(documentUri, range, replacement);

    const editSuccess = await vscode.workspace.applyEdit(edit);
    if (!editSuccess) {
      vscode.window.showErrorMessage(
        'Failed to modify source document. Remediation aborted with zero file alterations.'
      );
      return;
    }

    // 5. If source file was successfully updated, write escaped value to .env
    const escapedSecret = escapeEnvValue(finding.rawSecret);
    const envLine = `${varName}="${escapedSecret}"\n`;

    try {
      if (!isReused) {
        const prefix = existingEnvContent.endsWith('\n') || existingEnvContent.length === 0 ? '' : '\n';
        fs.appendFileSync(envPath, `${prefix}${envLine}`, 'utf8');
      }

      // Update .env.example
      const envExamplePath = path.join(workspaceRoot, '.env.example');
      const exampleLine = `${varName}=your_${varName.toLowerCase()}_here\n`;
      if (!fs.existsSync(envExamplePath) || !fs.readFileSync(envExamplePath, 'utf8').includes(varName)) {
        const exContent = fs.existsSync(envExamplePath) ? fs.readFileSync(envExamplePath, 'utf8') : '';
        const exPrefix = exContent.endsWith('\n') || exContent.length === 0 ? '' : '\n';
        fs.appendFileSync(envExamplePath, `${exPrefix}${exampleLine}`, 'utf8');
      }
    } catch (err) {
      // Rollback source code change if writing .env fails
      const rollbackEdit = new vscode.WorkspaceEdit();
      rollbackEdit.replace(documentUri, range, finding.rawSecret);
      await vscode.workspace.applyEdit(rollbackEdit);

      vscode.window.showErrorMessage(
        `Failed to write to .env: ${err}. Document edit was safely rolled back.`
      );
      return;
    }

    vscode.window.showInformationMessage(
      `✅ Moved ${finding.type} to .env (${varName}) and verified .gitignore protection!`
    );
  }
}
