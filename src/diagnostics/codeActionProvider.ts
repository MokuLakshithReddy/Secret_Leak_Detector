import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { DiagnosticProvider } from './diagnosticProvider';
import { SecretFinding } from '../types';

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

      // QuickFix 2: Ignore this finding
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
   * Performs the automated extraction to .env and ensures .gitignore protects .env.
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
    const gitignorePath = path.join(workspaceRoot, '.gitignore');

    // Generate appropriate environment variable name
    let envVarName = 'SECRET_KEY';
    if (finding.type.includes('AWS Access Key')) envVarName = 'AWS_ACCESS_KEY_ID';
    else if (finding.type.includes('AWS Secret')) envVarName = 'AWS_SECRET_ACCESS_KEY';
    else if (finding.type.includes('GitHub')) envVarName = 'GITHUB_TOKEN';
    else if (finding.type.includes('OpenAI')) envVarName = 'OPENAI_API_KEY';
    else if (finding.type.includes('Anthropic')) envVarName = 'ANTHROPIC_API_KEY';
    else if (finding.type.includes('Stripe')) envVarName = 'STRIPE_SECRET_KEY';
    else if (finding.type.includes('Slack')) envVarName = 'SLACK_TOKEN';
    else if (finding.type.includes('Database')) envVarName = 'DATABASE_URL';
    else {
      envVarName = `${finding.provider.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()}_API_KEY`;
    }

    // Append to .env
    const envLine = `\n${envVarName}="${finding.rawSecret}"\n`;
    try {
      fs.appendFileSync(envPath, envLine, 'utf8');
    } catch (err) {
      vscode.window.showErrorMessage(`Failed to write to .env: ${err}`);
      return;
    }

    // Ensure .env is added to .gitignore
    if (fs.existsSync(gitignorePath)) {
      const gitignoreContent = fs.readFileSync(gitignorePath, 'utf8');
      if (!gitignoreContent.includes('.env')) {
        fs.appendFileSync(gitignorePath, '\n# Credentials\n.env\n.env.*.local\n', 'utf8');
      }
    } else {
      fs.writeFileSync(gitignorePath, '# Credentials\n.env\n.env.*.local\n', 'utf8');
    }

    // Replace the secret in the active file with process.env.<NAME>
    const edit = new vscode.WorkspaceEdit();
    // Replace raw secret with process.env.NAME or "process.env.NAME"
    const replacement = `process.env.${envVarName}`;
    edit.replace(documentUri, range, replacement);
    await vscode.workspace.applyEdit(edit);

    vscode.window.showInformationMessage(
      `✅ Moved ${finding.type} to .env (${envVarName}) and protected in .gitignore!`
    );
  }
}
