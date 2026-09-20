import * as vscode from 'vscode';
import { DiagnosticProvider } from './diagnostics/diagnosticProvider';
import { SecretCodeActionProvider } from './diagnostics/codeActionProvider';
import { FindingsTreeProvider, OverviewTreeProvider } from './sidebar/findingsTreeProvider';
import { DashboardPanel } from './webview/dashboardPanel';
import { GitService } from './git/gitService';
import { scanContent } from './engine/scanner';
import { SecretFinding } from './types';

let outputChannel: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext) {
  outputChannel = vscode.window.createOutputChannel('Secret Leak Detector');
  context.subscriptions.push(outputChannel);

  outputChannel.appendLine('🔐 [Secret Leak Detector] Extension activated.');

  // Initialize Diagnostic and Code Action Providers
  const diagnosticProvider = new DiagnosticProvider();
  context.subscriptions.push(diagnosticProvider);

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      { scheme: 'file' },
      new SecretCodeActionProvider(diagnosticProvider),
      { providedCodeActionKinds: SecretCodeActionProvider.providedCodeActionKinds }
    )
  );

  // Initialize Sidebar Tree Views
  const findingsTree = new FindingsTreeProvider();
  const overviewTree = new OverviewTreeProvider();

  vscode.window.registerTreeDataProvider('secret-leak-detector.findingsView', findingsTree);
  vscode.window.registerTreeDataProvider('secret-leak-detector.overviewView', overviewTree);

  // Workspace Root & Git Service
  const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
  const workspaceRoot = workspaceFolder ? workspaceFolder.uri.fsPath : process.cwd();
  const gitService = new GitService(workspaceRoot);

  // Sync findings to Tree Providers and Dashboard
  diagnosticProvider.onFindingsChanged((findings) => {
    findingsTree.updateFindings(findings);
    overviewTree.update(findings.length, true);
    if (DashboardPanel.currentPanel) {
      DashboardPanel.currentPanel.updateFindings(findings);
    }
  });

  // Real-time Scanning on open and save
  const config = vscode.workspace.getConfiguration('secretLeakDetector');
  if (config.get<boolean>('enableRealtimeScanning', true)) {
    if (vscode.window.activeTextEditor) {
      diagnosticProvider.scanDocument(vscode.window.activeTextEditor.document);
    }

    context.subscriptions.push(
      vscode.workspace.onDidSaveTextDocument((doc) => {
        diagnosticProvider.scanDocument(doc);
      })
    );

    context.subscriptions.push(
      vscode.workspace.onDidOpenTextDocument((doc) => {
        diagnosticProvider.scanDocument(doc);
      })
    );

    context.subscriptions.push(
      vscode.workspace.onDidCloseTextDocument((doc) => {
        diagnosticProvider.removeDocument(doc.uri);
      })
    );
  }

  // Command: Scan Entire Workspace
  context.subscriptions.push(
    vscode.commands.registerCommand('secret-leak-detector.scanWorkspace', async () => {
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: '🔐 Scanning workspace for secret leaks...',
          cancellable: false,
        },
        async (progress) => {
          const excludeGlobs = config.get<string[]>('excludeGlobs', []);
          const excludePattern = `{${excludeGlobs.join(',')}}`;

          const files = await vscode.workspace.findFiles('**/*', excludePattern, 1000);
          let allFindings: SecretFinding[] = [];
          let scannedCount = 0;

          for (const file of files) {
            try {
              const doc = await vscode.workspace.openTextDocument(file);
              const findings = diagnosticProvider.scanDocument(doc);
              allFindings.push(...findings);
              scannedCount++;
            } catch {
              // Ignore binary or inaccessible files
            }
          }

          if (allFindings.length === 0) {
            vscode.window.showInformationMessage(
              `✅ Scan complete: Scanned ${scannedCount} files. No secrets or credentials detected!`
            );
          } else {
            const criticalCount = allFindings.filter((f) => f.risk === 'CRITICAL').length;
            vscode.window
              .showErrorMessage(
                `🚨 Found ${allFindings.length} leaked secret(s) (${criticalCount} Critical)! Commits may be blocked.`,
                'Open Dashboard',
                'View Findings'
              )
              .then((selection) => {
                if (selection === 'Open Dashboard') {
                  vscode.commands.executeCommand('secret-leak-detector.openDashboard');
                } else if (selection === 'View Findings') {
                  vscode.commands.executeCommand('workbench.view.extension.secret-leak-detector-sidebar');
                }
              });
          }
        }
      );
    })
  );

  // Command: Scan Staged Changes
  context.subscriptions.push(
    vscode.commands.registerCommand('secret-leak-detector.scanStaged', async () => {
      outputChannel.clear();
      outputChannel.appendLine('🔐 [Secret Leak Detector] Scanning Git staged changes...');
      outputChannel.show(true);

      const stagedFindings = await gitService.scanStagedChanges();

      if (stagedFindings.length === 0) {
        outputChannel.appendLine('✅ All staged changes are clean! No credentials detected.');
        vscode.window.showInformationMessage('✅ Git staged changes are safe to commit.');
      } else {
        const terminalMessage = gitService.formatTerminalBlockedMessage(stagedFindings);
        outputChannel.appendLine(terminalMessage);

        vscode.window
          .showErrorMessage(
            `❌ COMMIT BLOCKED: ${stagedFindings.length} secret(s) detected in staged changes!`,
            'Open Dashboard',
            'View Output'
          )
          .then((sel) => {
            if (sel === 'Open Dashboard') {
              DashboardPanel.createOrShow(context.extensionUri, stagedFindings);
            }
          });
      }
    })
  );

  // Command: Open Webview Dashboard
  context.subscriptions.push(
    vscode.commands.registerCommand('secret-leak-detector.openDashboard', () => {
      DashboardPanel.createOrShow(context.extensionUri, diagnosticProvider.getAllFindings());
    })
  );

  // Command: Install Git Pre-Commit Hook
  context.subscriptions.push(
    vscode.commands.registerCommand('secret-leak-detector.installGitHook', async () => {
      const result = await gitService.installPreCommitHook();
      if (result.success) {
        vscode.window.showInformationMessage(`🛡️ ${result.message}`);
      } else {
        vscode.window.showErrorMessage(`Failed to install hook: ${result.message}`);
      }
    })
  );

  // Command: Remediate Finding (.env extraction)
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'secret-leak-detector.remediateFinding',
      async (documentUri: vscode.Uri, range: vscode.Range, finding: SecretFinding) => {
        await SecretCodeActionProvider.executeRemediation(documentUri, range, finding);
      }
    )
  );

  // Command: Clear Findings
  context.subscriptions.push(
    vscode.commands.registerCommand('secret-leak-detector.clearFindings', () => {
      diagnosticProvider.clear();
      vscode.window.showInformationMessage('Secret Leak Detector: All findings cleared.');
    })
  );

  // Check initial workspace git status
  gitService.isGitRepo().then((isGit) => {
    overviewTree.update(0, isGit);
  });
}

export function deactivate() {
  if (outputChannel) {
    outputChannel.dispose();
  }
}
