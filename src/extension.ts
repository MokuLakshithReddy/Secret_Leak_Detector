import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { DiagnosticProvider } from './diagnostics/diagnosticProvider';
import { SecretCodeActionProvider } from './diagnostics/codeActionProvider';
import { FindingsTreeProvider, OverviewTreeProvider } from './sidebar/findingsTreeProvider';
import { DashboardPanel } from './webview/dashboardPanel';
import { GitService } from './git/gitService';
import { SecretFinding, Risk } from './core/types';
import { DEFAULT_FAIL_ON, meetsThreshold, resolveFailOn } from './core/policy';
import { scanContent, ScannerOptions } from './core/scanner/scanner';
import { BINARY_EXTENSIONS } from './core/ignore/ignoreEngine';

let outputChannel: vscode.OutputChannel;
const changeDebounceTimers = new Map<string, NodeJS.Timeout>();

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

  context.subscriptions.push(
    vscode.window.registerTreeDataProvider('secret-leak-detector.findingsView', findingsTree)
  );
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider('secret-leak-detector.overviewView', overviewTree)
  );

  // Primary workspace root
  const firstFolder = vscode.workspace.workspaceFolders?.[0];
  const primaryRoot = firstFolder ? firstFolder.uri.fsPath : process.cwd();
  const gitService = new GitService(primaryRoot, (msg) => outputChannel.appendLine(msg));

  // Sync findings to Tree Providers and Dashboard
  diagnosticProvider.onFindingsChanged((findings) => {
    findingsTree.updateFindings(findings);
    overviewTree.update(findings.length, true);
    if (DashboardPanel.currentPanel) {
      DashboardPanel.currentPanel.updateFindings(findings);
    }
  });

  // Configuration accessor helper
  const getConfig = () => vscode.workspace.getConfiguration('secretLeakDetector');

  // Apply and listen to configuration changes
  function applyConfiguration() {
    const config = getConfig();
    const minEntropy = config.get<number>('minEntropy');
    diagnosticProvider.setMinEntropy(typeof minEntropy === 'number' && minEntropy > 0 ? minEntropy : undefined);
    const persistedIgnores = context.workspaceState.get<string[]>('ignoredFindings', []);
    diagnosticProvider.setIgnoredFindings(persistedIgnores);
  }
  applyConfiguration();

  // Stable CLI management under globalStorageUri (survives extension version upgrades)
  let activeCliPath = path.join(context.extensionPath, 'dist', 'cli.js');
  try {
    const globalStorage = context.globalStorageUri.fsPath;
    if (!fs.existsSync(globalStorage)) {
      fs.mkdirSync(globalStorage, { recursive: true });
    }
    const stableCli = path.join(globalStorage, 'cli.js');
    if (fs.existsSync(activeCliPath)) {
      fs.copyFileSync(activeCliPath, stableCli);
      activeCliPath = stableCli;
    }
  } catch {}

  // Re-pin pre-commit hooks in all workspace folders that are Git repositories
  async function pinHooksInAllFolders(cli: string) {
    const folders = vscode.workspace.workspaceFolders || [];
    const blockCommits = getConfig().get<boolean>('blockGitCommits', true);
    const configuredFailOn = resolveFailOn(getConfig().get<string>('failOn', DEFAULT_FAIL_ON));
    for (const folder of folders) {
      const gs = new GitService(folder.uri.fsPath, (msg) => outputChannel.appendLine(msg));
      if (await gs.isGitRepo()) {
        await gs.ensureHookIsPinned(cli, process.execPath, blockCommits).catch(() => {});
      }
    }
  }

  if (fs.existsSync(activeCliPath)) {
    pinHooksInAllFolders(activeCliPath).catch(() => {});
  }

  context.subscriptions.push(
    vscode.workspace.onDidChangeWorkspaceFolders(async () => {
      if (fs.existsSync(activeCliPath)) {
        await pinHooksInAllFolders(activeCliPath).catch(() => {});
      }
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration('secretLeakDetector')) {
        applyConfiguration();
        if (vscode.window.activeTextEditor) {
          diagnosticProvider.scanDocument(vscode.window.activeTextEditor.document);
        }
      }
    })
  );

  // Real-time scanning
  if (vscode.window.activeTextEditor) {
    diagnosticProvider.scanDocument(vscode.window.activeTextEditor.document);
  }

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (getConfig().get<boolean>('enableRealtimeScanning', true)) {
        diagnosticProvider.scanDocument(doc);
      }
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      if (getConfig().get<boolean>('enableRealtimeScanning', true)) {
        diagnosticProvider.scanDocument(doc);
      }
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      if (!getConfig().get<boolean>('enableRealtimeScanning', true)) return;
      const docUri = event.document.uri.toString();
      const existing = changeDebounceTimers.get(docUri);
      if (existing) clearTimeout(existing);
      const timer = setTimeout(() => {
        diagnosticProvider.scanDocument(event.document);
        changeDebounceTimers.delete(docUri);
      }, 350);
      changeDebounceTimers.set(docUri, timer);
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidDeleteFiles((event) => {
      event.files.forEach((f) => diagnosticProvider.removeDocument(f));
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidRenameFiles((event) => {
      event.files.forEach((f) => diagnosticProvider.renameDocument(f.oldUri, f.newUri));
    })
  );

  // Command: Scan Entire Workspace (Non-blocking, batch read, progress & cancellation)
  context.subscriptions.push(
    vscode.commands.registerCommand('secret-leak-detector.scanWorkspace', async () => {
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: '🔐 Scanning workspace for secret leaks...',
          cancellable: true,
        },
        async (progress, token) => {
          const excludeGlobs = getConfig().get<string[]>('excludeGlobs', []);
          const excludePattern = excludeGlobs.length > 0 ? `{${excludeGlobs.join(',')}}` : undefined;

          const MAX_SCAN_FILES = 1000;
          const files = await vscode.workspace.findFiles('**/*', excludePattern, MAX_SCAN_FILES);
          const batchMap = new Map<string, SecretFinding[]>();
          let allFindings: SecretFinding[] = [];
          let scannedCount = 0;
          let skippedCount = 0;

          const total = files.length;
          for (let i = 0; i < total; i++) {
            if (token.isCancellationRequested) {
              vscode.window.showInformationMessage('Secret Leak Detector: Workspace scan was cancelled.');
              return;
            }

            const file = files[i];
            const ext = path.extname(file.fsPath).toLowerCase();
            if (BINARY_EXTENSIONS.has(ext)) {
              skippedCount++;
              continue;
            }

            try {
              const stat = await vscode.workspace.fs.stat(file);
              if (stat.size > 5 * 1024 * 1024) {
                skippedCount++;
                continue;
              }
              const bytes = await vscode.workspace.fs.readFile(file);
              const text = Buffer.from(bytes).toString('utf8');
              const workspaceFolder = vscode.workspace.getWorkspaceFolder(file);
              const scanOpts: ScannerOptions = {
                workspaceRoot: workspaceFolder ? workspaceFolder.uri.fsPath : undefined,
                minEntropyThreshold: getConfig().get<number>('minEntropy'),
              };
              const fileFindings = scanContent(text, file.fsPath, scanOpts);
              batchMap.set(file.fsPath, fileFindings);
              allFindings.push(...fileFindings);
              scannedCount++;
            } catch {
              skippedCount++;
            }

            progress.report({
              message: `${scannedCount}/${total} files scanned`,
              increment: (1 / (total || 1)) * 100,
            });
          }

          // Atomic batch update to findings and diagnostics
          diagnosticProvider.setBatchFindings(batchMap);

          const isCapped = files.length >= MAX_SCAN_FILES;
          let notice = `Scanned ${scannedCount} files.`;
          if (isCapped) {
            notice += ` ⚠️ Scan was capped at ${MAX_SCAN_FILES} files.`;
          }
          if (skippedCount > 0) {
            notice += ` (${skippedCount} large or binary files skipped)`;
          }

          if (scannedCount === 0) {
            vscode.window.showWarningMessage(`⚠️ Workspace scan complete: 0 files were scanned. ${notice}`);
          } else if (allFindings.length === 0) {
            vscode.window.showInformationMessage(
              `✅ Scan complete: ${notice} No secrets or credentials detected!`
            );
          } else {
            const criticalCount = allFindings.filter((f) => f.risk === 'CRITICAL').length;
            vscode.window
              .showErrorMessage(
                `🚨 Found ${allFindings.length} leaked secret(s) (${criticalCount} Critical)! ${notice}`,
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

      const blockCommits = getConfig().get<boolean>('blockGitCommits', true);
      const configuredFailOn = resolveFailOn(getConfig().get<string>('failOn', DEFAULT_FAIL_ON));
      const scanResult = await gitService.scanStagedChanges();

      if (scanResult.status === 'ERROR') {
        outputChannel.appendLine(`❌ [Secret Leak Detector] Scan error: ${scanResult.error}`);
        const errMsg = blockCommits
          ? `❌ COMMIT GATE BLOCKED: Git security scan failed (${scanResult.error}). Failing closed for safety.`
          : `⚠️ Git scan encountered an error: ${scanResult.error}`;

        vscode.window.showErrorMessage(errMsg, 'View Output').then((sel) => {
          if (sel === 'View Output') {
            outputChannel.show(true);
          }
        });
        return;
      }

      if (scanResult.skippedFiles && scanResult.skippedFiles.length > 0) {
        outputChannel.appendLine(`ℹ️  Skipped ${scanResult.skippedFiles.length} binary or oversized file(s):`);
        for (const s of scanResult.skippedFiles) {
          outputChannel.appendLine(`   • ${s.path}: ${s.reason}`);
        }
      }

      if (scanResult.status === 'CLEAN') {
        outputChannel.appendLine('✅ All staged changes are clean! No credentials detected.');
        vscode.window.showInformationMessage('✅ Git staged changes are safe to commit.');
        return;
      }

      const findings = scanResult.findings;
      const blocking = findings.filter((f) => meetsThreshold(f.risk, configuredFailOn));
      const terminalMessage = gitService.formatTerminalBlockedMessage(
        blocking.length > 0 ? blocking : findings
      );
      outputChannel.appendLine(terminalMessage);

      const willBlock = blockCommits && blocking.length > 0;
      const msg = willBlock
        ? `❌ COMMIT BLOCKED: ${blocking.length} secret(s) at or above ${configuredFailOn} detected in staged changes!`
        : `⚠️ WARNING: ${findings.length} secret(s) detected in staged changes (none block at the ${configuredFailOn} threshold).`;

      vscode.window
        .showErrorMessage(msg, 'Open Dashboard', 'View Output')
        .then((sel) => {
          if (sel === 'Open Dashboard') {
            DashboardPanel.createOrShow(context.extensionUri, findings);
          } else if (sel === 'View Output') {
            outputChannel.show(true);
          }
        });
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
      const blockCommits = getConfig().get<boolean>('blockGitCommits', true);
      const configuredFailOn = resolveFailOn(getConfig().get<string>('failOn', DEFAULT_FAIL_ON));
      const result = await gitService.installPreCommitHook(activeCliPath, process.execPath, blockCommits, configuredFailOn);
      if (result.success) {
        vscode.window.showInformationMessage(`🛡️ ${result.message}`);
      } else {
        vscode.window.showErrorMessage(`Failed to install hook: ${result.message}`);
      }
    })
  );

  // Command: Uninstall Git Pre-Commit Hook
  context.subscriptions.push(
    vscode.commands.registerCommand('secret-leak-detector.uninstallGitHook', async () => {
      const result = await gitService.uninstallPreCommitHook();
      if (result.success) {
        vscode.window.showInformationMessage(`🛡️ ${result.message}`);
      } else {
        vscode.window.showErrorMessage(`Failed to uninstall hook: ${result.message}`);
      }
    })
  );

  // Command: Ignore Finding (False Positive suppression)
  context.subscriptions.push(
    vscode.commands.registerCommand('secret-leak-detector.ignoreFinding', async (findingId?: string) => {
      let targetId = findingId;
      if (!targetId) {
        const all = diagnosticProvider.getAllFindings();
        if (all.length === 0) {
          vscode.window.showInformationMessage('No active findings to ignore.');
          return;
        }
        const picked = await vscode.window.showQuickPick(
          all.map((f) => ({
            label: `${f.type} (${f.file}:${f.line})`,
            description: f.redactedSecret,
            id: f.id,
          })),
          { placeHolder: 'Select a finding to ignore (suppress as false-positive)' }
        );
        if (!picked) return;
        targetId = picked.id;
      }
      diagnosticProvider.ignoreFinding(targetId);
      const currentIgnores = diagnosticProvider.getIgnoredFindings();
      await context.workspaceState.update('ignoredFindings', currentIgnores);
      vscode.window.showInformationMessage(`🛡️ Finding marked as false-positive and suppressed.`);
    })
  );

  // Command: Unignore Finding (Restore suppressed finding)
  context.subscriptions.push(
    vscode.commands.registerCommand('secret-leak-detector.unignoreFinding', async () => {
      const ignored = diagnosticProvider.getIgnoredFindings();
      if (ignored.length === 0) {
        vscode.window.showInformationMessage('No suppressed findings to restore.');
        return;
      }
      const picked = await vscode.window.showQuickPick(
        ignored.map((id) => ({ label: id })),
        { placeHolder: 'Select a suppressed finding to restore' }
      );
      if (!picked) return;
      const updated = ignored.filter((id) => id !== picked.label);
      diagnosticProvider.setIgnoredFindings(updated);
      await context.workspaceState.update('ignoredFindings', updated);
      if (vscode.window.activeTextEditor) {
        diagnosticProvider.scanDocument(vscode.window.activeTextEditor.document);
      }
      vscode.window.showInformationMessage(`🛡️ Restored finding '${picked.label}'.`);
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
  for (const timer of changeDebounceTimers.values()) {
    clearTimeout(timer);
  }
  changeDebounceTimers.clear();
}
