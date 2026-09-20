import * as vscode from 'vscode';
import { SecretFinding, Risk } from '../types';

export class FindingsTreeProvider implements vscode.TreeDataProvider<TreeItem> {
  private _onDidChangeTreeData: vscode.EventEmitter<TreeItem | undefined | null | void> =
    new vscode.EventEmitter<TreeItem | undefined | null | void>();
  readonly onDidChangeTreeData: vscode.Event<TreeItem | undefined | null | void> =
    this._onDidChangeTreeData.event;

  private findings: SecretFinding[] = [];

  public updateFindings(findings: SecretFinding[]): void {
    this.findings = findings;
    this._onDidChangeTreeData.fire();
  }

  public getTreeItem(element: TreeItem): vscode.TreeItem {
    return element;
  }

  public getChildren(element?: TreeItem): Thenable<TreeItem[]> {
    if (!element) {
      if (this.findings.length === 0) {
        const cleanItem = new TreeItem(
          'No Leaks Detected (Safe)',
          vscode.TreeItemCollapsibleState.None
        );
        cleanItem.iconPath = new vscode.ThemeIcon('shield-check', new vscode.ThemeColor('testing.iconPassed'));
        cleanItem.description = 'Workspace is clean';
        return Promise.resolve([cleanItem]);
      }

      // Group by risk levels
      const riskOrder: Risk[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
      const categories: TreeItem[] = [];

      for (const risk of riskOrder) {
        const count = this.findings.filter((f) => f.risk === risk).length;
        if (count > 0) {
          const catItem = new TreeItem(
            `${risk} Risk (${count})`,
            vscode.TreeItemCollapsibleState.Expanded,
            risk
          );

          if (risk === 'CRITICAL') {
            catItem.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('errorForeground'));
          } else if (risk === 'HIGH') {
            catItem.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('editorWarning.foreground'));
          } else if (risk === 'MEDIUM') {
            catItem.iconPath = new vscode.ThemeIcon('info', new vscode.ThemeColor('editorInfo.foreground'));
          } else {
            catItem.iconPath = new vscode.ThemeIcon('pass', new vscode.ThemeColor('testing.iconPassed'));
          }

          categories.push(catItem);
        }
      }

      return Promise.resolve(categories);
    }

    if (element.contextValue) {
      // Risk category node - return child findings
      const risk = element.contextValue as Risk;
      const matching = this.findings.filter((f) => f.risk === risk);

      const items = matching.map((f) => {
        const item = new TreeItem(
          `${f.type}`,
          vscode.TreeItemCollapsibleState.None
        );
        item.description = `${f.file}:${f.line}`;
        item.tooltip = new vscode.MarkdownString(
          `**${f.type}** (${f.provider})\n\n` +
          `- **Risk:** ${f.risk}\n` +
          `- **Confidence:** ${f.confidence}%\n` +
          `- **Entropy:** ${f.entropy} bits/char\n` +
          `- **Secret:** \`${f.redactedSecret}\`\n\n` +
          `*${f.remediation}*`
        );
        item.iconPath = new vscode.ThemeIcon('key');

        // Clicking jumps directly to the file & line!
        item.command = {
          command: 'vscode.open',
          title: 'Jump to Secret',
          arguments: [
            vscode.Uri.file(f.fullPath),
            {
              selection: new vscode.Range(
                f.line - 1,
                f.column - 1,
                f.line - 1,
                f.column - 1 + f.length
              ),
            },
          ],
        };

        return item;
      });

      return Promise.resolve(items);
    }

    return Promise.resolve([]);
  }
}

export class OverviewTreeProvider implements vscode.TreeDataProvider<TreeItem> {
  private _onDidChangeTreeData = new vscode.EventEmitter<TreeItem | undefined | null | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private findingsCount = 0;
  private isGit = true;

  public update(count: number, isGit: boolean): void {
    this.findingsCount = count;
    this.isGit = isGit;
    this._onDidChangeTreeData.fire();
  }

  public getTreeItem(element: TreeItem): vscode.TreeItem {
    return element;
  }

  public getChildren(): Thenable<TreeItem[]> {
    const items: TreeItem[] = [];

    const statusItem = new TreeItem(
      this.findingsCount === 0 ? 'Status: Protected' : `Status: ${this.findingsCount} Leaks Active`,
      vscode.TreeItemCollapsibleState.None
    );
    statusItem.iconPath = new vscode.ThemeIcon(
      this.findingsCount === 0 ? 'check' : 'alert',
      this.findingsCount === 0 ? new vscode.ThemeColor('testing.iconPassed') : new vscode.ThemeColor('errorForeground')
    );
    items.push(statusItem);

    const scanWorkspaceItem = new TreeItem('Run Full Workspace Scan', vscode.TreeItemCollapsibleState.None);
    scanWorkspaceItem.iconPath = new vscode.ThemeIcon('search');
    scanWorkspaceItem.command = {
      command: 'secret-leak-detector.scanWorkspace',
      title: 'Scan Workspace',
    };
    items.push(scanWorkspaceItem);

    const scanStagedItem = new TreeItem('Check Git Staged Changes', vscode.TreeItemCollapsibleState.None);
    scanStagedItem.iconPath = new vscode.ThemeIcon('git-commit');
    scanStagedItem.command = {
      command: 'secret-leak-detector.scanStaged',
      title: 'Scan Staged Changes',
    };
    items.push(scanStagedItem);

    const dashboardItem = new TreeItem('Open Interactive Dashboard', vscode.TreeItemCollapsibleState.None);
    dashboardItem.iconPath = new vscode.ThemeIcon('dashboard');
    dashboardItem.command = {
      command: 'secret-leak-detector.openDashboard',
      title: 'Open Dashboard',
    };
    items.push(dashboardItem);

    const hookItem = new TreeItem('Install Pre-Commit Hook', vscode.TreeItemCollapsibleState.None);
    hookItem.iconPath = new vscode.ThemeIcon('terminal');
    hookItem.command = {
      command: 'secret-leak-detector.installGitHook',
      title: 'Install Hook',
    };
    items.push(hookItem);

    return Promise.resolve(items);
  }
}

class TreeItem extends vscode.TreeItem {
  constructor(
    label: string,
    collapsibleState: vscode.TreeItemCollapsibleState,
    contextValue?: string
  ) {
    super(label, collapsibleState);
    this.contextValue = contextValue;
  }
}
