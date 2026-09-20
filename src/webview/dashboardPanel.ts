import * as vscode from 'vscode';
import { SecretFinding } from '../types';

export class DashboardPanel {
  public static currentPanel: DashboardPanel | undefined;
  public static readonly viewType = 'secretLeakDetectorDashboard';

  private readonly _panel: vscode.WebviewPanel;
  private readonly _extensionUri: vscode.Uri;
  private _disposables: vscode.Disposable[] = [];
  private _findings: SecretFinding[] = [];

  public static createOrShow(extensionUri: vscode.Uri, initialFindings: SecretFinding[]) {
    const column = vscode.window.activeTextEditor
      ? vscode.window.activeTextEditor.viewColumn
      : undefined;

    if (DashboardPanel.currentPanel) {
      DashboardPanel.currentPanel._panel.reveal(column);
      DashboardPanel.currentPanel.updateFindings(initialFindings);
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      DashboardPanel.viewType,
      '🔐 Secret Leak Detector Dashboard',
      column || vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [extensionUri],
      }
    );

    DashboardPanel.currentPanel = new DashboardPanel(panel, extensionUri, initialFindings);
  }

  private constructor(
    panel: vscode.WebviewPanel,
    extensionUri: vscode.Uri,
    initialFindings: SecretFinding[]
  ) {
    this._panel = panel;
    this._extensionUri = extensionUri;
    this._findings = initialFindings;

    this._update();

    this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

    // Handle messages from webview
    this._panel.webview.onDidReceiveMessage(
      async (message) => {
        switch (message.command) {
          case 'scanWorkspace':
            vscode.commands.executeCommand('secret-leak-detector.scanWorkspace');
            return;
          case 'scanStaged':
            vscode.commands.executeCommand('secret-leak-detector.scanStaged');
            return;
          case 'installHook':
            vscode.commands.executeCommand('secret-leak-detector.installGitHook');
            return;
          case 'openFile':
            if (message.file && message.line) {
              const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(message.file));
              await vscode.window.showTextDocument(doc, {
                selection: new vscode.Range(message.line - 1, 0, message.line - 1, 0),
              });
            }
            return;
        }
      },
      null,
      this._disposables
    );
  }

  public updateFindings(findings: SecretFinding[]) {
    this._findings = findings;
    this._panel.webview.postMessage({
      command: 'updateData',
      findings: this._findings,
    });
    this._update();
  }

  public dispose() {
    DashboardPanel.currentPanel = undefined;
    this._panel.dispose();
    while (this._disposables.length) {
      const x = this._disposables.pop();
      if (x) {
        x.dispose();
      }
    }
  }

  private _update() {
    this._panel.webview.html = this._getHtmlForWebview();
  }

  private _getHtmlForWebview(): string {
    const findingsJson = JSON.stringify(this._findings);

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Secret Leak Detector</title>
  <style>
    :root {
      --bg: #0b0f17;
      --card-bg: #131926;
      --border: #1f293d;
      --text: #e2e8f0;
      --text-muted: #8492a6;
      --accent: #00e5b0;
      --critical: #ff3b3b;
      --high: #ff8c00;
      --medium: #e8b800;
      --low: #00e5b0;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      padding: 24px;
      line-height: 1.5;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
    }
    .title-area {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .title-area h1 {
      font-size: 22px;
      font-weight: 700;
      letter-spacing: -0.5px;
    }
    .badge-live {
      background: rgba(0, 229, 176, 0.15);
      color: var(--accent);
      border: 1px solid rgba(0, 229, 176, 0.3);
      padding: 3px 10px;
      border-radius: 9999px;
      font-size: 12px;
      font-weight: 600;
    }
    .btn-group {
      display: flex;
      gap: 10px;
    }
    button {
      background: var(--card-bg);
      color: var(--text);
      border: 1px solid var(--border);
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 600;
      font-size: 13px;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.2s;
    }
    button:hover {
      background: #1a2336;
      border-color: #2e3d5a;
    }
    button.primary {
      background: var(--accent);
      color: #0b0f17;
      border-color: var(--accent);
    }
    button.primary:hover {
      background: #00c799;
    }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 28px;
    }
    .stat-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px 20px;
    }
    .stat-label {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-muted);
      margin-bottom: 6px;
    }
    .stat-value {
      font-size: 28px;
      font-weight: 700;
    }
    .stat-value.critical { color: var(--critical); }
    .stat-value.high { color: var(--high); }
    .stat-value.clean { color: var(--accent); }

    .tabs {
      display: flex;
      gap: 12px;
      margin-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }
    .tab {
      padding: 10px 16px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      border-bottom: 2px solid transparent;
      color: var(--text-muted);
    }
    .tab.active {
      color: var(--accent);
      border-bottom-color: var(--accent);
    }

    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
    }
    th {
      background: #0e1420;
      padding: 12px 16px;
      color: var(--text-muted);
      font-weight: 600;
      border-bottom: 1px solid var(--border);
    }
    td {
      padding: 14px 16px;
      border-bottom: 1px solid #161e2e;
    }
    tr:hover td {
      background: rgba(255,255,255,0.02);
    }
    .tag {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
    }
    .tag-CRITICAL { background: rgba(255, 59, 59, 0.15); color: var(--critical); }
    .tag-HIGH { background: rgba(255, 140, 0, 0.15); color: var(--high); }
    .tag-MEDIUM { background: rgba(232, 184, 0, 0.15); color: var(--medium); }
    .tag-LOW { background: rgba(0, 229, 176, 0.15); color: var(--low); }

    .secret-code {
      font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace;
      background: #080b11;
      padding: 3px 8px;
      border-radius: 4px;
      border: 1px solid #1f293d;
      font-size: 12px;
      color: #93c5fd;
    }
    .file-link {
      color: #60a5fa;
      cursor: pointer;
      text-decoration: underline;
    }
    .empty-state {
      padding: 48px;
      text-align: center;
      color: var(--text-muted);
    }
    .empty-icon {
      font-size: 40px;
      margin-bottom: 12px;
    }
    .remediation-box {
      font-size: 12px;
      color: #cbd5e1;
      background: #0b0f17;
      padding: 8px 12px;
      border-radius: 6px;
      border-left: 3px solid var(--accent);
      margin-top: 6px;
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="title-area">
      <h1>🔐 Secret Leak Detector</h1>
      <span class="badge-live">LIVE MONITORING</span>
    </div>
    <div class="btn-group">
      <button onclick="scanStaged()">⚡ Scan Staged</button>
      <button class="primary" onclick="scanWorkspace()">🔍 Full Workspace Scan</button>
      <button onclick="installHook()">🛡️ Install Hook</button>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Total Leaks Detected</div>
      <div class="stat-value" id="stat-total">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Critical Risks</div>
      <div class="stat-value critical" id="stat-critical">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">High Risks</div>
      <div class="stat-value high" id="stat-high">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Commit Guardrail</div>
      <div class="stat-value clean" id="stat-guard">ACTIVE</div>
    </div>
  </div>

  <div class="tabs">
    <div class="tab active" onclick="switchTab('findings')">Active Findings</div>
    <div class="tab" onclick="switchTab('blast')">Blast Radius & Providers</div>
    <div class="tab" onclick="switchTab('workflow')">Workflow Architecture</div>
  </div>

  <div id="tab-findings" class="card">
    <table>
      <thead>
        <tr>
          <th>Risk</th>
          <th>Type / Provider</th>
          <th>File & Line</th>
          <th>Redacted Secret</th>
          <th>Confidence</th>
          <th>Entropy</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody id="findings-table-body">
      </tbody>
    </table>
    <div id="empty-state" class="empty-state" style="display: none;">
      <div class="empty-icon">🛡️</div>
      <h3>No secrets detected in current files!</h3>
      <p>Your workspace and staged commits are currently safe from credential leaks.</p>
    </div>
  </div>

  <div id="tab-blast" class="card" style="display: none; padding: 24px;">
    <h3 style="margin-bottom: 16px;">Trace & Blast Radius Analysis</h3>
    <p style="color: var(--text-muted); margin-bottom: 20px;">
      Correlates credential exposures across files and commits to prevent lateral propagation.
    </p>
    <div id="blast-content"></div>
  </div>

  <div id="tab-workflow" class="card" style="display: none; padding: 24px;">
    <h3 style="margin-bottom: 16px;">Zero-Leak Enforcement Pipeline</h3>
    <pre style="background: #080b11; padding: 18px; border-radius: 8px; font-family: monospace; color: #00e5b0; line-height: 1.6;">
DETECT (Pattern + Shannon Entropy)
   ↓
PROVE (Verification & Provider Match)
   ↓
TRACE (Blast Radius across Files/Git)
   ↓
BLOCK (Intercept git commit / git push)
   ↓
FIX (One-click Extraction to .env)
   ↓
RESCAN (Validate Safe State)
   ↓
ALLOW (Commit Proceeds)
    </pre>
  </div>

  <script>
    const vscode = acquireVsCodeApi();
    let findings = ${findingsJson};

    function render() {
      const tbody = document.getElementById('findings-table-body');
      const emptyState = document.getElementById('empty-state');
      
      const totalCount = findings.length;
      const criticalCount = findings.filter(f => f.risk === 'CRITICAL').length;
      const highCount = findings.filter(f => f.risk === 'HIGH').length;

      document.getElementById('stat-total').innerText = totalCount;
      document.getElementById('stat-critical').innerText = criticalCount;
      document.getElementById('stat-high').innerText = highCount;
      document.getElementById('stat-guard').innerText = totalCount > 0 ? 'BLOCKING' : 'READY';
      document.getElementById('stat-guard').className = totalCount > 0 ? 'stat-value critical' : 'stat-value clean';

      if (findings.length === 0) {
        tbody.innerHTML = '';
        emptyState.style.display = 'block';
        return;
      }

      emptyState.style.display = 'none';
      tbody.innerHTML = findings.map(f => \`
        <tr>
          <td><span class="tag tag-\${f.risk}">\${f.risk}</span></td>
          <td>
            <strong>\${f.type}</strong><br/>
            <span style="font-size: 11px; color: var(--text-muted)">\${f.provider}</span>
          </td>
          <td>
            <span class="file-link" onclick="openFile('\${f.fullPath.replace(/\\\\/g, '\\\\\\\\')}', \${f.line})">
              \${f.file}:\${f.line}
            </span>
          </td>
          <td><span class="secret-code">\${f.redactedSecret}</span></td>
          <td><strong>\${f.confidence}%</strong></td>
          <td>\${f.entropy} b/c</td>
          <td>
            <button onclick="openFile('\${f.fullPath.replace(/\\\\/g, '\\\\\\\\')}', \${f.line})">View Line</button>
          </td>
        </tr>
        <tr>
          <td colspan="7" style="padding-top: 0; padding-bottom: 14px; background: #0e1420;">
            <div class="remediation-box">
              <strong>Remediation:</strong> \${f.remediation}<br/>
              <code>\${f.exampleFix}</code>
            </div>
          </td>
        </tr>
      \`).join('');

      // Blast radius view
      const blastDiv = document.getElementById('blast-content');
      const providers = {};
      findings.forEach(f => {
        providers[f.provider] = (providers[f.provider] || 0) + 1;
      });

      blastDiv.innerHTML = \`
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
          <div style="background: #080b11; padding: 16px; border-radius: 6px;">
            <h4>Affected Providers</h4>
            <ul style="margin-top: 8px; padding-left: 20px;">
              \${Object.entries(providers).map(([p, count]) => \`<li><strong>\${p}</strong>: \${count} occurrence(s)</li>\`).join('')}
            </ul>
          </div>
          <div style="background: #080b11; padding: 16px; border-radius: 6px;">
            <h4>Total Exposure Surface</h4>
            <p style="margin-top: 8px;">\${totalCount} active credentials identified across \${new Set(findings.map(f => f.file)).size} file(s).</p>
          </div>
        </div>
      \`;
    }

    function switchTab(tabId) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.getElementById('tab-findings').style.display = tabId === 'findings' ? 'block' : 'none';
      document.getElementById('tab-blast').style.display = tabId === 'blast' ? 'block' : 'none';
      document.getElementById('tab-workflow').style.display = tabId === 'workflow' ? 'block' : 'none';
      event.target.classList.add('active');
    }

    function scanWorkspace() {
      vscode.postMessage({ command: 'scanWorkspace' });
    }

    function scanStaged() {
      vscode.postMessage({ command: 'scanStaged' });
    }

    function installHook() {
      vscode.postMessage({ command: 'installHook' });
    }

    function openFile(file, line) {
      vscode.postMessage({ command: 'openFile', file, line });
    }

    window.addEventListener('message', event => {
      const message = event.data;
      if (message.command === 'updateData') {
        findings = message.findings;
        render();
      }
    });

    render();
  </script>
</body>
</html>`;
  }
}
