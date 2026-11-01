import * as assert from 'assert';
import * as vscode from 'vscode';

suite('Secret Leak Detector VS Code Extension Host Integration', () => {
  test('1. Extension is present in registry', () => {
    const ext = vscode.extensions.getExtension('MokuLakshithReddy.secret-leak-detector');
    assert.ok(ext, 'Extension MokuLakshithReddy.secret-leak-detector should be installed in host');
  });

  test('2. Extension activates without errors', async () => {
    const ext = vscode.extensions.getExtension('MokuLakshithReddy.secret-leak-detector');
    assert.ok(ext);
    if (!ext.isActive) {
      await ext.activate();
    }
    assert.strictEqual(ext.isActive, true, 'Extension should activate cleanly');
  });

  test('3. Registered commands match manifest', async () => {
    const commands = await vscode.commands.getCommands(true);
    const expected = [
      'secret-leak-detector.scanWorkspace',
      'secret-leak-detector.scanStaged',
      'secret-leak-detector.openDashboard',
      'secret-leak-detector.installGitHook',
      'secret-leak-detector.installGitHookStrict',
      'secret-leak-detector.uninstallGitHook',
      'secret-leak-detector.ignoreFinding',
      'secret-leak-detector.unignoreFinding',
      'secret-leak-detector.clearFindings',
    ];

    for (const cmd of expected) {
      assert.ok(commands.includes(cmd), `Command ${cmd} should be registered in extension host`);
    }
  });

  test('4. Real-time document scanner emits diagnostics on credential input', async () => {
    const fakeToken = ['ghp_', '123456789012345678901234567890123456'].join('');
    const doc = await vscode.workspace.openTextDocument({
      language: 'typescript',
      content: `// Test file\nconst GITHUB_PAT = "${fakeToken}";\n`,
    });
    await vscode.window.showTextDocument(doc);

    // Allow document change debounce (300ms)
    await new Promise((resolve) => setTimeout(resolve, 600));

    const diagnostics = vscode.languages.getDiagnostics(doc.uri);
    assert.ok(diagnostics.length > 0, 'Diagnostic should be emitted for credential in active document');
    assert.strictEqual(diagnostics[0].severity, vscode.DiagnosticSeverity.Error);
    assert.ok(diagnostics[0].message.includes('GitHub') || diagnostics[0].message.includes('Secret'));
  });
});
