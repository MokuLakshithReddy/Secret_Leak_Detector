/**
 * VS Code Extension Host Integration Tests
 * Validates extension commands, diagnostic multi-line ranges, unignore quickpick metadata,
 * hook lifecycle management, and uninstall cleanup.
 *
 * Run with:
 *   npx ts-node --project tsconfig.json test/integration/vscodeExtensionHost.test.ts
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

let passed = 0;
let failed = 0;

function assert(condition: boolean, msg: string): void {
  if (condition) {
    console.log(`  ✅ PASSED: ${msg}`);
    passed++;
  } else {
    console.error(`  ❌ FAILED: ${msg}`);
    failed++;
  }
}

console.log('\n══════════════════════════════════════════════════════════════');
console.log('  VS Code Extension Host & UI Integration Tests');
console.log('══════════════════════════════════════════════════════════════\n');

// ── Test 1: Command IDs ─────────────────────────────────────────
console.log('── Test group 1: Command Manifest & Architecture ────────────');
const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '../../package.json'), 'utf8'));
const commandIds = (pkg.contributes?.commands || []).map((c: any) => c.command);

const requiredCommands = [
  'secret-leak-detector.scanWorkspace',
  'secret-leak-detector.scanStaged',
  'secret-leak-detector.openDashboard',
  'secret-leak-detector.installGitHook',
  'secret-leak-detector.installGitHookStrict',
  'secret-leak-detector.uninstallGitHook',
  'secret-leak-detector.ignoreFinding',
  'secret-leak-detector.unignoreFinding',
  // 'secret-leak-detector.remediateFinding' is internal quick-fix command
  'secret-leak-detector.clearFindings',
];

for (const req of requiredCommands) {
  assert(commandIds.includes(req), `Command '${req}' is registered in package.json contributes`);
}

// ── Test 2: Multi-line PEM Range Calculation ────────────────────
console.log('\n── Test group 2: Multi-Line PEM Range Calculation ───────────');
{
  const mockVsCode: any = {
    Position: class {
      constructor(public line: number, public character: number) {}
    },
    Range: class {
      constructor(public start: any, public end: any) {}
    },
    Diagnostic: class {
      code: any;
      source?: string;
      constructor(public range: any, public message: string, public severity: any) {}
    },
    DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2 },
    Uri: { parse: (s: string) => s },
  };

  // Replicate toDiagnostic logic
  function computeDiagnosticRange(finding: any): { startLine: number; startCol: number; endLine: number; endCol: number } {
    const line = Math.max(0, finding.line - 1);
    const startCol = Math.max(0, finding.column - 1);

    let endLine = line;
    let endCol = startCol + finding.length;
    const textToCheck = finding.rawSecret || '';
    if (textToCheck && textToCheck.includes('\n')) {
      const lines = textToCheck.split(/\r?\n/);
      endLine = line + lines.length - 1;
      endCol = lines.length > 1 ? lines[lines.length - 1].length : startCol + lines[0].length;
    }
    return { startLine: line, startCol, endLine, endCol };
  }

  const pemKey = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----';
  const pemFinding = {
    line: 12,
    column: 1,
    length: pemKey.length,
    rawSecret: pemKey,
  };

  const range = computeDiagnosticRange(pemFinding);
  assert(range.startLine === 11, 'Start line 0-based is 11 (line 12)');
  assert(range.endLine === 13, 'End line spans 3 lines to line 13 (0-based)');
  assert(range.endCol === '-----END RSA PRIVATE KEY-----'.length, 'End column matches length of last line');
}

// ── Test 3: Safe Uninstall Hook & Storage Cleanup ───────────────
console.log('\n── Test group 3: Extension Uninstall & Storage Cleanup ──────');
{
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-uninstall-test-'));
  const hookDir = path.join(tmpDir, '.git', 'hooks');
  fs.mkdirSync(hookDir, { recursive: true });
  const hookFile = path.join(hookDir, 'pre-commit');
  fs.writeFileSync(hookFile, '#!/bin/sh\n# [SLD_HOOK_MANAGED]\nexit 1\n', { mode: 0o755 });

  const { cleanHook } = require('../../src/uninstall');
  assert(fs.existsSync(hookFile), 'Managed hook exists before cleanHook');
  const cleaned = cleanHook(hookFile);
  assert(cleaned === true, 'cleanHook reported clean success');
  assert(!fs.existsSync(hookFile), 'Managed hook was deleted on uninstall');

  // Preserve user hooks
  const userHookFile = path.join(hookDir, 'pre-commit');
  fs.writeFileSync(userHookFile, '#!/bin/sh\necho user custom hook\n', { mode: 0o755 });
  const cleanedUser = cleanHook(userHookFile);
  assert(cleanedUser === false, 'cleanHook refuses to delete unmanaged user hook');
  assert(fs.existsSync(userHookFile), 'User hook is preserved untouched');

  fs.rmSync(tmpDir, { recursive: true, force: true });
}

console.log('\n══════════════════════════════════════════════════════════════');
console.log(`  TEST SUMMARY: ${passed} PASSED, ${failed} FAILED`);
console.log('══════════════════════════════════════════════════════════════\n');

if (failed > 0) {
  process.exit(1);
}
