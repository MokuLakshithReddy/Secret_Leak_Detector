/**
 * Git Hook Integration Tests
 *
 * Proves that the Secret Leak Detector pre-commit hook ACTUALLY blocks commits
 * containing credentials and ALLOWS clean commits.
 *
 * Run with:
 *   npx ts-node --project tsconfig.json test/integration/gitHookScenarios.test.ts
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync, spawnSync } from 'child_process';
import { buildPreCommitHook } from '../../src/git/preCommitHook';

// ── Synth helper — prevents scanner from flagging this source file ────────────
function synth(parts: string[]): string {
  return parts.join('');
}

// ── Test harness ──────────────────────────────────────────────────────────────
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

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Create a temp git repo, configure user identity, return its path. */
function createTempRepo(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-hook-test-'));
  execFileSync('git', ['init'], { cwd: dir, stdio: 'pipe' });
  execFileSync('git', ['config', 'user.email', 'test@example.com'], { cwd: dir, stdio: 'pipe' });
  execFileSync('git', ['config', 'user.name', 'SLD Integration Test'], { cwd: dir, stdio: 'pipe' });
  return dir;
}

/** Write and install the SLD pre-commit hook in the given repo. */
function installHook(repoDir: string, cliPath: string): void {
  const hookScript = buildPreCommitHook();
  // Patch the hook to always use the local dist/cli.js from this repo
  const localCli = cliPath.replace(/\\/g, '/');
  const patchedHook = hookScript
    .replace(
      'if [ -f "./dist/cli.js" ]; then\n  node ./dist/cli.js scan --staged --fail-on "$SLD_FAIL_ON"',
      `if true; then\n  node "${localCli}" scan --staged --fail-on "$SLD_FAIL_ON"`
    );

  const hooksDir = path.join(repoDir, '.git', 'hooks');
  fs.mkdirSync(hooksDir, { recursive: true });
  const hookPath = path.join(hooksDir, 'pre-commit');
  fs.writeFileSync(hookPath, patchedHook, 'utf8');

  // Make executable on POSIX
  if (process.platform !== 'win32') {
    fs.chmodSync(hookPath, 0o755);
  } else {
    // On Windows, Git for Windows will execute the hook via bash if it is a
    // sh/bash script. No chmod is needed. The hook file must be present at
    // .git/hooks/pre-commit (no extension).
    // Note: pre-commit hooks on native Windows without Git Bash may not execute
    // sh scripts. This test detects that scenario and skips hook execution.
  }
}

/** Attempt a commit in the given repo. Returns the spawnSync result. */
function tryCommit(repoDir: string, message: string) {
  return spawnSync('git', ['commit', '-m', message], {
    cwd: repoDir,
    stdio: 'pipe',
    encoding: 'utf8',
  });
}

/** Count commits in the given repo. */
function countCommits(repoDir: string): number {
  const result = spawnSync('git', ['log', '--oneline'], {
    cwd: repoDir,
    stdio: 'pipe',
    encoding: 'utf8',
  });
  if (result.status !== 0 || !result.stdout.trim()) return 0;
  return result.stdout.trim().split('\n').length;
}

/** Detect whether a POSIX shell is available (required for hook execution on Windows). */
function findBash(): string | null {
  const candidates =
    process.platform === 'win32'
      ? [
          'C:\\Program Files\\Git\\bin\\bash.exe',
          'C:\\Program Files\\Git\\usr\\bin\\bash.exe',
          'C:\\Program Files (x86)\\Git\\bin\\bash.exe',
        ]
      : ['/bin/bash', '/bin/sh', '/usr/bin/bash', '/usr/bin/sh'];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  return null;
}

// ── Main test runner ──────────────────────────────────────────────────────────

export async function runGitHookIntegrationTests(): Promise<void> {
  console.log('\n══════════════════════════════════════════════════════════════');
  console.log('  Git Hook Integration Tests — Secret Leak Detector');
  console.log('══════════════════════════════════════════════════════════════\n');

  const cliPath = path.join(__dirname, '..', '..', 'dist', 'cli.js');

  // Verify CLI exists
  assert(fs.existsSync(cliPath), `CLI exists at ${cliPath}`);

  const bash = findBash();
  const hookExecutable = bash !== null;

  if (!hookExecutable) {
    console.log('  ⚠  No POSIX shell found — hook execution tests will be skipped on this platform.');
    console.log('     Install Git for Windows (which includes bash) to run hook tests.\n');
  }

  // ── Test 1: buildPreCommitHook generates a non-empty script ───────────────
  console.log('── Test group 1: Hook script generation ─────────────────────');
  const hookScript = buildPreCommitHook();
  assert(typeof hookScript === 'string', 'buildPreCommitHook returns a string');
  assert(hookScript.length > 50, 'Hook script is non-trivial (> 50 chars)');
  assert(hookScript.startsWith('#!/bin/sh'), 'Hook script starts with #!/bin/sh');
  assert(hookScript.includes('# [SLD_HOOK_MANAGED]'), 'Hook script contains SLD_HOOK_MARKER');
  assert(hookScript.includes('scan --staged'), 'Hook script invokes staged scan');
  assert(!hookScript.includes('${{ inputs'), 'Hook script contains no template literal injection points');
  console.log('');

  // ── Test 2: Hook file can be written to a temp repo ──────────────────────
  console.log('── Test group 2: Hook installation ──────────────────────────');
  const repoDir = createTempRepo();
  installHook(repoDir, cliPath);
  const hookPath = path.join(repoDir, '.git', 'hooks', 'pre-commit');
  assert(fs.existsSync(hookPath), `Hook file written at ${hookPath}`);
  const writtenHook = fs.readFileSync(hookPath, 'utf8');
  assert(writtenHook.includes('scan --staged'), 'Written hook invokes staged scan');
  console.log('');

  if (!hookExecutable) {
    // Skip live commit tests — no bash available
    console.log('── Test groups 3–5: SKIPPED (no bash on this platform) ──────');
    console.log('');
  } else {
    // ── Test 3: Commit with fake credential is REJECTED ────────────────────
    console.log('── Test group 3: Commit with credential is blocked ──────────');

    // Write a file with a synthesized fake AWS key
    const fakeKey = synth(['AKIA', '3F9K', '8M2X', '5P7Q', '9R1T']);
    const credFile = path.join(repoDir, 'config.env');
    fs.writeFileSync(credFile, `AWS_ACCESS_KEY_ID=${fakeKey}\n`, 'utf8');
    execFileSync('git', ['add', 'config.env'], { cwd: repoDir, stdio: 'pipe' });

    const blockResult = tryCommit(repoDir, 'add creds');
    assert(blockResult.status !== 0, 'Commit with fake AWS key was rejected (non-zero exit)');
    assert(countCommits(repoDir) === 0, 'Repository still has 0 commits after blocked attempt');
    console.log('');

    // ── Test 4: Clean commit SUCCEEDS after removing credential ────────────
    console.log('── Test group 4: Clean commit succeeds ──────────────────────');

    // Remove credential line — replace with env reference
    fs.writeFileSync(credFile, 'AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}\n', 'utf8');
    execFileSync('git', ['add', 'config.env'], { cwd: repoDir, stdio: 'pipe' });

    // Add a safe README
    const readmePath = path.join(repoDir, 'README.md');
    fs.writeFileSync(readmePath, '# Test Repo\nNo credentials here.\n', 'utf8');
    execFileSync('git', ['add', 'README.md'], { cwd: repoDir, stdio: 'pipe' });

    const allowResult = tryCommit(repoDir, 'safe config');
    assert(allowResult.status === 0, 'Clean commit (no credentials) was allowed (exit 0)');
    assert(countCommits(repoDir) === 1, 'Repository has exactly 1 commit after clean commit');
    console.log('');

    // ── Test 5: Second commit with credential is REJECTED again ────────────
    console.log('── Test group 5: Second credential commit is also blocked ───');

    const credFile2 = path.join(repoDir, 'secrets.env');
    const fakeKey2 = synth(['AKIA', '7B2N', '4W8Y', '6Z1C', '3V5X']);
    fs.writeFileSync(credFile2, `AWS_ACCESS_KEY_ID=${fakeKey2}\n`, 'utf8');
    execFileSync('git', ['add', 'secrets.env'], { cwd: repoDir, stdio: 'pipe' });

    const blockResult2 = tryCommit(repoDir, 'add secrets');
    assert(blockResult2.status !== 0, 'Second credential commit is rejected (non-zero exit)');
    assert(countCommits(repoDir) === 1, 'Repository still has exactly 1 commit after second block');
    console.log('');
  }

  // ── Cleanup ───────────────────────────────────────────────────────────────
  try { fs.rmSync(repoDir, { recursive: true, force: true }); } catch { /* ignore */ }

  // ── Summary ───────────────────────────────────────────────────────────────
  console.log('══════════════════════════════════════════════════════════════');
  console.log(`  TEST SUMMARY: ${passed} PASSED, ${failed} FAILED`);
  console.log('══════════════════════════════════════════════════════════════\n');

  if (failed > 0) {
    process.exit(1);
  }
}

// ── Entry point ───────────────────────────────────────────────────────────────
runGitHookIntegrationTests().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
