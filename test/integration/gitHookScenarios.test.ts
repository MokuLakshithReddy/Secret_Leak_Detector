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
import { buildPreCommitHook, SLD_HOOK_MARKER } from '../../src/git/preCommitHook';
import { GitService } from '../../src/git/gitService';

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
  const localCli = cliPath.replace(/\\/g, '/');
  const patchedHook = buildPreCommitHook(undefined, localCli);

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

    // ── Test 6: Backup Chaining — user hook executes alongside SLD ──────────
    console.log('── Test group 6: Hook backup chaining ──────────────────────');
    const chainRepo = createTempRepo();
    const hooksDir = path.join(chainRepo, '.git', 'hooks');
    fs.mkdirSync(hooksDir, { recursive: true });
    const userHookPath = path.join(hooksDir, 'pre-commit');
    const canaryPath = path.join(chainRepo, 'canary.txt');
    // Pre-existing user hook
    fs.writeFileSync(
      userHookPath,
      `#!/bin/sh\necho "user hook ran" > "${canaryPath.replace(/\\/g, '/')}"\nexit 0\n`,
      { mode: 0o755 }
    );

    const gitServiceChain = new GitService(chainRepo, cliPath);
    const installRes = await gitServiceChain.installPreCommitHook();
    assert(installRes.success, 'SLD hook installed over existing user hook');

    // Add safe file and commit
    fs.writeFileSync(path.join(chainRepo, 'safe.txt'), 'clean content\n', 'utf8');
    execFileSync('git', ['add', 'safe.txt'], { cwd: chainRepo, stdio: 'pipe' });
    const chainCommit = tryCommit(chainRepo, 'commit with chained hook');
    assert(chainCommit.status === 0, 'Clean commit allowed with chained hook');
    assert(fs.existsSync(canaryPath), 'Chained user hook was executed and canary file was created');
    console.log('');

    // ── Test 7: Safe Uninstall — restores user hook and refuses non-SLD hooks ───
    console.log('── Test group 7: Safe hook uninstallation ──────────────────');
    const uninstallRes = await gitServiceChain.uninstallPreCommitHook();
    assert(uninstallRes.success, 'SLD hook uninstalled successfully');
    const restoredContent = fs.readFileSync(userHookPath, 'utf8');
    assert(restoredContent.includes('user hook ran'), 'Original user hook restored on uninstall');

    // Attempting to uninstall again should refuse to delete the restored user hook
    const secondUninstall = await gitServiceChain.uninstallPreCommitHook();
    assert(!secondUninstall.success, 'Uninstall refuses to delete user pre-commit hook without SLD marker');
    assert(fs.existsSync(userHookPath), 'User pre-commit hook is preserved');
    try { fs.rmSync(chainRepo, { recursive: true, force: true }); } catch {}
    console.log('');

    // ── Test 8: Subdirectory Monorepo Staged Commit ────────────────────────────
    console.log('── Test group 8: Subdirectory monorepo commit ───────────────');
    const subRepo = createTempRepo();
    installHook(subRepo, cliPath);
    const subPkgDir = path.join(subRepo, 'packages', 'core', 'src');
    fs.mkdirSync(subPkgDir, { recursive: true });
    const subSecretFile = path.join(subPkgDir, 'secret.ts');
    const fakeSubKey = synth(['AKIA', '5M9Q', '2N4V', '7P1X', '8R3Z']);
    fs.writeFileSync(subSecretFile, `export const k = "${fakeSubKey}";\n`, 'utf8');

    // Stage from inside subdirectory
    execFileSync('git', ['add', path.relative(subRepo, subSecretFile)], { cwd: subRepo, stdio: 'pipe' });
    const subCommit = spawnSync('git', ['commit', '-m', 'subpkg commit'], {
      cwd: subPkgDir,
      stdio: 'pipe',
      encoding: 'utf8',
    });
    assert(subCommit.status !== 0, 'Subdirectory commit with secret was rejected');
    assert(countCommits(subRepo) === 0, 'Subdirectory commit blocked before committing to repo');
    try { fs.rmSync(subRepo, { recursive: true, force: true }); } catch {}
    console.log('');

    // ── Test 9: Rename Staged Changes ─────────────────────────────────────────
    console.log('── Test group 9: Rename commit with secret ──────────────────');
    const renameRepo = createTempRepo();
    installHook(renameRepo, cliPath);
    const origFile = path.join(renameRepo, 'clean.ts');
    fs.writeFileSync(origFile, 'export const val = 1;\n', 'utf8');
    execFileSync('git', ['add', 'clean.ts'], { cwd: renameRepo, stdio: 'pipe' });
    execFileSync('git', ['commit', '-m', 'initial clean'], { cwd: renameRepo, stdio: 'pipe' });

    // Rename file and introduce secret
    const newFile = path.join(renameRepo, 'renamed.ts');
    const fakeRenameKey = synth(['AKIA', '8W1Y', '3K6M', '9P2T', '4V7X']);
    fs.renameSync(origFile, newFile);
    fs.writeFileSync(newFile, `export const key = "${fakeRenameKey}";\n`, 'utf8');
    execFileSync('git', ['add', '-A'], { cwd: renameRepo, stdio: 'pipe' });

    const renameCommit = tryCommit(renameRepo, 'rename with secret');
    assert(renameCommit.status !== 0, 'Commit renaming clean file and adding secret was rejected');
    assert(countCommits(renameRepo) === 1, 'Repository still has only initial commit');
    try { fs.rmSync(renameRepo, { recursive: true, force: true }); } catch {}
    console.log('');

    // ── Test 10: Stale CLI Pinning & Fail-Closed Branch ───────────────────────
    console.log('── Test group 10: Stale pin & fail-closed behavior ──────────');
    const staleRepo = createTempRepo();
    const staleHook = buildPreCommitHook(undefined, '/nonexistent/path/to/cli.js');
    const staleHookPath = path.join(staleRepo, '.git', 'hooks', 'pre-commit');
    fs.mkdirSync(path.dirname(staleHookPath), { recursive: true });
    fs.writeFileSync(staleHookPath, staleHook, { mode: 0o755 });

    fs.writeFileSync(path.join(staleRepo, 'file.txt'), 'some content\n', 'utf8');
    execFileSync('git', ['add', 'file.txt'], { cwd: staleRepo, stdio: 'pipe' });
    const staleCommit = tryCommit(staleRepo, 'stale pin commit');
    assert(staleCommit.status !== 0, 'Commit blocked when pinned CLI is missing (fail-closed contract)');
    assert(staleCommit.stdout.includes('FAIL-CLOSED') || staleCommit.stdout.includes('fail-closed') || staleCommit.stderr.includes('fail-closed'), 'Fail-closed warning output printed');

    // Test automatic re-pinning via GitService.ensureHookIsPinned
    const staleService = new GitService(staleRepo);
    const repinSuccess = await staleService.ensureHookIsPinned(cliPath);
    assert(repinSuccess, 'ensureHookIsPinned detected stale path and successfully re-pinned hook');
    const repinnedCommit = tryCommit(staleRepo, 'repinned clean commit');
    assert(repinnedCommit.status === 0, 'Clean commit allowed after automatic re-pinning');
    try { fs.rmSync(staleRepo, { recursive: true, force: true }); } catch {}
    console.log('');
  }

  // ── Test group 11: Binary commit strict fail-closed default & relaxed opt-out ──
  if (bash) {
    console.log('── Test group 11: Binary commit strict fail-closed default & relaxed opt-out ──');
    const group11Repo = createTempRepo();
    installHook(group11Repo, cliPath);

    // 1. By default (strict mode), commit containing uninspected binary file (logo.png) is BLOCKED
    const pngHeader = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00]);
    fs.writeFileSync(path.join(group11Repo, 'logo.png'), pngHeader);
    fs.writeFileSync(path.join(group11Repo, 'doc.txt'), 'clean document\n', 'utf8');
    execFileSync('git', ['add', 'logo.png', 'doc.txt'], { cwd: group11Repo, stdio: 'pipe' });

    const binCommitStrict = tryCommit(group11Repo, 'add binary logo strict');
    assert(binCommitStrict.status !== 0, 'Binary logo.png commit blocked by default strict hook (fail-closed)');

    // 2. When opted into relaxed mode via git config, binary file commit succeeds
    execFileSync('git', ['config', 'secret-leak-detector.ignore-skipped', 'true'], { cwd: group11Repo, stdio: 'pipe' });
    const binCommitRelaxed = tryCommit(group11Repo, 'add binary logo relaxed');
    assert(binCommitRelaxed.status === 0, 'Binary logo.png commit allowed when explicitly configured relaxed');

    // 3. Commit containing secret in src/dist/token.ts is BLOCKED (scoped exclude does not skip src/dist)
    const srcDistDir = path.join(group11Repo, 'src', 'dist');
    fs.mkdirSync(srcDistDir, { recursive: true });
    const awsKey = synth(['AK', 'IA', '1234567890SRCSEC']);
    fs.writeFileSync(path.join(srcDistDir, 'token.ts'), `export const apiKey = "${awsKey}";\n`, 'utf8');
    execFileSync('git', ['add', 'src/dist/token.ts'], { cwd: group11Repo, stdio: 'pipe' });

    const srcDistCommit = tryCommit(group11Repo, 'leak in src/dist');
    assert(srcDistCommit.status !== 0, 'Secret in src/dist/token.ts blocked by hook (not skipped by top-level dist/** pattern)');

    try { fs.rmSync(group11Repo, { recursive: true, force: true }); } catch {}
    console.log('');
  }

  // ── Test group 12: Node version verification fail-closed guards ─────────────
  if (bash) {
    console.log('── Test group 12: Node version verification fail-closed guards ─');
    const group12Repo = createTempRepo();
    installHook(group12Repo, cliPath);

    // Verify generated hook file contains fail-closed Node version verification
    const hookContent = fs.readFileSync(path.join(group12Repo, '.git', 'hooks', 'pre-commit'), 'utf8');
    assert(hookContent.includes('Cannot determine Node.js version. Commit blocked.'), 'Installed hook blocks when Node version query fails');
    assert(hookContent.includes('Invalid Node.js version. Commit blocked.'), 'Installed hook blocks on invalid Node version');
    assert(hookContent.includes('Node.js 18+ required'), 'Installed hook requires Node.js >=18');

    // Test with mock failing Node runtime
    const fakeBinDir = path.join(group12Repo, 'mock-bin');
    fs.mkdirSync(fakeBinDir, { recursive: true });
    fs.writeFileSync(path.join(fakeBinDir, 'node'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
    if (process.platform === 'win32') {
      fs.writeFileSync(path.join(fakeBinDir, 'node.cmd'), '@echo off\r\nexit /b 1\r\n');
    }

    fs.writeFileSync(path.join(group12Repo, 'clean.txt'), 'clean text\n', 'utf8');
    execFileSync('git', ['add', 'clean.txt'], { cwd: group12Repo, stdio: 'pipe' });

    // With mock failing node prepended to PATH, commit must be BLOCKED (fail-closed)
    const envWithFailingNode = {
      ...process.env,
      PATH: `${fakeBinDir}${path.delimiter}${process.env.PATH || ''}`,
    };
    const failNodeCommit = spawnSync('git', ['commit', '-m', 'clean with failing node'], {
      cwd: group12Repo,
      env: envWithFailingNode,
      stdio: 'pipe',
      encoding: 'utf8',
    });
    assert(failNodeCommit.status !== 0, 'Commit blocked when Node runtime query fails (fail-closed contract)');
    assert(
      failNodeCommit.stdout.includes('Cannot determine Node.js version') ||
      failNodeCommit.stderr.includes('Cannot determine Node.js version') ||
      failNodeCommit.stdout.includes('COMMIT BLOCKED') ||
      failNodeCommit.stderr.includes('COMMIT BLOCKED'),
      'Commit output informs user commit is blocked due to Node version query error'
    );

    try { fs.rmSync(group12Repo, { recursive: true, force: true }); } catch {}
    console.log('');
  }

  // ── Test group 13: Electron-pinned runtime execution with ELECTRON_RUN_AS_NODE=1 ──
  if (bash) {
    console.log('── Test group 13: Electron-pinned runtime execution ─────────');
    const group13Repo = createTempRepo();
    const fakeElectronDir = path.join(group13Repo, 'mock-electron-bin');
    fs.mkdirSync(fakeElectronDir, { recursive: true });

    // Mock Electron binary that executes scripts ONLY when ELECTRON_RUN_AS_NODE=1 is present
    const mockElectronPath = path.join(fakeElectronDir, 'electron-runner').replace(/\\/g, '/');
    fs.writeFileSync(
      mockElectronPath,
      `#!/bin/sh
if [ "$ELECTRON_RUN_AS_NODE" != "1" ]; then
  echo "Error: Electron binary invoked without ELECTRON_RUN_AS_NODE=1" >&2
  exit 1
fi
exec node "$@"
`,
      { mode: 0o755 }
    );

    // Install hook pinned to the mock electron runner
    const electronHook = buildPreCommitHook('HIGH', cliPath.replace(/\\/g, '/'), mockElectronPath);
    const hookPath13 = path.join(group13Repo, '.git', 'hooks', 'pre-commit');
    fs.writeFileSync(hookPath13, electronHook, { mode: 0o755 });

    // Add safe file and commit
    fs.writeFileSync(path.join(group13Repo, 'safe.ts'), 'export const cleanValue = 42;\n', 'utf8');
    execFileSync('git', ['add', 'safe.ts'], { cwd: group13Repo, stdio: 'pipe' });

    const electronCommit = tryCommit(group13Repo, 'commit with electron-pinned runtime');
    assert(electronCommit.status === 0, 'Clean commit allowed using Electron-pinned runtime with ELECTRON_RUN_AS_NODE=1');
    assert(countCommits(group13Repo) === 1, 'Commit recorded successfully');

    try { fs.rmSync(group13Repo, { recursive: true, force: true }); } catch {}
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
