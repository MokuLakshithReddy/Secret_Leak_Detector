#!/usr/bin/env node
'use strict';

/**
 * Scan only files introduced or changed by an untrusted pull request.
 * This path does not load the private-keyed repository baseline and strips
 * any private fingerprint-key override from the scanner child environment.
 */
const cp = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const MAX_CHANGED_FILES = 5000;
const MAX_DIFF_BYTES = 64 * 1024 * 1024;
const MAX_SCAN_OUTPUT_BYTES = 32 * 1024 * 1024;

function git(args, cwd, options = {}) {
  return cp.execFileSync('git', args, {
    cwd,
    encoding: options.encoding,
    maxBuffer: options.maxBuffer || MAX_DIFF_BYTES,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function emptySarif() {
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'Secret Leak Detector',
          informationUri: 'https://github.com/MokuLakshithReddy/Secret_Leak_Detector',
          rules: [],
        },
      },
      results: [],
    }],
  };
}

function parseSarif(stdout, filePath) {
  let report;
  try {
    report = JSON.parse(stdout);
  } catch {
    throw new Error(`Scanner returned invalid SARIF for changed file "${filePath}".`);
  }
  if (
    !report ||
    report.version !== '2.1.0' ||
    !Array.isArray(report.runs) ||
    report.runs.length !== 1 ||
    !report.runs[0] ||
    !report.runs[0].tool ||
    !report.runs[0].tool.driver ||
    !Array.isArray(report.runs[0].results)
  ) {
    throw new Error(`Scanner returned an incomplete SARIF report for changed file "${filePath}".`);
  }
  return report;
}

function scanChangedFiles(options = {}) {
  const workspaceRoot = path.resolve(options.workspaceRoot || process.cwd());
  const baseRef = options.baseRef;
  const cliPath = path.resolve(options.cliPath || path.join(__dirname, '..', 'dist', 'cli.js'));

  if (typeof baseRef !== 'string' || !baseRef.trim()) {
    throw new Error('A pull-request base commit SHA is required.');
  }
  if (!fs.existsSync(cliPath)) {
    throw new Error(`Built scanner CLI is missing: ${cliPath}`);
  }

  const baseSha = String(git([
    'rev-parse', '--verify', '--quiet', '--end-of-options', `${baseRef}^{commit}`,
  ], workspaceRoot, { encoding: 'utf8' })).trim();
  if (!/^[0-9a-f]{40,64}$/i.test(baseSha)) {
    throw new Error('Git did not resolve the pull-request base to a commit.');
  }

  // NUL-delimited names correctly handle whitespace, quotes, and newlines.
  const rawDiff = git([
    'diff', '--name-only', '-z', '--diff-filter=ACMRT', `${baseSha}...HEAD`, '--',
  ], workspaceRoot);
  const changedPaths = rawDiff.toString('utf8').split('\0').filter(Boolean);
  if (changedPaths.length > MAX_CHANGED_FILES) {
    throw new Error(`Pull request changes ${changedPaths.length} files; limit is ${MAX_CHANGED_FILES}. Refusing an incomplete scan.`);
  }

  const sarif = emptySarif();
  const mergedRules = new Map();
  let blockingFinding = false;
  let scannedFiles = 0;
  const childEnv = { ...process.env };
  delete childEnv.SLD_SALT;
  delete childEnv.SLD_FINGERPRINT_SALT;

  for (const repoPath of changedPaths) {
    const absolutePath = path.resolve(workspaceRoot, repoPath);
    const relativePath = path.relative(workspaceRoot, absolutePath);
    if (
      !relativePath ||
      relativePath === '..' ||
      relativePath.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relativePath)
    ) {
      throw new Error(`Changed path escapes the checkout: "${repoPath}".`);
    }

    let stat;
    try {
      stat = fs.lstatSync(absolutePath);
    } catch (error) {
      throw new Error(`Could not inspect changed file "${repoPath}": ${error.message || error}`);
    }
    if (stat.isSymbolicLink() || !stat.isFile()) {
      throw new Error(`Changed path "${repoPath}" is not a regular file; refusing to skip it in a security scan.`);
    }

    const cliTarget = `./${relativePath.split(path.sep).join('/')}`;
    let stdout = '';
    let status = 0;
    try {
      stdout = cp.execFileSync(process.execPath, [
        cliPath, 'scan', cliTarget, '--sarif', '--fail-on', 'HIGH',
      ], {
        cwd: workspaceRoot,
        env: childEnv,
        encoding: 'utf8',
        maxBuffer: MAX_SCAN_OUTPUT_BYTES,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (error) {
      status = Number.isInteger(error.status) ? error.status : 2;
      stdout = error.stdout ? String(error.stdout) : '';
      if (status !== 1) {
        const diagnostic = error.stderr ? String(error.stderr).trim() : '';
        throw new Error(`Scanner failed for changed file "${repoPath}" (exit ${status})${diagnostic ? `: ${diagnostic.slice(0, 1200)}` : '.'}`);
      }
    }

    const report = parseSarif(stdout, repoPath);
    const run = report.runs[0];
    const currentRun = sarif.runs[0];
    if (scannedFiles === 0) {
      sarif.runs[0].tool.driver = { ...run.tool.driver, rules: [] };
    }

    for (const rule of (run.tool.driver.rules || [])) {
      if (rule.id && !mergedRules.has(rule.id)) mergedRules.set(rule.id, rule);
    }
    currentRun.results.push(...run.results);

    if (status === 1) blockingFinding = true;
    scannedFiles++;
  }

  sarif.runs[0].tool.driver.rules = Array.from(mergedRules.values());
  return {
    sarif,
    exitCode: blockingFinding ? 1 : 0,
    changedFiles: changedPaths.length,
    scannedFiles,
  };
}

function runGitForTest(args, cwd) {
  cp.execFileSync('git', args, { cwd, stdio: 'ignore' });
}

function selfTest() {
  const cliPath = path.resolve(__dirname, '..', 'dist', 'cli.js');
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-dependabot-scan-test-'));
  try {
    runGitForTest(['init', '-q'], tempRoot);
    runGitForTest(['config', 'user.name', 'SLD CI Test'], tempRoot);
    runGitForTest(['config', 'user.email', 'sld-ci-test@example.invalid'], tempRoot);

    fs.writeFileSync(path.join(tempRoot, '.gitignore'), '.sld/\\n', 'utf8');
    fs.writeFileSync(path.join(tempRoot, 'README.txt'), 'Clean baseline fixture.\\n', 'utf8');
    runGitForTest(['add', '--', '.gitignore', 'README.txt'], tempRoot);
    runGitForTest(['commit', '-m', 'baseline fixture'], tempRoot);
    const baseSha = String(git(['rev-parse', 'HEAD'], tempRoot, { encoding: 'utf8' })).trim();

    const secret = ['AKIA', '1234567890ABCDEF'].join('');
    const nested = path.join(tempRoot, 'folder with spaces');
    fs.mkdirSync(nested, { recursive: true });
    fs.writeFileSync(path.join(nested, 'credential fixture.txt'), `AWS_ACCESS_KEY_ID="${secret}"\n`, 'utf8');
    runGitForTest(['add', '--', 'folder with spaces/credential fixture.txt'], tempRoot);
    runGitForTest(['commit', '-m', 'add synthetic credential fixture'], tempRoot);

    const withFinding = scanChangedFiles({ workspaceRoot: tempRoot, baseRef: baseSha, cliPath });
    const serialized = JSON.stringify(withFinding.sarif);
    if (withFinding.exitCode !== 1 || withFinding.scannedFiles !== 1 || !withFinding.sarif.runs[0].results.length) {
      throw new Error('Changed-file scanner regression test failed to detect the synthetic AWS fixture.');
    }
    if (serialized.includes(secret)) {
      throw new Error('Changed-file scanner included an unredacted credential in SARIF.');
    }

    const headSha = String(git(['rev-parse', 'HEAD'], tempRoot, { encoding: 'utf8' })).trim();
    const unchanged = scanChangedFiles({ workspaceRoot: tempRoot, baseRef: headSha, cliPath });
    if (unchanged.exitCode !== 0 || unchanged.scannedFiles !== 0 || unchanged.sarif.runs[0].results.length !== 0) {
      throw new Error('Changed-file scanner should emit a clean SARIF report when no files changed.');
    }

    fs.rmSync(path.join(nested, 'credential fixture.txt'), { force: true });
    runGitForTest(['add', '-A'], tempRoot);
    runGitForTest(['commit', '-m', 'delete credential fixture'], tempRoot);
    const deleted = scanChangedFiles({ workspaceRoot: tempRoot, baseRef: headSha, cliPath });
    if (deleted.exitCode !== 0 || deleted.scannedFiles !== 0) {
      throw new Error('Deleted paths should not be treated as scan targets.');
    }

    console.log('Changed-file scanner self-test passed: NUL-safe paths, secret detection, redacted SARIF, empty diff, and deletions.');
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

if (require.main === module) {
  try {
    if (process.argv.includes('--self-test')) {
      selfTest();
    } else {
      const result = scanChangedFiles({ baseRef: process.argv[2] });
      process.stdout.write(`${JSON.stringify(result.sarif, null, 2)}\n`);
      process.exitCode = result.exitCode;
    }
  } catch (error) {
    console.error(`Changed-file scan failed closed: ${error.message || error}`);
    process.exitCode = 2;
  }
}

module.exports = { emptySarif, parseSarif, scanChangedFiles };
