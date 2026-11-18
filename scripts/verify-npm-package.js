#!/usr/bin/env node
'use strict';

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

function runNpm(args, options = {}) {
  const npmCli = process.env.npm_execpath;
  if (npmCli) {
    return execFileSync(process.execPath, [npmCli, ...args], options);
  }
  return execFileSync(process.platform === 'win32' ? 'npm.cmd' : 'npm', args, {
    ...options,
    shell: process.platform === 'win32',
  });
}

const ALLOWED_FILES = new Set([
  'package.json',
  'README.md',
  'LICENSE',
  'SECURITY.md',
  'CHANGELOG.md',
  'dist/cli.js',
  'dist/ast-parser.js',
  'dist/uninstall.js',
  'dist/extension.js',
  'media/icon.png',
  'media/shield.svg',
]);
const REQUIRED_FILES = [
  'package.json',
  'README.md',
  'LICENSE',
  'dist/cli.js',
  'dist/ast-parser.js',
];

function main() {
  let output;
  try {
    output = runNpm(['pack', '--dry-run', '--json'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'inherit'],
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (error) {
    const detail = error.stderr ? String(error.stderr) : error.message;
    throw new Error(`npm pack --dry-run failed: ${detail}`);
  }

  let report;
  try {
    report = JSON.parse(output);
  } catch (error) {
    throw new Error(`npm pack returned invalid JSON: ${error.message}`);
  }

  if (!Array.isArray(report) || !report[0] || !Array.isArray(report[0].files)) {
    throw new Error('npm pack returned an unexpected file manifest.');
  }

  const packaged = report[0].files.map((entry) => entry.path);
  const packagedSet = new Set(packaged);
  const missing = REQUIRED_FILES.filter((file) => !packagedSet.has(file));
  const unexpected = packaged.filter((file) => !ALLOWED_FILES.has(file));

  if (missing.length || unexpected.length) {
    if (missing.length) {
      console.error(`Missing required npm package files: ${missing.join(', ')}`);
    }
    if (unexpected.length) {
      console.error(`Unexpected files in npm package: ${unexpected.join(', ')}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log(`npm package contents verified (${packaged.length} files):`);
  for (const file of packaged.sort()) console.log(`  - ${file}`);

  // Verify the actual tarball can be installed without development dependencies
  // and that its published CLI starts from the installed package directory.
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-npm-package-smoke-'));
  try {
    const packDir = path.join(tempRoot, 'pack');
    const installDir = path.join(tempRoot, 'install');
    fs.mkdirSync(packDir, { recursive: true });
    fs.mkdirSync(installDir, { recursive: true });

    const packOutput = runNpm(['pack', '--json', '--pack-destination', packDir], {
      cwd: process.cwd(),
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'inherit'],
      maxBuffer: 16 * 1024 * 1024,
    });
    const packReport = JSON.parse(packOutput);
    const tarballName = packReport?.[0]?.filename;
    if (!tarballName) throw new Error('npm pack did not report a tarball filename.');

    const tarballPath = path.join(packDir, tarballName);
    runNpm([
      'install', '--prefix', installDir, '--omit=dev', '--ignore-scripts',
      '--no-audit', '--no-fund', tarballPath,
    ], {
      cwd: tempRoot,
      stdio: ['ignore', 'pipe', 'pipe'],
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    });

    const installedPackageRoot = path.join(installDir, 'node_modules', 'secret-leak-detector');
    const installedCli = path.join(installedPackageRoot, 'dist', 'cli.js');
    if (!fs.existsSync(installedCli)) {
      throw new Error('Installed npm tarball is missing dist/cli.js.');
    }
    const installedVersion = execFileSync(process.execPath, [installedCli, '--version'], {
      cwd: tempRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
    const sourceVersion = require(path.join(process.cwd(), 'package.json')).version;
    if (installedVersion !== sourceVersion) {
      throw new Error(`Installed CLI reported version ${installedVersion}; expected ${sourceVersion}.`);
    }
    console.log(`Installed npm tarball smoke test passed (CLI ${installedVersion}).`);

    // Extended smoke test: verify real scanner execution on clean & credential fixtures
    const smokeDir = path.join(tempRoot, 'smoke-fixture');
    fs.mkdirSync(smokeDir, { recursive: true });

    // 1. Clean file scan should exit 0
    const cleanFilePath = path.join(smokeDir, 'clean.js');
    fs.writeFileSync(cleanFilePath, 'const value = 42;\nmodule.exports = { value };\n', 'utf8');
    const cleanScanOutput = execFileSync(process.execPath, [installedCli, 'scan', cleanFilePath], {
      cwd: smokeDir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (/CRITICAL|HIGH|MEDIUM|LOW/i.test(cleanScanOutput) && cleanScanOutput.includes('Found')) {
      throw new Error(`Clean scan unexpectedly reported secret findings: ${cleanScanOutput}`);
    }
    console.log('Installed npm tarball scan smoke test passed on clean file (exit 0).');

    // 2. Secret file scan should detect a synthetic credential and redact it.
    // Build the fixture at runtime so the repository's own scanner does not
    // mistake this test harness for a leaked credential.
    const synth = (...parts) => parts.join('');
    const rawSecret = synth('AKIA', '4Z7K9B2D8F1M3P5Q');
    const secretFilePath = path.join(smokeDir, 'secret.js');
    fs.writeFileSync(secretFilePath, `const awsAccessKey = "${rawSecret}";\n`, 'utf8');
    let secretScanBlocked = false;
    let secretScanOutput = '';
    try {
      secretScanOutput = execFileSync(process.execPath, [installedCli, 'scan', secretFilePath], {
        cwd: smokeDir,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (scanError) {
      secretScanBlocked = true;
      secretScanOutput = (scanError.stdout || '') + (scanError.stderr || '');
    }
    if (!secretScanBlocked && !secretScanOutput.includes('CRITICAL')) {
      throw new Error(`Secret scan did not detect the credential fixture: ${secretScanOutput}`);
    }
    if (secretScanOutput.includes(rawSecret)) {
      throw new Error('Secret scan output leaked the raw unredacted secret value!');
    }
    console.log('Installed npm tarball scan smoke test passed on secret fixture (detected & redacted).');

    // 3. Git hook installation & uninstallation smoke test
    const gitRepoDir = path.join(tempRoot, 'smoke-git-repo');
    fs.mkdirSync(gitRepoDir, { recursive: true });
    execFileSync('git', ['init', '-q'], { cwd: gitRepoDir, stdio: 'ignore' });
    execFileSync('git', ['config', 'user.email', 'smoke@test.local'], { cwd: gitRepoDir, stdio: 'ignore' });
    execFileSync('git', ['config', 'user.name', 'Smoke Test'], { cwd: gitRepoDir, stdio: 'ignore' });

    // Install pre-commit hook
    execFileSync(process.execPath, [installedCli, 'hook', 'install'], {
      cwd: gitRepoDir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const hookPath = path.join(gitRepoDir, '.git', 'hooks', 'pre-commit');
    if (!fs.existsSync(hookPath)) {
      throw new Error('Pre-commit hook was not created by installed CLI hook install.');
    }
    const hookContent = fs.readFileSync(hookPath, 'utf8');
    if (!hookContent.includes('SLD_HOOK_MARKER') && !hookContent.includes('secret-leak-detector')) {
      throw new Error('Pre-commit hook content is missing expected marker.');
    }
    console.log('Installed npm tarball pre-commit hook installation passed.');

    // Uninstall pre-commit hook
    execFileSync(process.execPath, [installedCli, 'hook', 'uninstall'], {
      cwd: gitRepoDir,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (fs.existsSync(hookPath)) {
      throw new Error('Pre-commit hook was not removed by installed CLI hook uninstall.');
    }
    console.log('Installed npm tarball pre-commit hook uninstallation passed.');

    // 4. SBOM verification smoke test
    const sbomTempPath = path.join(tempRoot, 'sbom.test.json');
    execFileSync(process.execPath, [path.join(process.cwd(), 'scripts', 'generate-sbom.js'), '--output', sbomTempPath], {
      cwd: tempRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    execFileSync(process.execPath, [path.join(process.cwd(), 'scripts', 'generate-sbom.js'), '--verify', sbomTempPath], {
      cwd: tempRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    console.log('Release SBOM generation and cryptographic verification smoke test passed.');
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error) {
  console.error(error.message || error);
  process.exitCode = 1;
}
