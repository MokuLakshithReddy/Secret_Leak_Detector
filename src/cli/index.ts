#!/usr/bin/env node
import * as path from 'path';
import * as fs from 'fs';
import { scanFile, scanContent, buildScanResult } from '../core/scanner/scanner';
import { GitHistoryEngine } from '../core/history/gitHistoryEngine';
import { BaselineEngine, DEFAULT_BASELINE_FILENAME } from '../core/baseline/baselineEngine';
import { VerificationEngine } from '../core/verification/verificationEngine';
import { applyControlledRemediation } from '../core/remediation/remediationEngine';
import { formatAsSarif } from '../core/sarif/sarifFormatter';
import { SecretFinding, Risk } from '../core/types';

const args = process.argv.slice(2);
const command = args[0] || 'help';

async function main() {
  const cwd = process.cwd();

  switch (command) {
    case 'scan':
      await runScan(args.slice(1), cwd);
      break;

    case 'history':
      await runHistory(args.slice(1), cwd);
      break;

    case 'trace':
      await runTrace(args.slice(1), cwd);
      break;

    case 'baseline':
      await runBaseline(args.slice(1), cwd);
      break;

    case 'fix':
      await runFix(args.slice(1), cwd);
      break;

    case 'verify':
      await runVerify(args.slice(1), cwd);
      break;

    case 'hook':
      await runHook(args.slice(1), cwd);
      break;

    case 'help':
    default:
      printHelp();
      break;
  }
}

function printHelp() {
  console.log(`
🔐 Secret Leak Detector CLI — Context-Aware Secret Protection & History Analysis

Usage:
  secret-leak-detector <command> [options]

Commands:
  scan [target]          Scan working tree or file for exposed credentials
                         Options:
                           --json             Output findings in JSON format
                           --sarif            Output findings in SARIF v2.1.0 (for CI/CD)
                           --baseline <file>  Evaluate against baseline (pass on known secrets)
                           --staged           Scan only Git staged changes (pre-commit check)
                           --fail-on <tier>   Exit code 1 on tier: CRITICAL (default), HIGH, MEDIUM

  history                Scan Git commit history for previously introduced credentials
                         Options:
                           --max <n>          Number of commits to inspect (default: 100)

  trace <secret>         Trace a credential's commit provenance, duration, and blast radius

  baseline init          Generate or update .secretleak-baseline.json with existing findings

  fix <file>             Controlled interactive remediation (diff preview & .env migration)
                         Options:
                           --dry-run          Preview patch without modifying files

  verify <file>          Rescan and verify that credential exposure has been eliminated

  hook install           Install standalone pre-commit hook in .git/hooks/pre-commit

Examples:
  npx secret-leak-detector scan . --sarif > results.sarif
  npx secret-leak-detector scan --staged
  npx secret-leak-detector history --max 50
  npx secret-leak-detector baseline init
`);
}

async function runScan(cmdArgs: string[], cwd: string) {
  const isJson = cmdArgs.includes('--json');
  const isSarif = cmdArgs.includes('--sarif');
  const isStaged = cmdArgs.includes('--staged');
  const baselineIdx = cmdArgs.indexOf('--baseline');
  const baselineFile = baselineIdx !== -1 ? cmdArgs[baselineIdx + 1] : undefined;

  const failOnIdx = cmdArgs.indexOf('--fail-on');
  const failOn: Risk = (failOnIdx !== -1 ? cmdArgs[failOnIdx + 1]?.toUpperCase() : 'CRITICAL') as Risk;

  let targetPath = cmdArgs.find((a) => !a.startsWith('--') && a !== baselineFile && a !== failOn) || '.';
  const absPath = path.resolve(cwd, targetPath);

  const startTime = Date.now();
  let findings: SecretFinding[] = [];
  let filesScanned = 0;

  if (isStaged) {
    const gitEngine = new GitHistoryEngine(cwd);
    const isGit = await gitEngine.isGitRepo();
    if (!isGit) {
      console.error('Error: Not a Git repository.');
      process.exit(1);
    }
    // Scan staged diff
    const { execSync } = require('child_process');
    try {
      const stdout = execSync('git diff --cached --unified=0', { cwd, encoding: 'utf8' });
      if (stdout.trim()) {
        const fileDiffs = stdout.split(/^diff --git /m);
        for (const diff of fileDiffs) {
          if (!diff.trim()) continue;
          const match = diff.match(/^[ab]\/(.+?) [ab]\/(.+)/m) || diff.match(/^\+\+\+ b\/(.+)/m);
          const fname = match ? match[1] : 'staged-file';
          const addedLines = diff
            .split('\n')
            .filter((l: string) => l.startsWith('+') && !l.startsWith('+++'))
            .map((l: string) => l.substring(1))
            .join('\n');
          if (addedLines.trim()) {
            findings.push(...scanContent(addedLines, fname, { workspaceRoot: cwd }));
            filesScanned++;
          }
        }
      }
    } catch (e: any) {
      console.error(`Git diff failed: ${e.message}`);
      process.exit(1);
    }
  } else {
    // Scan directory or single file
    const filesToScan: string[] = [];
    collectFiles(absPath, filesToScan, cwd);
    filesScanned = filesToScan.length;

    for (const file of filesToScan) {
      findings.push(...scanFile(file, { workspaceRoot: cwd }));
    }
  }

  // Baseline filtering if enabled
  let baselineStats: any;
  if (baselineFile || fs.existsSync(path.join(cwd, DEFAULT_BASELINE_FILENAME))) {
    const baselineEngine = new BaselineEngine(cwd, baselineFile || DEFAULT_BASELINE_FILENAME);
    if (baselineEngine.exists()) {
      const filtered = baselineEngine.filterAgainstBaseline(findings);
      baselineStats = {
        total: findings.length,
        existing: filtered.existingFindings.length,
        newFindings: filtered.newFindings.length,
        resolved: filtered.resolvedCount,
      };
      // Only report new findings for blocking
      findings = filtered.newFindings;
    }
  }

  const durationMs = Date.now() - startTime;
  const scanResult = buildScanResult(findings, filesScanned, durationMs);
  if (baselineStats) scanResult.baselineStats = baselineStats;

  if (isSarif) {
    console.log(JSON.stringify(formatAsSarif(findings), null, 2));
    processExitCheck(findings, failOn);
    return;
  }

  if (isJson) {
    console.log(JSON.stringify(scanResult, null, 2));
    processExitCheck(findings, failOn);
    return;
  }

  // Human-Readable Colored Output
  console.log('\n============================================================');
  console.log('🔍 SECRET LEAK DETECTOR SCAN RESULTS');
  console.log('============================================================');
  console.log(`Files Scanned:    ${filesScanned}`);
  console.log(`Duration:         ${durationMs}ms`);
  console.log(`Active Leaks:     ${findings.length}`);

  if (baselineStats) {
    console.log(`Baseline Active:  ${baselineStats.existing} known finding(s) ignored`);
    console.log(`New Exposures:    ${baselineStats.newFindings}`);
    console.log(`Resolved:         ${baselineStats.resolved}`);
  }

  if (findings.length === 0) {
    console.log('\n✅ ALL CLEAN! No secrets or credentials detected.');
    console.log('============================================================\n');
    process.exit(0);
  }

  console.log('\n🚨 DETECTED CREDENTIAL FINDINGS:\n');

  findings.forEach((f, idx) => {
    console.log(`------------------------------------------------------------`);
    console.log(`Finding #${idx + 1}: ${f.type} (${f.provider})`);
    console.log(`File:        ${f.file}:${f.line}:${f.column}`);
    console.log(`Secret:      ${f.redactedSecret}`);
    console.log(`Confidence:  ${f.confidence}%`);
    console.log(`Risk Score:  ${f.riskAssessment.score}/100 [${f.risk}]`);
    console.log(`Blast Radius: ${f.riskAssessment.blastRadius.level} (${f.riskAssessment.blastRadius.summary})`);
    console.log(`\nEvidence:`);
    f.evidence.items.forEach((item) => {
      console.log(`  • [${item.confidenceImpact >= 0 ? '+' : ''}${item.confidenceImpact}] ${item.description}`);
    });
    console.log(`\nSuggested Fix:`);
    console.log(`  ${f.remediation.replacementCode}`);
    console.log(`  Add to .env: ${f.remediation.envFileSnippet}`);
  });

  console.log('============================================================\n');
  processExitCheck(findings, failOn);
}

function processExitCheck(findings: SecretFinding[], failOn: Risk) {
  const riskLevels: Record<Risk, number> = {
    CRITICAL: 4,
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1,
  };

  const threshold = riskLevels[failOn] || 4;
  const shouldFail = findings.some((f) => (riskLevels[f.risk] || 0) >= threshold);

  if (shouldFail) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

async function runHistory(cmdArgs: string[], cwd: string) {
  const maxIdx = cmdArgs.indexOf('--max');
  const maxCommits = maxIdx !== -1 ? parseInt(cmdArgs[maxIdx + 1], 10) : 100;

  console.log(`\n⏳ Scanning Git commit history (last ${maxCommits} commits) for historical leaks...`);
  const historyEngine = new GitHistoryEngine(cwd);

  const findings = await historyEngine.scanHistoryCommits(maxCommits);

  if (findings.length === 0) {
    console.log('✅ No historical secret exposures detected in inspected commits.');
    process.exit(0);
  }

  console.log(`\n⚠️ DETECTED ${findings.length} HISTORICAL SECRET EXPOSURE(S) IN GIT LOG:\n`);
  findings.forEach((f, idx) => {
    console.log(`------------------------------------------------------------`);
    console.log(`Historical Finding #${idx + 1}: ${f.type}`);
    console.log(`Commit:      ${f.gitExposure?.introducedCommit?.sha.substring(0, 8)} (${f.gitExposure?.introducedCommit?.date})`);
    console.log(`Author:      ${f.gitExposure?.introducedCommit?.author}`);
    console.log(`Secret:      ${f.redactedSecret}`);
    console.log(`Status:      ${f.gitExposure?.statusDescription}`);
    console.log(`Risk:        ${f.risk} (Score ${f.riskAssessment.score}/100)`);
    console.log(`Purge CMD:   ${f.remediation.gitHistoryPurgeCommand}`);
  });
  console.log('------------------------------------------------------------\n');
  process.exit(1);
}

async function runTrace(cmdArgs: string[], cwd: string) {
  const secret = cmdArgs[0];
  if (!secret) {
    console.error('Usage: secret-leak-detector trace <secret-string>');
    process.exit(1);
  }

  console.log(`\n🔍 Tracing provenance and exposure for credential...`);
  const historyEngine = new GitHistoryEngine(cwd);
  const exposure = await historyEngine.traceSecret(secret);

  console.log('\n============================================================');
  console.log('📊 GIT PROVENANCE & BLAST RADIUS TRACE');
  console.log('============================================================');
  console.log(`Status:             ${exposure.statusDescription}`);
  console.log(`In Active HEAD:     ${exposure.isPresentInHead ? 'YES 🚨' : 'NO (Deleted from HEAD)'}`);
  console.log(`In Git History:     ${exposure.isPresentInHistory ? 'YES ⚠️ (Must be rotated)' : 'NO'}`);
  console.log(`Exposure Duration:  ${exposure.exposureDurationDays} days`);
  console.log(`Exposed Branches:   ${exposure.branches.join(', ')}`);
  console.log(`Remote Pushed:      ${exposure.isRemote ? 'YES (External exposure!)' : 'Local only'}`);

  if (exposure.introducedCommit) {
    console.log(`Introduced By:      ${exposure.introducedCommit.author} <${exposure.introducedCommit.sha.substring(0, 7)}>`);
    console.log(`Commit Date:        ${exposure.introducedCommit.date}`);
    console.log(`Commit Message:     "${exposure.introducedCommit.message}"`);
  }

  console.log('============================================================\n');
}

async function runBaseline(cmdArgs: string[], cwd: string) {
  const subCommand = cmdArgs[0] || 'init';
  if (subCommand !== 'init' && subCommand !== 'update') {
    console.error('Usage: secret-leak-detector baseline [init|update]');
    process.exit(1);
  }

  console.log(`\n📦 Initializing baseline for workspace: ${cwd}`);
  const files: string[] = [];
  collectFiles(cwd, files, cwd);

  const findings: SecretFinding[] = [];
  for (const f of files) {
    findings.push(...scanFile(f, { workspaceRoot: cwd }));
  }

  const baselineEngine = new BaselineEngine(cwd);
  const baseline = baselineEngine.saveBaseline(findings);

  console.log(`✅ Saved ${baseline.findings.length} findings to ${DEFAULT_BASELINE_FILENAME}.`);
  console.log('Future CI scans will only fail on newly introduced secrets!\n');
}

async function runFix(cmdArgs: string[], cwd: string) {
  const targetFile = cmdArgs[0];
  const isDryRun = cmdArgs.includes('--dry-run');

  if (!targetFile) {
    console.error('Usage: secret-leak-detector fix <file> [--dry-run]');
    process.exit(1);
  }

  const absPath = path.resolve(cwd, targetFile);
  const findings = scanFile(absPath, { workspaceRoot: cwd });

  if (findings.length === 0) {
    console.log(`✅ No secrets detected in ${targetFile}.`);
    process.exit(0);
  }

  console.log(`\n🔧 Found ${findings.length} secret(s) in ${targetFile}. Controlled Remediation Plan:\n`);

  for (const f of findings) {
    console.log(`--- Finding: ${f.type} (${f.redactedSecret}) ---`);
    console.log(f.remediation.diffPreview);
    console.log('');

    if (!isDryRun) {
      const result = applyControlledRemediation(f, cwd);
      if (result.success) {
        console.log(`✅ Applied fix: ${result.message}`);
      } else {
        console.error(`❌ Failed: ${result.message}`);
      }
    }
  }

  if (isDryRun) {
    console.log('ℹ️ Dry-run mode: No files were changed. Omit --dry-run to apply patch.');
  }
}

async function runVerify(cmdArgs: string[], cwd: string) {
  const targetFile = cmdArgs[0];
  if (!targetFile) {
    console.error('Usage: secret-leak-detector verify <file>');
    process.exit(1);
  }

  const absPath = path.resolve(cwd, targetFile);
  const currentFindings = scanFile(absPath, { workspaceRoot: cwd });

  console.log('\n============================================================');
  console.log(`🔍 RESCAN VERIFICATION: ${targetFile}`);
  console.log('============================================================');

  if (currentFindings.length === 0) {
    console.log('✅ TARGET FILE VERIFIED CLEAN! No remaining credentials found.');
  } else {
    console.log(`❌ REMAINING EXPOSURES: Found ${currentFindings.length} secret(s) still present:`);
    currentFindings.forEach((f) => {
      console.log(`  • Line ${f.line}: ${f.type} (${f.redactedSecret})`);
    });
  }

  console.log('============================================================\n');
}

async function runHook(cmdArgs: string[], cwd: string) {
  const subCommand = cmdArgs[0] || 'install';
  if (subCommand === 'install') {
    const gitEngine = new GitHistoryEngine(cwd);
    if (!(await gitEngine.isGitRepo())) {
      console.error('Error: Current directory is not a Git repository.');
      process.exit(1);
    }

    const hooksDir = path.join(cwd, '.git', 'hooks');
    if (!fs.existsSync(hooksDir)) fs.mkdirSync(hooksDir, { recursive: true });

    const hookFile = path.join(hooksDir, 'pre-commit');
    const hookScript = `#!/bin/sh
# Secret Leak Detector Pre-Commit Hook
echo "🔐 [Secret Leak Detector] Inspecting staged changes..."
npx --no-install secret-leak-detector scan --staged --fail-on CRITICAL
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "❌ COMMIT REJECTED: Unredacted credentials found in staged commit!"
  echo "Run 'npx secret-leak-detector fix <file>' or migrate credentials to .env."
  exit 1
fi
exit 0
`;
    fs.writeFileSync(hookFile, hookScript, { mode: 0o755 });
    console.log(`✅ Pre-commit hook successfully installed to ${hookFile}`);
  }
}

function collectFiles(currentPath: string, fileList: string[], rootDir: string) {
  if (!fs.existsSync(currentPath)) return;
  const stat = fs.statSync(currentPath);

  if (stat.isFile()) {
    fileList.push(currentPath);
    return;
  }

  const entries = fs.readdirSync(currentPath);
  const EXCLUDES = [
    'node_modules',
    '.git',
    'dist',
    'build',
    '.next',
    'coverage',
    '.vscode',
  ];

  for (const entry of entries) {
    if (EXCLUDES.includes(entry)) continue;
    const full = path.join(currentPath, entry);
    const s = fs.statSync(full);
    if (s.isDirectory()) {
      collectFiles(full, fileList, rootDir);
    } else if (s.isFile()) {
      // Exclude binary and lockfiles
      if (!entry.endsWith('.lock') && !entry.endsWith('.png') && !entry.endsWith('.jpg') && !entry.endsWith('.vsix')) {
        fileList.push(full);
      }
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
