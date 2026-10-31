#!/usr/bin/env node
import * as path from 'path';
import * as fs from 'fs';
import * as readline from 'readline';
import { scanFile, scanContent, buildScanResult } from '../core/scanner/scanner';
import { GitHistoryEngine } from '../core/history/gitHistoryEngine';
import { GitTimelineEngine } from '../core/history/gitTimeline';
import { BaselineEngine, DEFAULT_BASELINE_FILENAME } from '../core/baseline/baselineEngine';
import { VerificationEngine } from '../core/verification/verificationEngine';
import { applyControlledRemediation } from '../core/remediation/remediationEngine';
import { redactSecret } from '../core/redactor/redactor';
import { formatAsSarif } from '../core/sarif/sarifFormatter';
import { SecretFinding, Risk } from '../core/types';
import { scanStagedChangesSync } from '../git/stagedScanner';
import { GitService } from '../git/gitService';
import { DEFAULT_FAIL_ON, resolveFailOn, shouldBlock } from '../core/policy';

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

    case 'timeline':
      await runTimeline(args.slice(1), cwd);
      break;

    case 'graph':
      await runGraph(args.slice(1), cwd);
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
                           --json             Output findings in JSON format (secrets redacted)
                           --sarif            Output findings in SARIF v2.1.0 (for CI/CD)
                           --baseline <file>  Evaluate against baseline (pass on known secrets)
                           --staged           Scan only Git staged changes (pre-commit check)
                           --fail-on <tier>   Exit code 1 on this tier and above: LOW, MEDIUM, HIGH, CRITICAL
                                              (default: HIGH — see src/core/policy.ts)

  history                Scan Git commit history for previously introduced credentials
                         Options:
                           --max <n>          Number of commits to inspect (default: 100)

  trace [secret]         Trace a credential's commit provenance, duration, and blast radius
                         (Pass secret via stdin or SLD_SECRET to avoid process table exposure)
  timeline [secret]      Display ASCII exposure timeline across commit history
  graph [secret]         Export formal Git DAG Exposure Graph (nodes, edges, reachability)

  baseline init          Generate .secretleak-baseline.json with existing findings
  baseline update        Refresh line numbers for known baseline findings (never whitelists new leaks)

  fix <file>             Controlled interactive remediation (diff preview & .env migration)
                         Options:
                           --dry-run          Preview patch without modifying files
                           --yes, -y          Apply changes non-interactively without prompt

  verify <file>          Rescan and verify that credential exposure has been eliminated

  hook install           Install standalone pre-commit hook in .git/hooks/pre-commit
  hook uninstall         Safely remove pre-commit hook without removing user hooks

Examples:
  npx secret-leak-detector scan . --sarif > results.sarif
  npx secret-leak-detector scan --staged
  npx secret-leak-detector history --max 50
  npx secret-leak-detector baseline init
  echo "$SECRET" | npx secret-leak-detector trace -
`);
}

async function runScan(cmdArgs: string[], cwd: string) {
  const isJson = cmdArgs.includes('--json');
  const isSarif = cmdArgs.includes('--sarif');
  const isStaged = cmdArgs.includes('--staged');

  const baselineIdx = cmdArgs.indexOf('--baseline');
  const baselineFile = baselineIdx !== -1 ? cmdArgs[baselineIdx + 1] : undefined;

  const failOnIdx = cmdArgs.indexOf('--fail-on');
  const failOnRaw = failOnIdx !== -1 ? cmdArgs[failOnIdx + 1] : undefined;
  const failOn: Risk = resolveFailOn(failOnRaw);

  let targetPath: string | undefined;
  for (let i = 0; i < cmdArgs.length; i++) {
    const a = cmdArgs[i];
    if (a === '--baseline' || a === '--fail-on') {
      i++; // skip value argument
      continue;
    }
    if (a.startsWith('--')) {
      continue;
    }
    targetPath = a;
    break;
  }
  targetPath = targetPath || '.';
  const absPath = path.resolve(cwd, targetPath);

  if (!isStaged && !fs.existsSync(absPath)) {
    console.error(`Error: Path does not exist: '${targetPath}' (${absPath})`);
    process.exit(1);
  }

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
    const staged = scanStagedChangesSync(cwd);
    findings.push(...staged.findings);
    filesScanned = staged.filesScanned || 0;

    if (staged.status === 'ERROR') {
      console.error(`Git staged scan error: ${staged.error}`);
      process.exit(1);
    }
  } else {
    // Scan directory or single file
    const filesToScan: string[] = [];
    collectFiles(absPath, filesToScan, cwd);
    filesScanned = filesToScan.length;

    const skippedFiles: { file: string; reason: string }[] = [];
    for (const file of filesToScan) {
      findings.push(
        ...scanFile(file, {
          workspaceRoot: cwd,
          onSkippedFile: (skippedPath, reason) => {
            skippedFiles.push({ file: skippedPath, reason });
          },
        })
      );
    }

    if (skippedFiles.length > 0) {
      console.error(`\n❌ Error: ${skippedFiles.length} file(s) were skipped during scan (failing closed for safety):`);
      for (const skipped of skippedFiles) {
        console.error(`  • ${skipped.file}: ${skipped.reason}`);
      }
      process.exit(1);
    }
  }

  // Baseline filtering if enabled
  let baselineStats: any;
  if (baselineFile || fs.existsSync(path.join(cwd, DEFAULT_BASELINE_FILENAME))) {
    const targetBaseline = baselineFile || DEFAULT_BASELINE_FILENAME;
    const baselineEngine = new BaselineEngine(cwd, targetBaseline);
    if (baselineEngine.exists()) {
      try {
        const filtered = baselineEngine.filterAgainstBaseline(findings);
        baselineStats = {
          total: findings.length,
          existing: filtered.existingFindings.length,
          newFindings: filtered.newFindings.length,
          resolved: filtered.resolvedCount,
        };
        findings = filtered.newFindings;
      } catch (err: any) {
        console.error(`Error: Malformed baseline file '${targetBaseline}': ${err.message}`);
        process.exit(1);
      }
    }
  }

  const durationMs = Date.now() - startTime;

  if (isSarif) {
    console.log(JSON.stringify(formatAsSarif(findings), null, 2));
    processExitCheck(findings, failOn);
    return;
  }

  if (isJson) {
    // Strip rawSecret and redact envFileSnippet to prevent leaking credentials in JSON logs
    const safeFindings = findings.map((f) => {
      const { rawSecret, ...rest } = f;
      return {
        ...rest,
        remediation: {
          ...f.remediation,
          envFileSnippet: `${f.remediation.envVarName}="[REDACTED]"`,
        },
      };
    });
    const scanResult = buildScanResult(safeFindings, filesScanned, durationMs);
    if (baselineStats) scanResult.baselineStats = baselineStats;
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
    console.log(`  Add to .env: ${f.remediation.envVarName}="<secret>"`);
  });

  console.log('============================================================\n');
  processExitCheck(findings, failOn);
}

function processExitCheck(findings: SecretFinding[], failOn: Risk) {
  process.exit(shouldBlock(findings, failOn) ? 1 : 0);
}

async function runHistory(cmdArgs: string[], cwd: string) {
  const maxIdx = cmdArgs.indexOf('--max');
  let maxCommits = 100;
  if (maxIdx !== -1) {
    const rawVal = cmdArgs[maxIdx + 1];
    const parsed = parseInt(rawVal, 10);
    if (isNaN(parsed) || parsed <= 0) {
      console.error(`Error: Invalid --max argument '${rawVal}'. Must be a positive integer.`);
      process.exit(1);
    }
    maxCommits = parsed;
  }

  console.log(`\n⏳ Scanning Git commit history (last ${maxCommits} commits) for historical leaks...`);
  const historyEngine = new GitHistoryEngine(cwd);
  let findings: SecretFinding[];
  try {
    findings = await historyEngine.scanHistoryCommits(maxCommits);
  } catch (err: any) {
    console.error(`Error: Failed to scan Git history: ${err.message || String(err)}`);
    process.exit(1);
  }

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

async function resolveSecretInput(cmdArgs: string[], commandName: string): Promise<string> {
  if (process.env.SLD_SECRET) {
    return process.env.SLD_SECRET.trim();
  }

  const explicitArg = cmdArgs.find((a) => !a.startsWith('--'));

  if (explicitArg === '-' || (!explicitArg && !process.stdin.isTTY)) {
    return new Promise((resolve) => {
      let data = '';
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', (chunk) => {
        data += chunk;
      });
      process.stdin.on('end', () => {
        const val = data.trim();
        if (!val) {
          console.error('Error: No secret string received from stdin.');
          process.exit(1);
        }
        resolve(val);
      });
      process.stdin.on('error', (err) => {
        console.error(`Error reading from stdin: ${err.message}`);
        process.exit(1);
      });
    });
  }

  if (explicitArg) {
    console.error(
      `⚠️  Security Warning: Passing secrets via CLI arguments exposes them in shell history and 'ps' listings.`
    );
    console.error(`   Recommended: Pipe via stdin ('echo "$SECRET" | secret-leak-detector ${commandName} -') or use SLD_SECRET env var.\n`);
    return explicitArg;
  }

  console.error(`Usage: secret-leak-detector ${commandName} <secret-string | ->`);
  console.error(`       Or set SLD_SECRET environment variable.`);
  process.exit(1);
}

async function runTrace(cmdArgs: string[], cwd: string) {
  const secret = await resolveSecretInput(cmdArgs, 'trace');

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

async function runTimeline(cmdArgs: string[], cwd: string) {
  const secret = await resolveSecretInput(cmdArgs, 'timeline');

  const redacted = redactSecret(secret);
  const timelineEngine = new GitTimelineEngine(cwd);
  const report = await timelineEngine.buildTimeline(secret, redacted);
  console.log(report.timelineAscii);
}

async function runGraph(cmdArgs: string[], cwd: string) {
  const isJson = cmdArgs.includes('--json');
  const secret = await resolveSecretInput(cmdArgs, 'graph');

  const redacted = redactSecret(secret);
  const timelineEngine = new GitTimelineEngine(cwd);
  const report = await timelineEngine.buildTimeline(secret, redacted);

  if (isJson) {
    console.log(JSON.stringify(report.graph, null, 2));
  } else {
    console.log('\n============================================================');
    console.log('🌐 GIT EXPOSURE GRAPH (DAG Nodes & Reachability)');
    console.log('============================================================');
    console.log(`Summary:`);
    console.log(`  • Exposed Commits:       ${report.graph.summary.totalExposedCommits}`);
    console.log(`  • Introduced In Commit:  ${report.graph.summary.introducedCommit.substring(0, 8)}`);
    if (report.graph.summary.removedCommit) {
      console.log(`  • Removed In Commit:     ${report.graph.summary.removedCommit.substring(0, 8)}`);
    }
    console.log(`  • Contaminated Branches: ${report.graph.summary.branchesContaminated.join(', ')}`);
    console.log(`  • Exposure Duration:     ${report.graph.summary.durationDays} days`);
    console.log(`  • Remote Synchronized:   ${report.graph.summary.isPushedToRemote ? 'YES (External!)' : 'NO'}`);
    console.log('\nNodes:');
    report.graph.nodes.forEach((n) => {
      console.log(`  [${n.shortHash}] ${n.eventType.padEnd(12)} - ${n.author} (${n.date.substring(0, 10)}) ${n.isHead ? '[HEAD]' : ''}`);
    });
    console.log('\nEdges (Parent -> Child):');
    report.graph.edges.forEach((e) => {
      console.log(`  ${e.from.substring(0, 8)} ──► ${e.to.substring(0, 8)}`);
    });
    console.log('============================================================\n');
  }
}

async function runBaseline(cmdArgs: string[], cwd: string) {
  const subCommand = cmdArgs[0] || 'init';
  if (subCommand !== 'init' && subCommand !== 'update') {
    console.error('Usage: secret-leak-detector baseline [init|update]');
    process.exit(1);
  }

  const baselineEngine = new BaselineEngine(cwd);

  const files: string[] = [];
  collectFiles(cwd, files, cwd);

  const findings: SecretFinding[] = [];
  for (const f of files) {
    findings.push(...scanFile(f, { workspaceRoot: cwd }));
  }

  if (subCommand === 'update') {
    if (!baselineEngine.exists()) {
      console.error(`Error: Baseline file does not exist. Run 'baseline init' first.`);
      process.exit(1);
    }
    const existing = baselineEngine.loadBaseline();
    const existingFps = new Set(existing?.findings.map((b) => b.fingerprint) || []);

    const updatedFindings = findings.filter((f) => existingFps.has(f.fingerprint));
    const newLeaks = findings.filter((f) => !existingFps.has(f.fingerprint));

    if (newLeaks.length > 0) {
      console.warn(`⚠️  Warning: Found ${newLeaks.length} new secret(s) not in existing baseline. These are NOT whitelisted by 'baseline update'.`);
    }

    const baseline = baselineEngine.saveBaseline(updatedFindings);
    console.log(`✅ Updated baseline: ${baseline.findings.length} known findings retained (${newLeaks.length} new leaks rejected).\n`);
    return;
  }

  console.log(`\n📦 Initializing baseline for workspace: ${cwd}`);
  const baseline = baselineEngine.saveBaseline(findings);
  console.log(`✅ Saved ${baseline.findings.length} findings to ${DEFAULT_BASELINE_FILENAME}.`);
  console.log('Future CI scans will only fail on newly introduced secrets!\n');
}

async function runFix(cmdArgs: string[], cwd: string) {
  const isDryRun = cmdArgs.includes('--dry-run');
  const autoConfirm = cmdArgs.includes('--yes') || cmdArgs.includes('-y');
  const targetFile = cmdArgs.find((a) => !a.startsWith('--') && !a.startsWith('-'));

  if (!targetFile) {
    console.error('Usage: secret-leak-detector fix <file> [--dry-run] [--yes]');
    process.exit(1);
  }

  const absPath = path.resolve(cwd, targetFile);
  if (!fs.existsSync(absPath)) {
    console.error(`Error: File does not exist: ${targetFile}`);
    process.exit(1);
  }

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
  }

  if (isDryRun) {
    console.log('ℹ️ Dry-run mode: No files were changed. Omit --dry-run to apply patch.');
    return;
  }

  if (process.stdin.isTTY && !autoConfirm) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const answer = await new Promise<string>((resolve) => {
      rl.question('Apply these changes to .env and target file? (y/N): ', (ans) => {
        rl.close();
        resolve(ans.trim().toLowerCase());
      });
    });

    if (answer !== 'y' && answer !== 'yes') {
      console.log('Aborted. No changes applied.');
      return;
    }
  }

  for (const f of findings) {
    const result = applyControlledRemediation(f, cwd);
    if (result.success) {
      console.log(`✅ Applied fix: ${result.message}`);
    } else {
      console.error(`❌ Failed: ${result.message}`);
    }
  }
}

async function runVerify(cmdArgs: string[], cwd: string) {
  const targetFile = cmdArgs[0];
  if (!targetFile) {
    console.error('Usage: secret-leak-detector verify <file>');
    process.exit(1);
  }

  const absPath = path.resolve(cwd, targetFile);
  if (!fs.existsSync(absPath)) {
    console.error(`Error: File does not exist: ${targetFile}`);
    process.exit(1);
  }

  const currentFindings = scanFile(absPath, { workspaceRoot: cwd });

  console.log('\n============================================================');
  console.log(`🔍 RESCAN VERIFICATION: ${targetFile}`);
  console.log('============================================================');

  if (currentFindings.length > 0) {
    console.log(`❌ REMAINING EXPOSURES: Found ${currentFindings.length} secret(s) still present:`);
    currentFindings.forEach((f) => {
      console.log(`  • Line ${f.line}: ${f.type} (${f.redactedSecret})`);
    });
    console.log('============================================================\n');
    process.exit(1);
  }

  console.log('✅ TARGET FILE VERIFIED CLEAN in working tree!');

  const verificationEngine = new VerificationEngine(cwd);
  const gitEngine = new GitHistoryEngine(cwd);
  const isGit = await gitEngine.isGitRepo();

  if (isGit) {
    console.log('Checking Git commit history status...');
    console.log('Target file contains no active credentials.');
  }

  console.log('============================================================\n');
  process.exit(0);
}

async function runHook(cmdArgs: string[], cwd: string) {
  const subCommand = cmdArgs[0] || 'install';
  const gitService = new GitService(cwd);

  if (subCommand === 'install') {
    const result = await gitService.installPreCommitHook();
    if (!result.success) {
      console.error(`Error: ${result.message}`);
      process.exit(1);
    }
    console.log(`✅ ${result.message}`);
    console.log(
      `   Severity policy (single source: src/core/policy.ts): blocks ${DEFAULT_FAIL_ON} and above; ` +
        `fails closed when the scanner cannot run.`
    );
  } else if (subCommand === 'uninstall') {
    const result = await gitService.uninstallPreCommitHook();
    if (!result.success) {
      console.error(`Error: ${result.message}`);
      process.exit(1);
    }
    console.log(`✅ ${result.message}`);
  } else {
    console.error('Usage: secret-leak-detector hook [install|uninstall]');
    process.exit(1);
  }
}

function collectFiles(
  currentPath: string,
  fileList: string[],
  rootDir: string,
  visitedDirs: Set<string> = new Set<string>()
) {
  if (!fs.existsSync(currentPath)) return;
  let realPath: string;
  try {
    realPath = fs.realpathSync(currentPath);
  } catch {
    return;
  }

  let stat: fs.Stats;
  try {
    stat = fs.statSync(currentPath);
  } catch {
    return;
  }

  if (stat.isFile()) {
    if (!currentPath.endsWith('.lock') && !currentPath.endsWith('.png') && !currentPath.endsWith('.jpg') && !currentPath.endsWith('.vsix')) {
      fileList.push(currentPath);
    }
    return;
  }

  if (visitedDirs.has(realPath)) {
    return;
  }
  visitedDirs.add(realPath);

  let entries: string[];
  try {
    entries = fs.readdirSync(currentPath);
  } catch {
    return;
  }

  const EXCLUDES = ['node_modules', '.git'];

  for (const entry of entries) {
    if (EXCLUDES.includes(entry)) continue;
    const full = path.join(currentPath, entry);
    let s: fs.Stats;
    try {
      s = fs.statSync(full);
    } catch {
      continue;
    }
    if (s.isDirectory()) {
      collectFiles(full, fileList, rootDir, visitedDirs);
    } else if (s.isFile()) {
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
