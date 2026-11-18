/**
 * Empirical Multi-Scanner Benchmark Runner
 * Runs Secret Leak Detector, Gitleaks, TruffleHog, and detect-secrets
 * on the exact same 500+ file corpus.
 */

import * as fs from 'fs';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { generateCorpus, CorpusItem } from '../datasets/corpusGenerator';
import { scanContent } from '../../src/core/scanner/scanner';
import { getPackageVersion } from '../../src/core/version';

function resolveComparatorBinary(toolName: string, candidateRelativePaths: string[]): string | null {
  const isWin = process.platform === 'win32';
  for (const rel of candidateRelativePaths) {
    const directPath = path.resolve(process.cwd(), rel);
    if (fs.existsSync(directPath)) return directPath;
    if (isWin && !rel.endsWith('.exe')) {
      const winPath = path.resolve(process.cwd(), `${rel}.exe`);
      if (fs.existsSync(winPath)) return winPath;
    }
  }

  // Check system PATH
  try {
    const whichCmd = isWin ? 'where' : 'which';
    const out = execFileSync(whichCmd, [toolName], { stdio: ['ignore', 'pipe', 'ignore'], encoding: 'utf8' }).trim();
    const candidate = out.split(/\r?\n/)[0]?.trim();
    if (candidate && fs.existsSync(candidate)) return candidate;
  } catch {}

  return null;
}

function readComparatorVersion(binary: string, args: string[]): string {
  try {
    const output = execFileSync(binary, args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true,
    }).trim();
    return output.split(/\r?\n/)[0] || 'unknown';
  } catch {
    return 'unknown';
  }
}

export interface ScannerMetrics {
  name: string;
  version: string;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  specificity: number;
  f1: number;
  fpr: number;
  adversarialRate: number;
  precisionCi: [number, number];
  recallCi: [number, number];
  wallClockMs: number;
  latencyPerFileUs: number;
  rssMb: number;
  heapUsedMb: number;
}

// Wilson 95% Score Confidence Interval
function calculateWilsonCi(successes: number, total: number): [number, number] {
  if (total === 0) return [0, 0];
  const z = 1.96;
  const p = successes / total;
  const denominator = 1 + (z * z) / total;
  const center = p + (z * z) / (2 * total);
  const spread = z * Math.sqrt((p * (1 - p)) / total + (z * z) / (4 * total * total));
  const lower = Math.max(0, (center - spread) / denominator);
  const upper = Math.min(1, (center + spread) / denominator);
  return [Math.round(lower * 1000) / 10, Math.round(upper * 1000) / 10];
}

function normalizePath(p: string): string {
  return p.replace(/\\/g, '/').toLowerCase();
}

export function runMultiScannerBenchmark(options: { sldOnly?: boolean } = {}): ScannerMetrics[] {
  const rootDir = process.cwd();
  const corpusDir = path.join(rootDir, 'evaluation', 'corpus');
  const reportsDir = path.join(rootDir, 'evaluation', 'reports');
  fs.mkdirSync(reportsDir, { recursive: true });

  console.log('=================================================================================');
  console.log('⚡ GENERATING STANDARDIZED EMPIRICAL CORPUS (1,000 Synthetic Files)...');
  console.log('=================================================================================');

  const corpus = generateCorpus(corpusDir);
  console.log(`✅ Corpus generated: ${corpus.length} files`);
  console.log(`   - True Positives:   ${corpus.filter((c) => c.category === 'true_positive').length}`);
  console.log(`   - False Positives:  ${corpus.filter((c) => c.category === 'false_positive').length}`);
  console.log(`   - Adversarial:      ${corpus.filter((c) => c.category === 'adversarial').length}`);

  const results: ScannerMetrics[] = [];

  // ---------------------------------------------------------------------------
  // 1. RUN SECRET LEAK DETECTOR (SLD)
  // ---------------------------------------------------------------------------
  console.log('\n[1/4] Running Secret Leak Detector (Ours)...');
  const sldStart = process.hrtime.bigint();
  const sldDetectedFiles = new Set<string>();

  for (const item of corpus) {
    const fullPath = path.join(corpusDir, item.relativePath);
    const content = fs.readFileSync(fullPath, 'utf8');
    const findings = scanContent(content, item.relativePath, corpusDir);
    if (findings.length > 0) {
      sldDetectedFiles.add(normalizePath(item.relativePath));
    }
  }
  const sldEnd = process.hrtime.bigint();
  const sldWallClockMs = Number(sldEnd - sldStart) / 1e6;
  const pkgVersion = getPackageVersion();
  results.push(evaluateScanner('Secret Leak Detector (Ours)', pkgVersion, corpus, sldDetectedFiles, sldWallClockMs));

  const allowMissing = !!(
    process.env.SLD_ALLOW_MISSING_COMPARATORS ||
    process.argv.includes('--allow-missing')
  );

  if (options.sldOnly || process.argv.includes('--sld-only')) {
    try {
      fs.rmSync(corpusDir, { recursive: true, force: true });
    } catch {}
    printBenchmarkSummary(results, corpus.length);
    return results;
  }

  // ---------------------------------------------------------------------------
  // 2. RUN GITLEAKS
  // ---------------------------------------------------------------------------
  console.log('\n[2/4] Running Gitleaks...');
  const gitleaksBin = resolveComparatorBinary('gitleaks', [
    path.join('tools', 'bin', 'gitleaks.exe'),
    path.join('tools', 'bin', 'gitleaks'),
    path.join('tools', 'gitleaks'),
  ]);
  const gitleaksReport = path.join(reportsDir, 'gitleaks_raw.json');
  const gitleaksDetectedFiles = new Set<string>();
  let gitleaksWallClockMs = 0;

  if (gitleaksBin) {
    try {
      const gStart = process.hrtime.bigint();
      execFileSync(gitleaksBin, [
        'dir', corpusDir, '--report-format', 'json', '--report-path', gitleaksReport,
        '--no-banner', '--exit-code', '0',
      ], { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024, windowsHide: true });
      const gEnd = process.hrtime.bigint();
      gitleaksWallClockMs = Number(gEnd - gStart) / 1e6;

      if (!fs.existsSync(gitleaksReport)) {
        throw new Error('Gitleaks completed without producing its JSON report.');
      }
      const rawJson = JSON.parse(fs.readFileSync(gitleaksReport, 'utf8'));
      if (!Array.isArray(rawJson)) throw new Error('Gitleaks report is not a JSON array.');
      for (const leak of rawJson) {
        const rawFile = leak.File || leak.file;
        if (typeof rawFile !== 'string') throw new Error('Gitleaks report entry is missing a file path.');
        const rel = path.relative(corpusDir, rawFile);
        gitleaksDetectedFiles.add(normalizePath(rel));
      }
      fs.unlinkSync(gitleaksReport);
    } catch (err: any) {
      try { fs.rmSync(gitleaksReport, { force: true }); } catch {}
      throw new Error(`Gitleaks benchmark failed; refusing to write partial metrics: ${err?.message || err}`);
    }
    results.push(evaluateScanner('Gitleaks', readComparatorVersion(gitleaksBin, ['version']), corpus, gitleaksDetectedFiles, gitleaksWallClockMs));
  } else {
    if (allowMissing) {
      console.warn('⚠️  Gitleaks binary not found on PATH or in tools/. Skipping Gitleaks evaluation.');
    } else {
      try { fs.rmSync(corpusDir, { recursive: true, force: true }); } catch {}
      throw new Error(
        "Missing required comparator binary: 'gitleaks' not found on system PATH or in tools/bin/. Either install Gitleaks, pass --allow-missing, or pass --sld-only to evaluate Secret Leak Detector alone."
      );
    }
  }

  // ---------------------------------------------------------------------------
  // 3. RUN TRUFFLEHOG
  // ---------------------------------------------------------------------------
  console.log('\n[3/4] Running TruffleHog...');
  const trufflehogBin = resolveComparatorBinary('trufflehog', [
    path.join('tools', 'bin', 'trufflehog.exe'),
    path.join('tools', 'bin', 'trufflehog'),
    path.join('tools', 'trufflehog'),
  ]);
  const trufflehogDetectedFiles = new Set<string>();
  let trufflehogWallClockMs = 0;

  if (trufflehogBin) {
    try {
      const tStart = process.hrtime.bigint();
      let output = '';
      try {
        output = execFileSync(trufflehogBin, [
          'filesystem', corpusDir, '--json', '--no-verification', '--no-update',
        ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024, windowsHide: true });
      } catch (err: any) {
        output = err.stdout || '';
      }
      const tEnd = process.hrtime.bigint();
      trufflehogWallClockMs = Number(tEnd - tStart) / 1e6;

      const lines = output.split('\n');
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const parsed = JSON.parse(line);
          const rawFile = parsed?.SourceMetadata?.Data?.Filesystem?.file;
          if (rawFile) {
            const rel = path.relative(corpusDir, rawFile);
            trufflehogDetectedFiles.add(normalizePath(rel));
          }
        } catch {
          throw new Error('TruffleHog emitted a non-JSON line; refusing to create a report from incomplete output.');
        }
      }
      if (!output.trim()) throw new Error('TruffleHog produced no output; refusing to count an empty run as zero detections.');
    } catch (err: any) {
      throw new Error(`TruffleHog benchmark failed; refusing to write partial metrics: ${err?.message || err}`);
    }
    results.push(evaluateScanner('TruffleHog', readComparatorVersion(trufflehogBin, ['--version']), corpus, trufflehogDetectedFiles, trufflehogWallClockMs));
  } else {
    if (allowMissing) {
      console.warn('⚠️  TruffleHog binary not found on PATH or in tools/. Skipping TruffleHog evaluation.');
    } else {
      try { fs.rmSync(corpusDir, { recursive: true, force: true }); } catch {}
      throw new Error(
        "Missing required comparator binary: 'trufflehog' not found on system PATH or in tools/bin/. Either install TruffleHog, pass --allow-missing, or pass --sld-only to evaluate Secret Leak Detector alone."
      );
    }
  }

  // ---------------------------------------------------------------------------
  // 4. RUN DETECT-SECRETS
  // ---------------------------------------------------------------------------
  console.log('\n[4/4] Running detect-secrets...');
  const detectSecretsBin = resolveComparatorBinary('detect-secrets', [
    path.join('tools', 'python', 'Scripts', 'detect-secrets.exe'),
    path.join('tools', 'python', 'Scripts', 'detect-secrets'),
    path.join('tools', 'bin', 'detect-secrets'),
    path.join('tools', 'detect-secrets'),
  ]);
  const detectSecretsDetectedFiles = new Set<string>();
  let detectSecretsWallClockMs = 0;

  if (detectSecretsBin) {
    try {
      const dStart = process.hrtime.bigint();
      let output = '';
      try {
        output = execFileSync(detectSecretsBin, ['scan', '--all-files', corpusDir], {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
          maxBuffer: 64 * 1024 * 1024,
          windowsHide: true,
        });
      } catch (err: any) {
        output = err.stdout || '';
      }
      const dEnd = process.hrtime.bigint();
      detectSecretsWallClockMs = Number(dEnd - dStart) / 1e6;

      let parsed: any;
      try { parsed = JSON.parse(output); } catch {
        throw new Error('detect-secrets did not emit valid JSON.');
      }
      if (!parsed || typeof parsed.results !== 'object' || parsed.results === null || Array.isArray(parsed.results)) {
        throw new Error('detect-secrets output is missing its results object.');
      }
      for (const rawFile of Object.keys(parsed.results)) {
        const rel = path.relative(corpusDir, rawFile);
        detectSecretsDetectedFiles.add(normalizePath(rel));
      }
    } catch (err: any) {
      throw new Error(`detect-secrets benchmark failed; refusing to write partial metrics: ${err?.message || err}`);
    }
    results.push(evaluateScanner('detect-secrets', readComparatorVersion(detectSecretsBin, ['--version']), corpus, detectSecretsDetectedFiles, detectSecretsWallClockMs));
  } else {
    if (allowMissing) {
      console.warn('⚠️  detect-secrets binary not found on PATH or in tools/. Skipping detect-secrets evaluation.');
    } else {
      try { fs.rmSync(corpusDir, { recursive: true, force: true }); } catch {}
      throw new Error(
        "Missing required comparator binary: 'detect-secrets' not found on system PATH or in tools/. Either install detect-secrets, pass --allow-missing, or pass --sld-only to evaluate Secret Leak Detector alone."
      );
    }
  }

  // ---------------------------------------------------------------------------
  // CLEANUP CORPUS
  // ---------------------------------------------------------------------------
  try {
    fs.rmSync(corpusDir, { recursive: true, force: true });
    console.log('\n🧹 Temporary corpus directory cleaned up.');
  } catch {
    // Ignore cleanup errors
  }

  // ---------------------------------------------------------------------------
  // PRINT EMPIRICAL REPORT & SAVE JSON
  // ---------------------------------------------------------------------------
  printBenchmarkSummary(results, corpus.length);

  let sourceCommit = 'unknown';
  try {
    sourceCommit = execFileSync('git', ['rev-parse', 'HEAD'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {}

  const reportPath = path.join(reportsDir, 'multi_scanner_benchmark.json');
  fs.writeFileSync(reportPath, JSON.stringify({
    timestamp: new Date().toISOString(),
    sourceCommit,
    detectorVersion: getPackageVersion(),
    corpusProvenance: 'Author-generated synthetic fixtures with maintainer-assigned labels; not an independent real-world evaluation.',
    totalFiles: corpus.length,
    results,
  }, null, 2), 'utf8');
  console.log(`\n📄 Report saved to: ${reportPath}`);

  return results;
}

function evaluateScanner(
  name: string,
  version: string,
  corpus: CorpusItem[],
  detectedFiles: Set<string>,
  wallClockMs: number
): ScannerMetrics {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  let advTotal = 0;
  let advDetected = 0;

  for (const item of corpus) {
    const isDetected = detectedFiles.has(normalizePath(item.relativePath));

    if (item.isSecret) {
      if (isDetected) {
        tp++;
      } else {
        fn++;
      }
    } else {
      if (isDetected) {
        fp++;
      } else {
        tn++;
      }
    }

    if (item.category === 'adversarial') {
      advTotal++;
      if (isDetected) advDetected++;
    }
  }

  const precision = tp + fp > 0 ? (tp / (tp + fp)) * 100 : 0;
  const recall = tp + fn > 0 ? (tp / (tp + fn)) * 100 : 0;
  const specificity = tn + fp > 0 ? (tn / (tn + fp)) * 100 : 0;
  const f1 = precision + recall > 0 ? (2 * (precision * recall)) / (precision + recall) : 0;
  const fpr = fp + tn > 0 ? (fp / (fp + tn)) * 100 : 0;
  const adversarialRate = advTotal > 0 ? (advDetected / advTotal) * 100 : 0;

  const precisionCi = calculateWilsonCi(tp, tp + fp);
  const recallCi = calculateWilsonCi(tp, tp + fn);
  const latencyPerFileUs = Math.round((wallClockMs * 1000) / corpus.length);

  const mem = process.memoryUsage();
  const rssMb = Math.round((mem.rss / (1024 * 1024)) * 10) / 10;
  const heapUsedMb = Math.round((mem.heapUsed / (1024 * 1024)) * 10) / 10;

  return {
    name,
    version,
    tp,
    fp,
    tn,
    fn,
    precision: Math.round(precision * 10) / 10,
    recall: Math.round(recall * 10) / 10,
    specificity: Math.round(specificity * 10) / 10,
    f1: Math.round(f1 * 10) / 10,
    fpr: Math.round(fpr * 10) / 10,
    adversarialRate: Math.round(adversarialRate * 10) / 10,
    precisionCi,
    recallCi,
    wallClockMs: Math.round(wallClockMs),
    latencyPerFileUs,
    rssMb,
    heapUsedMb,
  };
}

function printBenchmarkSummary(results: ScannerMetrics[], totalFiles: number) {
  console.log('\n======================================================================================================================');
  console.log(`📊 EMPIRICAL SCANNER BENCHMARK REPORT (${totalFiles} Identical Files: 500 TP, 400 FP, 100 Adversarial)`);
  console.log('======================================================================================================================');
  console.log('| Scanner Tool                | Precision (95% CI)   | Recall (95% CI)      | F1 Score | FP Rate | Adversarial | Latency/File | Memory (RSS) |');
  console.log('|:----------------------------|:---------------------|:---------------------|:---------|:--------|:------------|:-------------|:-------------|');

  for (const r of results) {
    const nameStr = `${r.name} ${r.version}`.padEnd(28, ' ');
    const precStr = `${r.precision}% [${r.precisionCi[0]}%-${r.precisionCi[1]}%]`.padEnd(21, ' ');
    const recStr = `${r.recall}% [${r.recallCi[0]}%-${r.recallCi[1]}%]`.padEnd(21, ' ');
    const f1Str = `${r.f1}%`.padEnd(9, ' ');
    const fprStr = `${r.fpr}%`.padEnd(8, ' ');
    const advStr = `${r.adversarialRate}%`.padEnd(12, ' ');
    const latStr = `${r.latencyPerFileUs} µs`.padEnd(13, ' ');
    const memStr = `${r.rssMb} MB`;
    console.log(`| ${nameStr}| ${precStr}| ${recStr}| ${f1Str}| ${fprStr}| ${advStr}| ${latStr}| ${memStr} |`);
  }
  console.log('======================================================================================================================\n');
}

// Run standalone if executed directly via multi-benchmark
if (require.main === module && !process.argv[1]?.includes('regression-gate')) {
  runMultiScannerBenchmark();
}
