/**
 * Empirical Multi-Scanner Benchmark Runner
 * Runs Secret Leak Detector, Gitleaks, TruffleHog, and detect-secrets
 * on the exact same 500+ file corpus.
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { generateCorpus, CorpusItem } from '../datasets/corpusGenerator';
import { scanContent } from '../../src/core/scanner/scanner';

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
  console.log('⚡ GENERATING STANDARDIZED EMPIRICAL CORPUS (520 Synthetic Files)...');
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
  results.push(evaluateScanner('Secret Leak Detector (Ours)', '1.0.0', corpus, sldDetectedFiles, sldWallClockMs));

  if (options.sldOnly) {
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
  const gitleaksBin = path.join(rootDir, 'tools', 'bin', 'gitleaks.exe');
  const gitleaksReport = path.join(reportsDir, 'gitleaks_raw.json');
  const gitleaksDetectedFiles = new Set<string>();
  let gitleaksWallClockMs = 0;

  if (fs.existsSync(gitleaksBin)) {
    try {
      const gStart = process.hrtime.bigint();
      try {
        execSync(`"${gitleaksBin}" dir "${corpusDir}" --report-format json --report-path "${gitleaksReport}" --no-banner --exit-code 0`, {
          stdio: 'pipe',
        });
      } catch {
        // gitleaks returns non-zero if leaks are found unless --exit-code 0 is set
      }
      const gEnd = process.hrtime.bigint();
      gitleaksWallClockMs = Number(gEnd - gStart) / 1e6;

      if (fs.existsSync(gitleaksReport)) {
        const rawJson = JSON.parse(fs.readFileSync(gitleaksReport, 'utf8'));
        if (Array.isArray(rawJson)) {
          for (const leak of rawJson) {
            const rel = path.relative(corpusDir, leak.File || leak.file);
            gitleaksDetectedFiles.add(normalizePath(rel));
          }
        }
        fs.unlinkSync(gitleaksReport);
      }
    } catch (err) {
      console.warn('Gitleaks execution encountered error:', err);
    }
  } else {
    console.warn('Gitleaks binary not found at:', gitleaksBin);
  }
  results.push(evaluateScanner('Gitleaks', 'v8.30.1', corpus, gitleaksDetectedFiles, gitleaksWallClockMs));

  // ---------------------------------------------------------------------------
  // 3. RUN TRUFFLEHOG
  // ---------------------------------------------------------------------------
  console.log('\n[3/4] Running TruffleHog...');
  const trufflehogBin = path.join(rootDir, 'tools', 'bin', 'trufflehog.exe');
  const trufflehogDetectedFiles = new Set<string>();
  let trufflehogWallClockMs = 0;

  if (fs.existsSync(trufflehogBin)) {
    try {
      const tStart = process.hrtime.bigint();
      let output = '';
      try {
        output = execSync(`"${trufflehogBin}" filesystem "${corpusDir}" --json --no-verification --no-update`, {
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'ignore'],
        });
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
          // ignore non-json log lines
        }
      }
    } catch (err) {
      console.warn('TruffleHog execution error:', err);
    }
  } else {
    console.warn('TruffleHog binary not found at:', trufflehogBin);
  }
  results.push(evaluateScanner('TruffleHog', 'v3.99.2', corpus, trufflehogDetectedFiles, trufflehogWallClockMs));

  // ---------------------------------------------------------------------------
  // 4. RUN DETECT-SECRETS
  // ---------------------------------------------------------------------------
  console.log('\n[4/4] Running detect-secrets...');
  const detectSecretsBin = path.join(rootDir, 'tools', 'python', 'Scripts', 'detect-secrets.exe');
  const detectSecretsDetectedFiles = new Set<string>();
  let detectSecretsWallClockMs = 0;

  if (fs.existsSync(detectSecretsBin)) {
    try {
      const dStart = process.hrtime.bigint();
      let output = '';
      try {
        output = execSync(`"${detectSecretsBin}" scan --all-files "${corpusDir}"`, {
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'ignore'],
        });
      } catch (err: any) {
        output = err.stdout || '';
      }
      const dEnd = process.hrtime.bigint();
      detectSecretsWallClockMs = Number(dEnd - dStart) / 1e6;

      try {
        const parsed = JSON.parse(output);
        if (parsed.results) {
          for (const rawFile of Object.keys(parsed.results)) {
            const rel = path.relative(corpusDir, rawFile);
            detectSecretsDetectedFiles.add(normalizePath(rel));
          }
        }
      } catch {
        // ignore parse error
      }
    } catch (err) {
      console.warn('detect-secrets execution error:', err);
    }
  } else {
    console.warn('detect-secrets binary not found at:', detectSecretsBin);
  }
  results.push(evaluateScanner('detect-secrets', 'v1.5.0', corpus, detectSecretsDetectedFiles, detectSecretsWallClockMs));

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

  const reportPath = path.join(reportsDir, 'multi_scanner_benchmark.json');
  fs.writeFileSync(reportPath, JSON.stringify({ timestamp: new Date().toISOString(), totalFiles: corpus.length, results }, null, 2), 'utf8');
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
  };
}

function printBenchmarkSummary(results: ScannerMetrics[], totalFiles: number) {
  console.log('\n===========================================================================================================');
  console.log(`📊 EMPIRICAL SCANNER BENCHMARK REPORT (${totalFiles} Identical Files: 260 TP, 200 FP, 60 Adversarial)`);
  console.log('===========================================================================================================');
  console.log('| Scanner Tool                | Precision (95% CI)   | Recall (95% CI)      | F1 Score | FP Rate | Adversarial | Latency/File |');
  console.log('|:----------------------------|:---------------------|:---------------------|:---------|:--------|:------------|:-------------|');

  for (const r of results) {
    const nameStr = `${r.name} ${r.version}`.padEnd(28, ' ');
    const precStr = `${r.precision}% [${r.precisionCi[0]}%-${r.precisionCi[1]}%]`.padEnd(21, ' ');
    const recStr = `${r.recall}% [${r.recallCi[0]}%-${r.recallCi[1]}%]`.padEnd(21, ' ');
    const f1Str = `${r.f1}%`.padEnd(9, ' ');
    const fprStr = `${r.fpr}%`.padEnd(8, ' ');
    const advStr = `${r.adversarialRate}%`.padEnd(12, ' ');
    const latStr = `${r.latencyPerFileUs} µs`;
    console.log(`| ${nameStr}| ${precStr}| ${recStr}| ${f1Str}| ${fprStr}| ${advStr}| ${latStr} |`);
  }
  console.log('===========================================================================================================\n');
}

// Run standalone if executed directly via multi-benchmark
if (require.main === module && !process.argv[1]?.includes('regression-gate')) {
  runMultiScannerBenchmark();
}
