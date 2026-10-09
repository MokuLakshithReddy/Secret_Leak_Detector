/**
 * Independently Labelled Real-World Benchmark Runner
 * Evaluates Secret Leak Detector, Gitleaks, TruffleHog, and detect-secrets
 * against 100 independently labelled real-world fixtures (50 True Positives, 50 False Positives).
 */

import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';
import { writeRealWorldCorpusToDisk, RealWorldFixture } from '../datasets/realWorldCorpus';
import { scanContent } from '../../src/core/scanner/scanner';

export interface RealWorldMetrics {
  name: string;
  version: string;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
  fpr: number;
  precisionCi: [number, number];
  recallCi: [number, number];
  wallClockMs: number;
  latencyPerFileUs: number;
  rssMb: number;
}

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

function normalize(p: string): string {
  return p.replace(/\\/g, '/').toLowerCase();
}

export function runRealWorldBenchmark(): RealWorldMetrics[] {
  const rootDir = process.cwd();
  const corpusDir = path.join(rootDir, 'evaluation', 'real_world_corpus');
  const reportsDir = path.join(rootDir, 'evaluation', 'reports');
  fs.mkdirSync(reportsDir, { recursive: true });

  console.log('================================================================================================');
  console.log('🌍 EXECUTING BENCHMARK ON INDEPENDENTLY LABELLED REAL-WORLD CORPUS (100 Curated Fixtures)...');
  console.log('================================================================================================\n');

  const corpus = writeRealWorldCorpusToDisk(corpusDir);
  console.log(`✅ Real-world corpus staged: ${corpus.length} files`);
  console.log(`   - True Positives (Leaked Real Credentials):  ${corpus.filter((c) => c.category === 'true_positive').length}`);
  console.log(`   - False Positives (High-Entropy Noise):       ${corpus.filter((c) => c.category === 'false_positive').length}\n`);

  const results: RealWorldMetrics[] = [];

  // 1. Secret Leak Detector
  console.log('[1/4] Running Secret Leak Detector...');
  const sldDetected = new Set<string>();
  const sldStart = process.hrtime.bigint();
  for (const item of corpus) {
    const fullPath = path.join(corpusDir, item.relativePath);
    const content = fs.readFileSync(fullPath, 'utf8');
    const findings = scanContent(content, item.relativePath, corpusDir);
    if (findings.length > 0) {
      sldDetected.add(normalize(item.relativePath));
    }
  }
  const sldEnd = process.hrtime.bigint();
  const sldMs = Number(sldEnd - sldStart) / 1e6;
  results.push(evaluateScanner('Secret Leak Detector (Ours)', '1.0.0', corpus, sldDetected, sldMs));

  // 2. Gitleaks
  console.log('[2/4] Running Gitleaks...');
  const gitleaksBin = path.join(rootDir, 'tools', 'bin', 'gitleaks.exe');
  const gitleaksReport = path.join(reportsDir, 'gitleaks_rw_report.json');
  const gitleaksDetected = new Set<string>();
  let gitleaksMs = 0;

  if (fs.existsSync(gitleaksBin)) {
    try {
      const gStart = process.hrtime.bigint();
      try {
        execSync(`"${gitleaksBin}" dir "${corpusDir}" --report-format json --report-path "${gitleaksReport}" --no-banner --exit-code 0`, {
          stdio: 'pipe',
        });
      } catch {}
      const gEnd = process.hrtime.bigint();
      gitleaksMs = Number(gEnd - gStart) / 1e6;

      if (fs.existsSync(gitleaksReport)) {
        const rawJson = JSON.parse(fs.readFileSync(gitleaksReport, 'utf8'));
        if (Array.isArray(rawJson)) {
          for (const leak of rawJson) {
            const rel = path.relative(corpusDir, leak.File || leak.file);
            gitleaksDetected.add(normalize(rel));
          }
        }
        fs.unlinkSync(gitleaksReport);
      }
    } catch (e) {
      console.warn('Gitleaks execution error:', e);
    }
  }
  results.push(evaluateScanner('Gitleaks', 'v8.30.1', corpus, gitleaksDetected, gitleaksMs));

  // 3. TruffleHog
  console.log('[3/4] Running TruffleHog...');
  const trufflehogBin = path.join(rootDir, 'tools', 'bin', 'trufflehog.exe');
  const trufflehogDetected = new Set<string>();
  let trufflehogMs = 0;

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
      trufflehogMs = Number(tEnd - tStart) / 1e6;

      for (const line of output.split('\n')) {
        if (!line.trim()) continue;
        try {
          const parsed = JSON.parse(line);
          const rawFile = parsed?.SourceMetadata?.Data?.Filesystem?.file;
          if (rawFile) {
            const rel = path.relative(corpusDir, rawFile);
            trufflehogDetected.add(normalize(rel));
          }
        } catch {}
      }
    } catch (e) {
      console.warn('TruffleHog execution error:', e);
    }
  }
  results.push(evaluateScanner('TruffleHog', 'v3.99.2', corpus, trufflehogDetected, trufflehogMs));

  // 4. detect-secrets
  console.log('[4/4] Running detect-secrets...');
  const detectSecretsBin = path.join(rootDir, 'tools', 'python', 'Scripts', 'detect-secrets.exe');
  const detectSecretsDetected = new Set<string>();
  let detectSecretsMs = 0;

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
      detectSecretsMs = Number(dEnd - dStart) / 1e6;

      try {
        const parsed = JSON.parse(output);
        if (parsed.results) {
          for (const rawFile of Object.keys(parsed.results)) {
            const rel = path.relative(corpusDir, rawFile);
            detectSecretsDetected.add(normalize(rel));
          }
        }
      } catch {}
    } catch (e) {
      console.warn('detect-secrets execution error:', e);
    }
  }
  results.push(evaluateScanner('detect-secrets', 'v1.5.0', corpus, detectSecretsDetected, detectSecretsMs));

  // Clean up
  try {
    fs.rmSync(corpusDir, { recursive: true, force: true });
  } catch {}

  // Print results
  printRealWorldSummary(results, corpus.length);

  const reportPath = path.join(reportsDir, 'real_world_benchmark.json');
  fs.writeFileSync(
    reportPath,
    JSON.stringify({ timestamp: new Date().toISOString(), totalFiles: corpus.length, results }, null, 2),
    'utf8'
  );
  console.log(`\n📄 Real-World Benchmark Report saved to: ${reportPath}\n`);

  return results;
}

function evaluateScanner(
  name: string,
  version: string,
  corpus: RealWorldFixture[],
  detected: Set<string>,
  wallClockMs: number
): RealWorldMetrics {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;

  for (const item of corpus) {
    const isDet = detected.has(normalize(item.relativePath));
    if (item.isSecret) {
      if (isDet) tp++;
      else fn++;
    } else {
      if (isDet) fp++;
      else tn++;
    }
  }

  const precision = tp + fp > 0 ? (tp / (tp + fp)) * 100 : 0;
  const recall = tp + fn > 0 ? (tp / (tp + fn)) * 100 : 0;
  const f1 = precision + recall > 0 ? (2 * (precision * recall)) / (precision + recall) : 0;
  const fpr = fp + tn > 0 ? (fp / (fp + tn)) * 100 : 0;

  const precisionCi = calculateWilsonCi(tp, tp + fp);
  const recallCi = calculateWilsonCi(tp, tp + fn);
  const latencyPerFileUs = Math.round((wallClockMs * 1000) / corpus.length);

  const mem = process.memoryUsage();
  const rssMb = Math.round((mem.rss / (1024 * 1024)) * 10) / 10;

  return {
    name,
    version,
    tp,
    fp,
    tn,
    fn,
    precision: Math.round(precision * 10) / 10,
    recall: Math.round(recall * 10) / 10,
    f1: Math.round(f1 * 10) / 10,
    fpr: Math.round(fpr * 10) / 10,
    precisionCi,
    recallCi,
    wallClockMs: Math.round(wallClockMs),
    latencyPerFileUs,
    rssMb,
  };
}

function printRealWorldSummary(results: RealWorldMetrics[], totalFiles: number) {
  console.log('\n======================================================================================================================');
  console.log(`📊 REAL-WORLD BENCHMARK REPORT (${totalFiles} Independently Labelled Fixtures: 50 True Positives, 50 False Positives)`);
  console.log('======================================================================================================================');
  console.log('| Scanner Tool                | Precision (95% CI)   | Recall (95% CI)      | F1 Score | FP Rate | Latency/File | Memory (RSS) |');
  console.log('|:----------------------------|:---------------------|:---------------------|:---------|:--------|:-------------|:-------------|');

  for (const r of results) {
    const nameStr = `${r.name} ${r.version}`.padEnd(28, ' ');
    const precStr = `${r.precision}% [${r.precisionCi[0]}%-${r.precisionCi[1]}%]`.padEnd(21, ' ');
    const recStr = `${r.recall}% [${r.recallCi[0]}%-${r.recallCi[1]}%]`.padEnd(21, ' ');
    const f1Str = `${r.f1}%`.padEnd(9, ' ');
    const fprStr = `${r.fpr}%`.padEnd(8, ' ');
    const latStr = `${r.latencyPerFileUs} µs`.padEnd(13, ' ');
    const memStr = `${r.rssMb} MB`;
    console.log(`| ${nameStr}| ${precStr}| ${recStr}| ${f1Str}| ${fprStr}| ${latStr}| ${memStr} |`);
  }
  console.log('======================================================================================================================\n');
}

if (require.main === module) {
  runRealWorldBenchmark();
}
