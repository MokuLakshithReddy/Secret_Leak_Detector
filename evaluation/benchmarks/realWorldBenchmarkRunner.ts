/**
 * Author-Generated, Real-World-Inspired Benchmark Runner
 * Evaluates Secret Leak Detector and any explicitly available comparator tools
 * against 100 deterministic, author-labelled fixtures.
 *
 * The fixture corpus is synthetic and pattern-inspired; it is not a collection
 * of independently sourced incident files and its labels are not independently
 * adjudicated. Missing comparators are never represented as zero-result scans.
 */

import * as fs from 'fs';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { writeRealWorldCorpusToDisk, RealWorldFixture } from '../datasets/realWorldCorpus';
import { scanContent } from '../../src/core/scanner/scanner';
import { getPackageVersion } from '../../src/core/version';

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

function resolveComparatorBinary(toolName: string, candidateRelativePaths: string[]): string | null {
  const isWin = process.platform === 'win32';
  for (const relativePath of candidateRelativePaths) {
    const directPath = path.resolve(process.cwd(), relativePath);
    if (fs.existsSync(directPath)) return directPath;
    if (isWin && !relativePath.toLowerCase().endsWith('.exe')) {
      const windowsPath = path.resolve(process.cwd(), relativePath + '.exe');
      if (fs.existsSync(windowsPath)) return windowsPath;
    }
  }

  try {
    const locator = isWin ? 'where' : 'which';
    const output = execFileSync(locator, [toolName], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    const candidate = output.split(/\\r?\\n/)[0]?.trim();
    if (candidate && fs.existsSync(candidate)) return candidate;
  } catch {
    // A missing optional comparator is handled explicitly by the caller.
  }
  return null;
}

function runComparator(binary: string, args: string[], label: string): string {
  try {
    return execFileSync(binary, args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 64 * 1024 * 1024,
      windowsHide: true,
    }) as string;
  } catch (error: any) {
    const stdout = error?.stdout == null ? '' : String(error.stdout);
    // Some scanners use a non-zero exit code when findings are present. Their
    // structured stdout is still usable; a failure without output is not.
    if (stdout.trim()) return stdout;
    const detail = error?.stderr == null ? (error?.message || String(error)) : String(error.stderr);
    throw new Error(`${label} failed to run: ${detail}`);
  }
}

function readComparatorVersion(binary: string, args: string[], label: string): string {
  try {
    const output = execFileSync(binary, args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      windowsHide: true,
    }).trim();
    return output.split(/\\r?\\n/)[0] || 'unknown';
  } catch {
    return 'unknown';
  }
}

export function runRealWorldBenchmark(options: { sldOnly?: boolean } = {}): RealWorldMetrics[] {
  const rootDir = process.cwd();
  const corpusDir = path.join(rootDir, 'evaluation', 'real_world_corpus');
  const reportsDir = path.join(rootDir, 'evaluation', 'reports');
  const args = process.argv.slice(2);
  const sldOnly = options.sldOnly === true || args.includes('--sld-only');
  const allowMissing = !!(process.env.SLD_ALLOW_MISSING_COMPARATORS || args.includes('--allow-missing'));

  const comparators = [
    {
      key: 'gitleaks',
      label: 'Gitleaks',
      binary: resolveComparatorBinary('gitleaks', [
        path.join('tools', 'bin', 'gitleaks.exe'),
        path.join('tools', 'bin', 'gitleaks'),
        path.join('tools', 'gitleaks'),
      ]),
    },
    {
      key: 'trufflehog',
      label: 'TruffleHog',
      binary: resolveComparatorBinary('trufflehog', [
        path.join('tools', 'bin', 'trufflehog.exe'),
        path.join('tools', 'bin', 'trufflehog'),
        path.join('tools', 'trufflehog'),
      ]),
    },
    {
      key: 'detect-secrets',
      label: 'detect-secrets',
      binary: resolveComparatorBinary('detect-secrets', [
        path.join('tools', 'python', 'Scripts', 'detect-secrets.exe'),
        path.join('tools', 'python', 'Scripts', 'detect-secrets'),
        path.join('tools', 'bin', 'detect-secrets.exe'),
        path.join('tools', 'bin', 'detect-secrets'),
        path.join('tools', 'detect-secrets'),
      ]),
    },
  ];

  if (!sldOnly && !allowMissing) {
    const missing = comparators.filter((tool) => !tool.binary).map((tool) => tool.label);
    if (missing.length) {
      throw new Error(
        `Missing required comparator(s): ${missing.join(', ')}. Install the tools and add them to PATH, or pass --allow-missing to omit unavailable tools, or --sld-only to run SLD alone. No benchmark report was written.`
      );
    }
  }

  fs.mkdirSync(reportsDir, { recursive: true });
  console.log('================================================================================================');
  console.log('🌍 EXECUTING BENCHMARK ON AUTHOR-LABELLED, REAL-WORLD-INSPIRED FIXTURES...');
  console.log('================================================================================================\\n');

  const corpus = writeRealWorldCorpusToDisk(corpusDir);
  const results: RealWorldMetrics[] = [];

  try {
    console.log(`✅ Author-generated fixture corpus staged: ${corpus.length} files`);
    console.log(`   - Labelled positives: ${corpus.filter((c) => c.category === 'true_positive').length}`);
    console.log(`   - Labelled negatives: ${corpus.filter((c) => c.category === 'false_positive').length}\\n`);

    // 1. Secret Leak Detector
    console.log('[1/4] Running Secret Leak Detector...');
    const sldDetected = new Set<string>();
    const sldStart = process.hrtime.bigint();
    for (const item of corpus) {
      const fullPath = path.join(corpusDir, item.relativePath);
      const content = fs.readFileSync(fullPath, 'utf8');
      const findings = scanContent(content, item.relativePath, corpusDir);
      if (findings.length > 0) sldDetected.add(normalize(item.relativePath));
    }
    const sldEnd = process.hrtime.bigint();
    const sldMs = Number(sldEnd - sldStart) / 1e6;
    results.push(evaluateScanner('Secret Leak Detector', getPackageVersion(), corpus, sldDetected, sldMs));

    if (!sldOnly) {
      // 2. Gitleaks
      const gitleaks = comparators[0];
      if (gitleaks.binary) {
        console.log('[2/4] Running Gitleaks...');
        const reportPath = path.join(reportsDir, `gitleaks_rw_report.${process.pid}.json`);
        const detected = new Set<string>();
        const start = process.hrtime.bigint();
        try {
          runComparator(gitleaks.binary, [
            'dir', corpusDir,
            '--report-format', 'json',
            '--report-path', reportPath,
            '--no-banner',
            '--exit-code', '0',
          ], 'Gitleaks');
          if (!fs.existsSync(reportPath)) throw new Error('Gitleaks completed without producing its JSON report.');
          const parsed = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
          if (!Array.isArray(parsed)) throw new Error('Gitleaks report is not a JSON array.');
          for (const leak of parsed) {
            const rawFile = leak.File || leak.file;
            if (typeof rawFile !== 'string') throw new Error('Gitleaks report entry is missing a file path.');
            detected.add(normalize(path.relative(corpusDir, rawFile)));
          }
        } finally {
          try { fs.rmSync(reportPath, { force: true }); } catch {}
        }
        const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
        const version = readComparatorVersion(gitleaks.binary, ['version'], 'Gitleaks');
        results.push(evaluateScanner('Gitleaks', version, corpus, detected, elapsed));
      } else {
        console.warn('Skipping Gitleaks: binary not installed (explicit --allow-missing).');
      }

      // 3. TruffleHog
      const trufflehog = comparators[1];
      if (trufflehog.binary) {
        console.log('[3/4] Running TruffleHog...');
        const start = process.hrtime.bigint();
        const output = runComparator(trufflehog.binary, [
          'filesystem', corpusDir, '--json', '--no-verification', '--no-update',
        ], 'TruffleHog');
        const detected = new Set<string>();
        for (const line of output.split('\\n')) {
          if (!line.trim()) continue;
          let parsed: any;
          try { parsed = JSON.parse(line); } catch {
            throw new Error('TruffleHog emitted a non-JSON line; refusing to create a benchmark report from incomplete output.');
          }
          const rawFile = parsed?.SourceMetadata?.Data?.Filesystem?.file;
          if (typeof rawFile === 'string') detected.add(normalize(path.relative(corpusDir, rawFile)));
        }
        if (!output.trim()) throw new Error('TruffleHog produced no output; refusing to record an empty scan as zero detections.');
        const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
        const version = readComparatorVersion(trufflehog.binary, ['--version'], 'TruffleHog');
        results.push(evaluateScanner('TruffleHog', version, corpus, detected, elapsed));
      } else {
        console.warn('Skipping TruffleHog: binary not installed (explicit --allow-missing).');
      }

      // 4. detect-secrets
      const detectSecrets = comparators[2];
      if (detectSecrets.binary) {
        console.log('[4/4] Running detect-secrets...');
        const start = process.hrtime.bigint();
        const output = runComparator(detectSecrets.binary, ['scan', '--all-files', corpusDir], 'detect-secrets');
        let parsed: any;
        try { parsed = JSON.parse(output); } catch {
          throw new Error('detect-secrets did not emit valid JSON; refusing to create a benchmark report.');
        }
        if (!parsed || typeof parsed.results !== 'object' || parsed.results === null || Array.isArray(parsed.results)) {
          throw new Error('detect-secrets JSON output is missing its results object.');
        }
        const detected = new Set<string>();
        for (const rawFile of Object.keys(parsed.results)) {
          detected.add(normalize(path.relative(corpusDir, rawFile)));
        }
        const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
        const version = readComparatorVersion(detectSecrets.binary, ['--version'], 'detect-secrets');
        results.push(evaluateScanner('detect-secrets', version, corpus, detected, elapsed));
      } else {
        console.warn('Skipping detect-secrets: binary not installed (explicit --allow-missing).');
      }
    }

    printRealWorldSummary(results, corpus.length);

    let sourceCommit = 'unknown';
    try {
      sourceCommit = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    } catch {}

    const reportPath = path.join(reportsDir, 'real_world_benchmark.json');
    fs.writeFileSync(reportPath, JSON.stringify({
      timestamp: new Date().toISOString(),
      detectorVersion: getPackageVersion(),
      sourceCommit,
      corpusProvenance: 'Author-generated synthetic, real-world-inspired fixtures; labels are author-assigned and not independently reviewed.',
      totalFiles: corpus.length,
      results,
    }, null, 2), 'utf8');
    console.log(`\\n📄 Real-World-Inspired Benchmark Report saved to: ${reportPath}\\n`);

    return results;
  } finally {
    try { fs.rmSync(corpusDir, { recursive: true, force: true }); } catch {}
  }
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
