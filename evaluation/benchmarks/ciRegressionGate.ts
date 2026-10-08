/**
 * CI Benchmark Regression Gate
 * Enforces strict regression thresholds:
 * 1. F1 score must not decrease (threshold >= 99.0%)
 * 2. False-Positive Rate must not increase (threshold <= 1.0%)
 * 3. Latency must not regress (threshold <= 1000 µs per file target)
 * 4. Adversarial detection rate must not regress (threshold >= 95.0%)
 */

import * as fs from 'fs';
import * as path from 'path';
import { runMultiScannerBenchmark, ScannerMetrics } from './multiScannerRunner';

interface RegressionThresholds {
  minF1: number;
  maxFpr: number;
  maxLatencyUs: number;
  minAdversarialRate: number;
}

const DEFAULT_THRESHOLDS: RegressionThresholds = {
  minF1: 99.0,
  maxFpr: 1.0,
  maxLatencyUs: 1000,
  minAdversarialRate: 95.0,
};

export function runRegressionGate(thresholds = DEFAULT_THRESHOLDS): void {
  console.log('=================================================================================');
  console.log('🛡️ RUNNING CI BENCHMARK REGRESSION GATE');
  console.log('=================================================================================');
  console.log(`Gate Thresholds:`);
  console.log(`  • Minimum F1 Score:            ${thresholds.minF1}%`);
  console.log(`  • Maximum False-Positive Rate: ${thresholds.maxFpr}%`);
  console.log(`  • Maximum Latency Per File:    ${thresholds.maxLatencyUs} µs`);
  console.log(`  • Minimum Adversarial Rate:    ${thresholds.minAdversarialRate}%`);

  const isFast = process.argv.includes('--fast') || process.env.CI_FAST === 'true';
  const benchmarkResults = runMultiScannerBenchmark({ sldOnly: isFast });
  const sld = benchmarkResults.find((r) => r.name.includes('Secret Leak Detector'));

  if (!sld) {
    console.error('❌ FATAL: Secret Leak Detector metrics not found in benchmark run.');
    process.exit(1);
  }

  console.log('\n--- Evaluating SLD Performance Against Gates ---');
  let hasRegression = false;

  // 1. F1 Gate
  if (sld.f1 < thresholds.minF1) {
    console.error(`❌ REGRESSION: F1 score regressed to ${sld.f1}% (Required: >= ${thresholds.minF1}%)`);
    hasRegression = true;
  } else {
    console.log(`✅ PASSED: F1 Score = ${sld.f1}% (>= ${thresholds.minF1}%)`);
  }

  // 2. False-Positive Rate Gate
  if (sld.fpr > thresholds.maxFpr) {
    console.error(`❌ REGRESSION: False-Positive Rate increased to ${sld.fpr}% (Required: <= ${thresholds.maxFpr}%)`);
    hasRegression = true;
  } else {
    console.log(`✅ PASSED: False-Positive Rate = ${sld.fpr}% (<= ${thresholds.maxFpr}%)`);
  }

  // 3. Latency Regression Gate
  if (sld.latencyPerFileUs > thresholds.maxLatencyUs) {
    console.error(`❌ REGRESSION: Latency per file regressed to ${sld.latencyPerFileUs} µs (Required: <= ${thresholds.maxLatencyUs} µs)`);
    hasRegression = true;
  } else {
    console.log(`✅ PASSED: Latency Per Target = ${sld.latencyPerFileUs} µs (<= ${thresholds.maxLatencyUs} µs)`);
  }

  // 4. Adversarial Rate Gate
  if (sld.adversarialRate < thresholds.minAdversarialRate) {
    console.error(`❌ REGRESSION: Adversarial rate regressed to ${sld.adversarialRate}% (Required: >= ${thresholds.minAdversarialRate}%)`);
    hasRegression = true;
  } else {
    console.log(`✅ PASSED: Adversarial Detection Rate = ${sld.adversarialRate}% (>= ${thresholds.minAdversarialRate}%)`);
  }

  console.log('=================================================================================');
  if (hasRegression) {
    console.error('💥 CI REGRESSION GATE FAILED: Performance or accuracy regression detected.');
    process.exit(1);
  } else {
    console.log('🎉 ALL BENCHMARK REGRESSION GATES PASSED CLEANLY!');
    console.log('=================================================================================\n');
  }
}

if (require.main === module) {
  runRegressionGate();
}
