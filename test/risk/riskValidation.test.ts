import { calculateRiskAssessment } from '../../src/core/risk/riskEngine';
import { DETECTOR_RULES } from '../../src/core/detectors/rules';
import { FileContext } from '../../src/core/context/contextAnalyzer';
import { GitExposure } from '../../src/core/types';

let passed = 0;
let failed = 0;

function assert(cond: boolean, msg: string) {
  if (!cond) {
    console.error(`❌ FAILED: ${msg}`);
    failed++;
  } else {
    console.log(`✅ PASSED: ${msg}`);
    passed++;
  }
}

console.log('============================================================');
console.log('⚖️ RUNNING RISK SCORE MODEL QUANTITATIVE VALIDATION');
console.log('============================================================\n');

const awsRule = DETECTOR_RULES.find((r) => r.id === 'aws-access-key')!;
const stripeRule = DETECTOR_RULES.find((r) => r.id === 'stripe-secret-key')!;
const genericRule = DETECTOR_RULES.find((r) => r.id === 'generic-api-key')!;

// 1. Storage Environment Calibration
console.log('--- 1. Storage Environment Calibration ---');
const configContext: FileContext = {
  isTest: false,
  isDoc: false,
  isConfig: true,
  isSensitiveName: true,
  extension: '.env',
};

const srcContext: FileContext = {
  isTest: false,
  isDoc: false,
  isConfig: false,
  isSensitiveName: false,
  extension: '.ts',
};

const testContext: FileContext = {
  isTest: true,
  isDoc: false,
  isConfig: false,
  isSensitiveName: false,
  extension: '.test.ts',
};

const riskInConfig = calculateRiskAssessment(awsRule, 100, configContext);
const riskInSrc = calculateRiskAssessment(awsRule, 100, srcContext);
const riskInTest = calculateRiskAssessment(awsRule, 100, testContext);

assert(riskInConfig.score > riskInSrc.score, 'Config file risk is higher than standard source code');
assert(riskInSrc.score > riskInTest.score, 'Source code risk is higher than test file');
assert(riskInConfig.tier === 'CRITICAL', 'Live AWS key in config file classified as CRITICAL');

// 2. Git Reachability & Exposure Monotonicity
console.log('\n--- 2. Git Reachability Impact ---');
const remoteExposure: GitExposure = {
  isPresentInHead: true,
  isPresentInHistory: true,
  commitHash: 'a1b2c3d4e5f6',
  branches: ['main', 'origin/main'],
  isRemote: true,
  exposureDurationDays: 45,
};

const historyExposure: GitExposure = {
  isPresentInHead: false,
  isPresentInHistory: true,
  commitHash: 'f6e5d4c3b2a1',
  branches: ['feature-branch'],
  isRemote: false,
  exposureDurationDays: 10,
};

const uncommittedRisk = calculateRiskAssessment(stripeRule, 95, srcContext);
const historyRisk = calculateRiskAssessment(stripeRule, 95, srcContext, historyExposure);
const remoteRisk = calculateRiskAssessment(stripeRule, 95, srcContext, remoteExposure);

assert(remoteRisk.score > historyRisk.score, 'Remotely pushed credential risk exceeds local history');
assert(historyRisk.score > uncommittedRisk.score, 'History-committed risk exceeds uncommitted working tree');

// 3. Mathematical Boundary Constraints
console.log('\n--- 3. Mathematical Boundary Constraints ---');
for (const rule of DETECTOR_RULES) {
  for (const conf of [0, 50, 100]) {
    for (const ctx of [configContext, srcContext, testContext]) {
      const assessment = calculateRiskAssessment(rule, conf, ctx, remoteExposure);
      assert(assessment.score >= 0 && assessment.score <= 100, `Score bounded [0, 100] for ${rule.id} (got ${assessment.score})`);
      assert(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(assessment.tier), `Valid risk tier assigned for ${rule.id}`);
      assert(assessment.factors.length === 4, `All 4 risk factors documented for ${rule.id}`);
    }
  }
}

console.log('\n============================================================');
console.log(`🎉 RISK VALIDATION SUMMARY: ${passed} PASSED, ${failed} FAILED`);
console.log('============================================================\n');

if (failed > 0) process.exit(1);
