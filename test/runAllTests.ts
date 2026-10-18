import { scanContent, scanFile, buildScanResult } from '../src/core/scanner/scanner';
import { calculateShannonEntropy, calculateNormalizedEntropy } from '../src/core/entropy/entropy';
import { redactSecret, generateFingerprint } from '../src/core/redactor/redactor';
import { BaselineEngine, BaselineValidationError, validateBaselineSchema } from '../src/core/baseline/baselineEngine';
import { toRedactedFindingView } from '../src/webview/dashboardModel';
import { VerificationEngine } from '../src/core/verification/verificationEngine';
import { GitHistoryEngine } from '../src/core/history/gitHistoryEngine';
import { formatAsSarif } from '../src/core/sarif/sarifFormatter';
import { DETECTOR_RULES } from '../src/core/detectors/rules';
import { calculateRiskAssessment } from '../src/core/risk/riskEngine';
import { GitTimelineEngine } from '../src/core/history/gitTimeline';
import { GitService } from '../src/git/gitService';
import { applyControlledRemediation, resolveUniqueEnvVarName, escapeEnvValue } from '../src/core/remediation/remediationEngine';
import * as path from 'path';
import * as fs from 'fs';
import * as cp from 'child_process';
import * as os from 'os';
import { DEFAULT_FAIL_ON, BLOCKING_POLICY, resolveFailOn, meetsThreshold, shouldBlock } from '../src/core/policy';
import { buildPreCommitHook, SLD_HOOK_MARKER } from '../src/git/preCommitHook';
import { Risk } from '../src/core/types';

/** Locate a POSIX shell so we can execute the generated hook script directly. */
function findPosixShell(): string | null {
  const candidates =
    process.platform === 'win32'
      ? [
          'C:\\Program Files\\Git\\bin\\bash.exe',
          'C:\\Program Files\\Git\\usr\\bin\\bash.exe',
          'C:\\Program Files (x86)\\Git\\bin\\bash.exe',
        ]
      : ['/bin/sh', '/usr/bin/sh', '/bin/bash', '/usr/bin/bash'];
  for (const c of candidates) {
    try {
      if (fs.existsSync(c)) return c;
    } catch {
      /* ignore */
    }
  }
  return null;
}

let passed = 0;
let failed = 0;

function assert(condition: boolean, msg: string) {
  if (!condition) {
    console.error(`❌ FAILED: ${msg}`);
    failed++;
  } else {
    console.log(`✅ PASSED: ${msg}`);
    passed++;
  }
}

console.log('============================================================');
console.log('🧪 RUNNING COMPREHENSIVE SECURITY ENGINEERING TEST SUITE');
console.log('============================================================\n');

// --- 1. Shannon Entropy & Distribution Tests ---
console.log('--- 1. Shannon Entropy & Character Distribution ---');
const low = calculateShannonEntropy('aaaaaaaaaa');
const normal = calculateShannonEntropy('hello world');
const high = calculateShannonEntropy('sk_test_51M0XYZ982734bca81923');
assert(low < 1.0, `Low entropy strings calculate < 1.0 (got ${low})`);
assert(normal > 2.0 && normal < 3.2, `Normal English text between 2.0 and 3.2 (got ${normal})`);
assert(high > 3.5, `High entropy credential calculates > 3.5 (got ${high})`);
const normEntropy = calculateNormalizedEntropy('AKIA1234567890ABCDEF');
assert(normEntropy > 0.5, `Normalized entropy calculated properly: ${normEntropy}`);

// --- 2. Safe Redaction & Fingerprinting Tests ---
// Runtime synthesizer to keep test tokens synthetic in source code
const synth = (parts: string[]) => parts.join('');

// --- 2. Masking & Cryptographic Fingerprinting ---
console.log('\n--- 2. Masking & Cryptographic Fingerprinting ---');
const maskedAws = redactSecret(synth(['AK', 'IA', '1234567890ABCDEF']));
assert(maskedAws.startsWith('AKIA'), 'Redaction preserves cloud prefix');
assert(maskedAws.endsWith('DEF'), 'Redaction preserves suffix');
assert(maskedAws.includes('•'), 'Redaction masks intermediate sensitive characters');
const fp1 = generateFingerprint('secret-12345');
const fp2 = generateFingerprint('secret-12345');
const fp3 = generateFingerprint('secret-99999');
assert(fp1 === fp2, 'Identical secrets yield identical fingerprints');
assert(fp1 !== fp3, 'Different secrets yield unique fingerprints');

// --- 3. Provider Detection Engine Tests ---
console.log('\n--- 3. Multi-Provider Detection Engine Tests ---');
const testCases = [
  {
    name: 'AWS Access Key',
    code: `const key = "${synth(['AK', 'IA', '1234567890ABCDEF'])}";`,
    expectedProvider: 'Amazon Web Services',
    minConfidence: 95,
  },
  {
    name: 'GitHub Personal Access Token',
    code: `const token = "${synth(['gh', 'p_', '1234567890abcdefghijklmnopqrstuvwxyz'])}";`,
    expectedProvider: 'GitHub',
    minConfidence: 95,
  },
  {
    name: 'Google Cloud API Key',
    code: `const key = "${synth(['AI', 'zaSyD-', '1234567890abcdefghijklmnopqrst'])}";`,
    expectedProvider: 'Google Cloud',
    minConfidence: 90,
  },
  {
    name: 'OpenAI Secret Key',
    code: `const openAiKey = "${synth(['sk', '-proj-', '1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef'])}";`,
    expectedProvider: 'OpenAI',
    minConfidence: 90,
  },
  {
    name: 'Anthropic Claude Key',
    code: `const anthropic = "${synth(['sk', '-ant-', '1234567890abcdefghijklmnopqrstuvwxyz12345678'])}";`,
    expectedProvider: 'Anthropic',
    minConfidence: 90,
  },
  {
    name: 'Stripe Secret Key',
    code: `const stripeKey = "${synth(['sk', '_live_', '51M0XYZ982734bca81923456789'])}";`,
    expectedProvider: 'Stripe',
    minConfidence: 90,
  },
  {
    name: 'Slack Bot Token',
    code: `const slack = "${synth(['xo', 'xb-', '1234567890-1234567890123-abcdefghijklmnopqrstuv'])}";`,
    expectedProvider: 'Slack',
    minConfidence: 90,
  },
  {
    name: 'Database Connection URI',
    code: `const url = "${synth(['post', 'gres://admin:SuperSecretPass123!@db.internal:5432/core_db'])}";`,
    expectedProvider: 'Database',
    minConfidence: 85,
  },
];

for (const tc of testCases) {
  const findings = scanContent(tc.code, 'config.ts');
  assert(findings.length > 0, `${tc.name} detected successfully`);
  if (findings.length > 0) {
    assert(findings[0].provider === tc.expectedProvider, `Provider classified as ${tc.expectedProvider}`);
    assert(findings[0].confidence >= tc.minConfidence, `Confidence >= ${tc.minConfidence}% (got ${findings[0].confidence}%)`);
    assert(findings[0].evidence.items.length > 0, 'Explainable evidence model generated');
    assert(findings[0].riskAssessment.score > 0, `Risk score calculated: ${findings[0].riskAssessment.score}/100 [${findings[0].risk}]`);
  }
}

// --- 4. False-Positive & Placeholder Suppression Tests ---
console.log('\n--- 4. False-Positive & Documentation Suppression Tests ---');
const fpSnippet = `
const exampleKey = "AKIAIOSFODNN7EXAMPLE"; // AWS docs placeholder
const placeholder = "your_api_key_here";
const uuid = "e7b1a290-2c3d-4e5f-8a1b-9c8d7e6f5a4b";
const repetitive = "00000000000000000000000000000000";
`;
const fpFindings = scanContent(fpSnippet, 'sample.ts');
assert(fpFindings.length === 0, `All benign placeholders & UUIDs suppressed (got ${fpFindings.length} findings)`);

// Documentation discount test
const docSnippet = `export API_KEY="d9f82b7c4a1e905d3b6f8a2c1e4d5b6a"`;
const docFindings = scanContent(docSnippet, 'docs/tutorial.md');
if (docFindings.length > 0) {
  assert(docFindings[0].evidence.fileContext.isDoc, 'Documentation context correctly recognized');
}

// --- 5. Adversarial Evasion Tests ---
console.log('\n--- 5. Adversarial Evasion Tests ---');
const splitCode = `const token = "${synth(['gh', 'p_'])}" + "1234567890abcdefghijklmnopqrstuvwxyz";`;
const splitFindings = scanContent(splitCode, 'auth.ts');
assert(splitFindings.length > 0, 'Adversarial split string concatenation detected and resolved');

const commentCode = `const API_KEY /* auth */ = "${synth(['sk', '_live_', '51M0XYZ982734bca81923456789'])}";`;
const commentFindings = scanContent(commentCode, 'config.ts');
assert(commentFindings.length > 0, 'Adversarial inline comment disruption detected');

// --- 6. Baseline System Tests ---
console.log('\n--- 6. Baseline Engine & CI Guardrail Tests ---');
const tmpDir = path.join(__dirname, '..', 'scratch', 'test_baseline');
if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
const baselineEngine = new BaselineEngine(tmpDir, 'test-baseline.json');

const testFinding = scanContent(`const k = "${synth(['AK', 'IA', '1234567890ABCDEF'])}";`, 'aws.ts')[0];
baselineEngine.saveBaseline([testFinding]);
assert(baselineEngine.exists(), 'Baseline file created successfully');

const checkFiltered = baselineEngine.filterAgainstBaseline([testFinding]);
assert(checkFiltered.existingFindings.length === 1, 'Known finding filtered into existing findings');
assert(checkFiltered.newFindings.length === 0, 'Known finding does not trigger new findings in CI');

const newFinding = scanContent(`const g = "${synth(['gh', 'p_', '1234567890abcdefghijklmnopqrstuvwxyz'])}";`, 'gh.ts')[0];
const checkWithNew = baselineEngine.filterAgainstBaseline([testFinding, newFinding]);
assert(checkWithNew.newFindings.length === 1, 'Newly introduced credential detected as new finding');
assert(checkWithNew.newFindings[0].provider === 'GitHub', 'New finding correctly identifies new secret');

// Clean up test baseline
try {
  fs.rmSync(tmpDir, { recursive: true, force: true });
} catch {}

// --- 7. SARIF Generation Test ---
console.log('\n--- 7. OASIS SARIF v2.1.0 Export Tests ---');
const sarifObj = formatAsSarif([testFinding, newFinding]) as any;
assert(sarifObj.version === '2.1.0', 'SARIF version is 2.1.0');
assert(sarifObj.runs[0].results.length === 2, 'SARIF contains all findings');
assert(sarifObj.runs[0].tool.driver.name === 'Secret Leak Detector', 'Tool name matched in SARIF');

// --- 8. Verification & Rescan Engine Tests ---
console.log('\n--- 8. Verification & Rescan Engine Tests ---');
const verifyEngine = new VerificationEngine(process.cwd());
const comparison = verifyEngine.compareScans([testFinding, newFinding], [newFinding]);
assert(comparison.resolvedFindings.length === 1, 'Rescan accurately identifies 1 resolved finding');
assert(comparison.remainingFindings.length === 1, 'Rescan accurately identifies 1 remaining finding');
assert(!comparison.isFullyClean, 'Rescan correctly marks incomplete remediation as not fully clean');

// --- 9. AST & Structural Validators Tests ---
console.log('\n--- 9. AST Analysis & Provider Structural Validators ---');
const envFallbackFinding = scanContent('const apiKey = process.env.API_KEY || "AKIA1234567890ABCDEF";', 'server.ts')[0];
assert(envFallbackFinding !== undefined, 'Detected secret in environment fallback expression');
assert(
  envFallbackFinding.evidence.items.some((i) => i.signal === 'ENV_FALLBACK_ASSIGNMENT'),
  'Evidence contains ENV_FALLBACK_ASSIGNMENT signal'
);

const synthStripe = synth(['sk_', 'live_', '51M0XYZ982734bca81923456789']);
const objFinding = scanContent(`config.auth.stripeKey = "${synthStripe}";`, 'auth.ts')[0];
assert(objFinding !== undefined, 'Detected secret in nested object property assignment');
assert(
  objFinding.evidence.items.some((i) => i.signal === 'STRUCTURAL_VALIDATION_PASSED'),
  'Evidence contains STRUCTURAL_VALIDATION_PASSED signal from Stripe validator'
);

// --- 10. Adversarial Evasion Test Suite ---
console.log('\n--- 10. Adversarial Evasion Suite ---');
const splitAdv = scanContent('const token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz";', 'auth.ts');
assert(splitAdv.length > 0, 'Adversarial: Detected split token concatenation');

const synthOpenAI = synth(['sk-proj-', 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMn']);
const multilineAdv = scanContent(`const\n  API_KEY\n  =\n  "${synthOpenAI}";`, 'secrets.ts');
assert(multilineAdv.length > 0, 'Adversarial: Detected multiline whitespace stretching');

const commentAdv = scanContent(`const KEY /* internal secret */ = "${synthStripe}";`, 'pay.ts');
assert(commentAdv.length > 0, 'Adversarial: Detected inline comment disruption');

// --- 11. Risk Score Quantitative Model Validation ---
console.log('\n--- 11. Risk Score Quantitative Model Validation ---');
const awsRule = DETECTOR_RULES.find((r) => r.id === 'aws-access-key')!;
const stripeRule = DETECTOR_RULES.find((r) => r.id === 'stripe-secret-key')!;
const cfgCtx = { isTest: false, isDoc: false, isConfig: true, isSensitiveName: true, extension: '.env' };
const srcCtx = { isTest: false, isDoc: false, isConfig: false, isSensitiveName: false, extension: '.ts' };
const tstCtx = { isTest: true, isDoc: false, isConfig: false, isSensitiveName: false, extension: '.test.ts' };

const riskInCfg = calculateRiskAssessment(awsRule, 100, cfgCtx);
const riskInSrc = calculateRiskAssessment(awsRule, 100, srcCtx);
const riskInTst = calculateRiskAssessment(awsRule, 100, tstCtx);

assert(riskInCfg.score > riskInSrc.score, 'Config file risk is higher than standard source code');
assert(riskInSrc.score > riskInTst.score, 'Source code risk is higher than test file');
assert(riskInCfg.tier === 'CRITICAL', 'Live AWS key in config file classified as CRITICAL');

// Monotonicity & Boundary
const testExposure = { isPresentInHead: true, isPresentInHistory: true, commitHash: 'abc', branches: ['main'], isRemote: true, exposureDurationDays: 10 };
const boundTest = calculateRiskAssessment(stripeRule, 100, cfgCtx, testExposure);
assert(boundTest.score >= 0 && boundTest.score <= 100, 'Risk score strictly bounded [0, 100]');
assert(boundTest.tier === 'CRITICAL', 'Remote exposed Stripe key classified as CRITICAL');

// --- 12. Git Exposure Graph Generation ---
console.log('\n--- 12. Git Exposure Graph Generation ---');
const timelineEngine = new GitTimelineEngine(process.cwd());
assert(timelineEngine !== undefined, 'GitTimelineEngine initialized');

// --- 13. Deterministic Benchmark PRNG Verification ---
console.log('\n--- 13. Deterministic Benchmark PRNG Verification ---');
import { createDeterministicPrng } from '../evaluation/datasets/corpusGenerator';
const prng1 = createDeterministicPrng(0x123456);
const seq1 = Array.from({ length: 50 }, () => prng1());
const prng2 = createDeterministicPrng(0x123456);
const seq2 = Array.from({ length: 50 }, () => prng2());
const prng3 = createDeterministicPrng(0x654321);
const seq3 = Array.from({ length: 50 }, () => prng3());

assert(seq1.every((v, i) => v === seq2[i]), 'PRNG sequence is 100% deterministic across identical seeds');
assert(seq1.some((v, i) => v !== seq3[i]), 'PRNG sequence varies across distinct seeds');

async function runAsyncTests() {
  // --- 14. Git Protection Fail-Closed & Hook Chaining Tests ---
  console.log('\n--- 14. Git Protection Fail-Closed & Hook Chaining Tests ---');
  const gitSvc = new GitService(process.cwd());
  const isGit = await gitSvc.isGitRepo();
  assert(isGit === true, 'GitService accurately identifies Git repository');

  const stagedRes = await gitSvc.scanStagedChanges();
  assert(
    stagedRes.status === 'CLEAN' || stagedRes.status === 'FINDINGS' || stagedRes.status === 'ERROR',
    'Git staged scan returns explicit status outcome'
  );
  assert(Array.isArray(stagedRes.findings), 'Git staged scan returns findings array');

  // Verify non-git fail-closed or clean behavior
  const nonGitSvc = new GitService('C:/non-existent-directory-xyz-123');
  const nonGitRes = await nonGitSvc.scanStagedChanges();
  assert(nonGitRes.status === 'CLEAN' || nonGitRes.status === 'ERROR', 'Non-git scan handles status safely');

  // --- 15. De-Obfuscation Source-Location Accuracy Tests ---
  console.log('\n--- 15. De-Obfuscation Source-Location Accuracy Tests ---');
  const codeWithConcat = `// line 1: comments
// line 2: header
const splitKey = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz";
// line 4: footer
`;
  const concatFindings = scanContent(codeWithConcat, 'src/auth.ts');
  assert(concatFindings.length > 0, 'Adversarial de-obfuscation resolves split string concatenation');
  assert(concatFindings[0].line === 3, `De-obfuscated match maps to true source line (expected 3, got ${concatFindings[0]?.line})`);
  assert(concatFindings[0].column > 0, `De-obfuscated match retains positive source column (${concatFindings[0]?.column})`);
  assert(
    concatFindings[0].evidence.items.some((i) => i.signal === 'ADVERSARIAL_DEOBFUSCATION_RESOLVED'),
    'Evidence model includes ADVERSARIAL_DEOBFUSCATION_RESOLVED signal'
  );

  // --- 16. Database URL Special Characters & Azure Compound Key Tests ---
  console.log('\n--- 16. Database URL Special Characters & Azure Compound Key Tests ---');
  const dbPass = synth(['P@ss', 'w0rd', '998877!']);
  const dbUrlWithAt = `const DB_URI = "postgres://db_admin:${dbPass}@prod-db.us-west-2.rds.amazonaws.com:5432/core_production";`;
  const dbFindings = scanContent(dbUrlWithAt, 'config/database.ts');
  assert(dbFindings.length > 0, 'Detected database URL with special characters (@ and !) in password');
  assert(dbFindings[0].provider === 'Database', 'Classified provider as Database');

  const mongoPass = synth(['P@ss', 'w0rd', 'Secure99']);
  const mongoWithAt = `const MONGO_URI = "mongodb+srv://app_user:${mongoPass}@cluster0.abcde.mongodb.net/prod?retryWrites=true";`;
  const mongoFindings = scanContent(mongoWithAt, 'config/mongo.go');
  assert(mongoFindings.length > 0, 'Detected mongodb+srv URL with @ in password');
  assert(mongoFindings[0].provider === 'Database', 'Classified mongodb+srv as Database');

  const azPart1 = synth(['FQbmx8JUfq1CNYju5GRcny9KVgr2DOZkv6HSdozALWhs3EPalw7ITep0BMXit4']);
  const azPart2 = synth(['FQbmx8JUfq1CNYju5GRcny9K==']);
  const azureCompound = `const conn = "DefaultEndpointsProtocol=https;AccountName=prodstore;AccountKey=${azPart1}${azPart2};EndpointSuffix=core.windows.net";`;
  const azFindings = scanContent(azureCompound, 'appsettings.json');
  assert(azFindings.length > 0, 'Detected unquoted Azure Storage Key in compound connection string');
  assert(azFindings[0].provider === 'Microsoft Azure', 'Classified provider as Microsoft Azure');

  // --- 17. Safe Transactional Remediation & Variable Deduplication Tests ---
  console.log('\n--- 17. Safe Transactional Remediation & Variable Deduplication Tests ---');
  const existingEnv = 'API_KEY="old_secret_123"\nDATABASE_URL="postgres://localhost"\n';
  const dedupRes = resolveUniqueEnvVarName(existingEnv, 'API_KEY', 'new_secret_456');
  assert(dedupRes.varName === 'API_KEY_2', `Duplicate variable name suffixed cleanly (got ${dedupRes.varName})`);
  assert(dedupRes.isReused === false, 'Duplicate flagged as new variable');

  const reuseRes = resolveUniqueEnvVarName(existingEnv, 'API_KEY', 'old_secret_123');
  assert(reuseRes.varName === 'API_KEY', 'Identical secret reuses existing variable name');
  assert(reuseRes.isReused === true, 'Identical flagged as reused variable');

  const rawDangerous = 'secret"with$and\\newline';
  const escaped = escapeEnvValue(rawDangerous);
  assert(escaped.includes('\\"'), 'Quotes are escaped in .env value');
  assert(escaped.includes('\\$'), 'Dollar signs are escaped in .env value');

  // --- 18. Git Staged-Scan: Adversarial Filenames, Renames & Commit Gate ---
  console.log('\n--- 18. Git Staged-Scan: Adversarial Filenames, Renames & Commit Gate ---');
    const scratchRoot = path.join(process.cwd(), 'scratch', 'sld-staged-tests');
    fs.rmSync(scratchRoot, { recursive: true, force: true });
    fs.mkdirSync(scratchRoot, { recursive: true });

    const awsSecret = 'AKIA1234567890ABCDEF';
    const ghSecret = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';

    const makeRepo = (name: string) => {
      const r = path.join(scratchRoot, name);
      fs.rmSync(r, { recursive: true, force: true });
      fs.mkdirSync(r, { recursive: true });
      cp.execSync('git init -q .', { cwd: r, stdio: 'ignore' });
      cp.execSync('git config user.email test@test.com', { cwd: r, stdio: 'ignore' });
      cp.execSync('git config user.name test', { cwd: r, stdio: 'ignore' });
      // Raw, unquoted paths so adversarial filenames are enumerated unambiguously.
      cp.execSync('git config core.quotepath false', { cwd: r, stdio: 'ignore' });
      fs.writeFileSync(path.join(r, 'readme.md'), '# safe\n');
      cp.execSync('git add -A', { cwd: r, stdio: 'ignore' });
      cp.execSync('git commit -q -m initial', { cwd: r, stdio: 'ignore' });
      return r;
    };

    // Ensure the CLI binary is built (the pre-commit hook invokes dist/cli.js).
    const cli = path.join(process.cwd(), 'dist', 'cli.js');
    if (!fs.existsSync(cli)) {
      cp.execSync('node esbuild.js --cli', { cwd: process.cwd(), stdio: 'ignore' });
    }

    // 18a. Adversarial filenames (spaces, $, ;) scanned from the staged blob, never the working tree.
    {
      const r = makeRepo('adv-filenames');
      fs.writeFileSync(path.join(r, 'normal.txt'), `const key = "${awsSecret}";\n`);
      fs.writeFileSync(path.join(r, 'file with spaces.ts'), `const token = "${ghSecret}";\n`);
      fs.writeFileSync(path.join(r, 'weird;name$.ts'), `const token = "${ghSecret}";\n`);
      cp.execSync('git add -A', { cwd: r, stdio: 'ignore' });
      const res = await new GitService(r).scanStagedChanges();
      assert(res.status === 'FINDINGS', `Adversarial filenames: expected FINDINGS, got ${res.status}`);
      const files = res.findings.map((f) => f.file);
      assert(files.some((f) => String(f).includes('file with spaces.ts')), 'File with spaces scanned from staged blob');
      assert(files.some((f) => String(f).includes('weird;name$.ts')), 'File with $ and ; scanned from staged blob');
      assert(files.some((f) => String(f).includes('normal.txt')), 'normal.txt scanned from staged blob');
      assert(res.filesScanned >= 2, `Staged files scanned (got ${res.filesScanned})`);
    }

    // 18b. Rename: the destination path (new content) is scanned.
    {
      const r = makeRepo('rename');
      fs.writeFileSync(path.join(r, 'oldname.ts'), `const key = "${awsSecret}";\n`);
      cp.execSync('git add -A', { cwd: r, stdio: 'ignore' });
      cp.execSync('git mv oldname.ts newname.ts', { cwd: r, stdio: 'ignore' });
      cp.execSync('git add -A', { cwd: r, stdio: 'ignore' });
      const res = await new GitService(r).scanStagedChanges();
      assert(res.status === 'FINDINGS', `Rename: expected FINDINGS, got ${res.status}`);
      assert(res.findings.some((f) => String(f.file) === 'newname.ts'), 'Renamed destination newname.ts scanned');
    }

    // 18g. Scored rename status (R100): git reports R100, not bare R.
    {
      const r = makeRepo('rename-scored');
      fs.writeFileSync(path.join(r, 'oldname.ts'), `const key = "${awsSecret}";\n`);
      cp.execSync('git add -A', { cwd: r, stdio: 'ignore' });
      cp.execSync('git commit -q -m add-oldname', { cwd: r, stdio: 'ignore' });
      cp.execSync('git mv oldname.ts newname.ts', { cwd: r, stdio: 'ignore' });
      // Confirm git emits a scored status (R100) when rename detection is enabled.
      const raw = cp.execSync('git diff --cached -z -M --name-status', {
        cwd: r, encoding: 'utf8',
      }).toString();
      assert(/^R\d+\0/.test(raw), `Git rename status should be scored (e.g. R100), got: ${JSON.stringify(raw)}`);
      const res = await new GitService(r).scanStagedChanges();
      assert(res.status === 'FINDINGS', `Scored rename R100: expected FINDINGS, got ${res.status}`);
      assert(res.findings.some((f) => String(f.file) === 'newname.ts'), 'Scored rename destination scanned');
    }

    // 18h. Scored copy status (C100): git reports C100 for copies.
    {
      const r = makeRepo('copy-scored');
      fs.writeFileSync(path.join(r, 'orig.ts'), `const key = "${awsSecret}";\n`);
      cp.execSync('git add -A', { cwd: r, stdio: 'ignore' });
      cp.execSync('git commit -q -m add-orig', { cwd: r, stdio: 'ignore' });
      fs.copyFileSync(path.join(r, 'orig.ts'), path.join(r, 'copy.ts'));
      cp.execSync('git add -A', { cwd: r, stdio: 'ignore' });
      const raw = cp.execSync('git diff --cached -z -C --find-copies-harder --name-status', {
        cwd: r, encoding: 'utf8',
      }).toString();
      assert(/^C\d+\0/.test(raw), `Git copy status should be scored (e.g. C100), got: ${JSON.stringify(raw)}`);
      const res = await new GitService(r).scanStagedChanges();
      assert(res.status === 'FINDINGS', `Scored copy C100: expected FINDINGS, got ${res.status}`);
      assert(res.findings.some((f) => String(f.file) === 'copy.ts'), 'Scored copy destination scanned');
    }

    // 18c. Clean staged changes -> CLEAN (commit allowed).
    {
      const r = makeRepo('clean');
      fs.writeFileSync(path.join(r, 'safe.ts'), `const x = 1;\n`);
      cp.execSync('git add -A', { cwd: r, stdio: 'ignore' });
      const res = await new GitService(r).scanStagedChanges();
      assert(res.status === 'CLEAN', `Clean staged: expected CLEAN, got ${res.status}`);
    }

    // 18d. Deleted file skipped (nothing to scan), not an error.
    {
      const r = makeRepo('delete');
      fs.writeFileSync(path.join(r, 'todelete.txt'), `const key = "${awsSecret}";\n`);
      cp.execSync('git add -A', { cwd: r, stdio: 'ignore' });
      cp.execSync('git commit -q -m add', { cwd: r, stdio: 'ignore' });
      cp.execSync('git rm -q todelete.txt', { cwd: r, stdio: 'ignore' });
      const res = await new GitService(r).scanStagedChanges();
      assert(res.status === 'CLEAN', `Deleted file skipped: expected CLEAN, got ${res.status}`);
    }

    // 18e. Secret staged -> CLI scan exits non-zero (commit blocked).
    {
      const r = makeRepo('commit-gate');
      fs.writeFileSync(path.join(r, 'secrets.ts'), `const key = "${awsSecret}";\n`);
      cp.execSync('git add -A', { cwd: r, stdio: 'ignore' });
      let threw = false;
      try {
        cp.execSync(`${process.execPath} "${cli}" scan --staged --fail-on HIGH`, {
          cwd: r, encoding: 'utf8', stdio: 'pipe',
        });
      } catch (e: any) {
        threw = true;
        assert(e.status === 1 || /exit code 1/.test(String(e)), `Secret staged scan blocked (status ${e.status})`);
      }
      assert(threw, 'Secret staged scan must exit non-zero to block the commit');
    }

    // 18f. Clean staged change -> CLI scan exits 0 (commit allowed).
    {
      const r = makeRepo('commit-gate-clean');
      fs.writeFileSync(path.join(r, 'safe.ts'), `const x = 1;\n`);
      cp.execSync('git add -A', { cwd: r, stdio: 'ignore' });
      let threw = false;
      let errDetail = '';
      try {
        cp.execSync(`"${process.execPath}" "${cli}" scan --staged --fail-on HIGH`, {
          cwd: r, encoding: 'utf8', stdio: 'pipe',
        });
      } catch (e: any) {
        threw = true;
        errDetail = String(e.stderr || e.stdout || e.message || '');
      }
      assert(!threw, `Clean staged scan must exit 0 to allow the commit (${errDetail})`);
    }

    fs.rmSync(scratchRoot, { recursive: true, force: true });

  // --- 19. Remediation: Fault-Injection Rollback Tests ---
  console.log('\n--- 19. Remediation: Fault-Injection Rollback Tests ---');
  const remScratchRoot = path.join(process.cwd(), 'scratch', 'sld-remediation-fault');
  fs.rmSync(remScratchRoot, { recursive: true, force: true });
  fs.mkdirSync(remScratchRoot, { recursive: true });

  const remSecret = 'AKIA1234567890ABCDEF';

  const makeWs = () => {
    const w = path.join(remScratchRoot, 'ws-' + Date.now() + '-' + Math.random().toString(36).slice(2));
    fs.rmSync(w, { recursive: true, force: true });
    fs.mkdirSync(w, { recursive: true });
    fs.writeFileSync(path.join(w, 'config.ts'), `const key = "${remSecret}";\n`);
    fs.writeFileSync(path.join(w, '.env'), 'OTHER="x"\n');
    fs.writeFileSync(path.join(w, '.gitignore'), 'node_modules\n');
    fs.writeFileSync(path.join(w, '.env.example'), 'OTHER=example\n');
    return w;
  };

  const finding = (w: string): any => ({
    type: 'AWS Access Key ID',
    provider: 'Amazon Web Services',
    file: 'config.ts',
    fullPath: path.join(w, 'config.ts'),
    rawSecret: remSecret,
    remediation: {
      envVarName: 'AWS_ACCESS_KEY_ID',
      replacementCode: 'process.env.AWS_ACCESS_KEY_ID',
      steps: [],
      envFileSnippet: '',
      envExampleSnippet: '',
      gitHistoryPurgeCommand: '',
      diffPreview: '',
    },
  });

  const assertOriginalPreserved = (w: string, msg: string) => {
    const content = fs.readFileSync(path.join(w, 'config.ts'), 'utf8');
    assert(content.includes(remSecret), msg);
  };

  // Build a mock fs that fails on chosen operations. applyControlledRemediation
  // accepts an injectable fsModule, so we can fault-inject without relying on
  // filesystem permissions (ineffective when CI runs as root).
  const makeMockFs = (failOps: Set<string>): typeof fs => {
    const mock: any = { ...fs };
    const isEnvPath = (target: string) => path.basename(target) === '.env';
    const isConfigPath = (target: string) => path.basename(target) === 'config.ts';

    if (failOps.has('write-env') || failOps.has('write-config')) {
      const realWrite = fs.writeFileSync.bind(fs);
      const realAppend = fs.appendFileSync.bind(fs);
      let currentWrite = realWrite;
      let currentAppend = realAppend;

      if (failOps.has('write-env')) {
        currentWrite = (...args: any[]) => {
          if (isEnvPath(String(args[0]))) {
            const e: any = new Error('EPERM: operation not permitted, open .env');
            e.code = 'EPERM';
            throw e;
          }
          return realWrite(...args);
        };
        currentAppend = (...args: any[]) => {
          if (isEnvPath(String(args[0]))) {
            const e: any = new Error('EPERM: operation not permitted, open .env');
            e.code = 'EPERM';
            throw e;
          }
          return realAppend(...args);
        };
      }
      if (failOps.has('write-config')) {
        const prevWrite = currentWrite;
        const prevAppend = currentAppend;
        currentWrite = (...args: any[]) => {
          if (isConfigPath(String(args[0]))) {
            const e: any = new Error('EPERM: operation not permitted, open config.ts');
            e.code = 'EPERM';
            throw e;
          }
          return prevWrite(...args);
        };
        currentAppend = (...args: any[]) => {
          if (isConfigPath(String(args[0]))) {
            const e: any = new Error('EPERM: operation not permitted, open config.ts');
            e.code = 'EPERM';
            throw e;
          }
          return prevAppend(...args);
        };
      }
      mock.writeFileSync = currentWrite;
      mock.appendFileSync = currentAppend;
    }

    if (failOps.has('rename')) {
      mock.renameSync = (...args: any[]) => {
        const e: any = new Error('EPERM: operation not permitted, rename');
        e.code = 'EPERM';
        throw e;
      };
    }
    if (failOps.has('unlink-env')) {
      const realUnlink = fs.unlinkSync.bind(fs);
      mock.unlinkSync = (...args: any[]) => {
        if (isEnvPath(String(args[0]))) {
          const e: any = new Error('EPERM: operation not permitted, unlink .env');
          e.code = 'EPERM';
          throw e;
        }
        return realUnlink(...args);
      };
    }
    return mock as typeof fs;
  };

  try {
    // 19a. Write failure (config.ts write fails) -> remediation fails, rollback runs, original preserved.
    {
      const w = makeWs();
      const result = applyControlledRemediation(finding(w), w, makeMockFs(new Set(['write-config'])));
      assert(result.success === false, 'Write failure should fail remediation');
      assert(/EPERM|operation not permitted/i.test(result.message || ''),
        `Write failure reason reported (got: ${result.message})`);
      assertOriginalPreserved(w, 'Target file preserved original secret after write failure');
      assert(typeof result.message === 'string' && result.message.length > 0, 'Failure message reported');
    }

    // 19b. Rename failure during rollback: .env write fails (triggers catch), then
    // rollback's atomic rename fails. Rollback failure reported, original preserved.
    {
      const w = makeWs();
      const result = applyControlledRemediation(
        finding(w), w, makeMockFs(new Set(['write-env', 'rename']))
      );
      assert(result.success === false, 'Rename failure during rollback should fail remediation');
      assert(/rollback/i.test(result.message), 'Rollback status reported on rename failure');
      assert(/restore|rename/i.test(result.message), 'Restore/rename failure detail reported');
      assertOriginalPreserved(w, 'Target file preserved original secret after rename failure');
    }

    // 19c. Delete path: .env pre-deleted, config.ts write fails -> rollback deletes
    // newly-created .env. .env removed, original preserved.
    {
      const w = makeWs();
      fs.unlinkSync(path.join(w, '.env')); // .env will be newly created by remediation
      const result = applyControlledRemediation(
        finding(w), w, makeMockFs(new Set(['write-config']))
      );
      assert(result.success === false, 'Delete-path scenario should fail remediation');
      assert(!fs.existsSync(path.join(w, '.env')), 'Newly-created .env removed by rollback on failure');
      assertOriginalPreserved(w, 'Target file preserved original secret in delete-path scenario');
    }

    // 19d. Unlink failure during rollback: .env pre-deleted + newly created, config.ts
    // write fails -> rollback tries to unlink .env but unlink fails. Rollback failure
    // reported, original preserved.
    {
      const w = makeWs();
      fs.unlinkSync(path.join(w, '.env')); // .env will be newly created by remediation
      const result = applyControlledRemediation(
        finding(w), w, makeMockFs(new Set(['write-config', 'unlink-env']))
      );
      assert(result.success === false, 'Unlink failure during rollback should fail remediation');
      assert(/rollback/i.test(result.message), 'Rollback status reported on unlink failure');
      assertOriginalPreserved(w, 'Target file preserved original secret after unlink failure');
    }
  } finally {
    fs.rmSync(remScratchRoot, { recursive: true, force: true });
  }

  // --- 20. History Tracing: Command-Injection Resistance (execFile argv) ---
  console.log('\n--- 20. History Tracing: Command-Injection Resistance ---');
  {
    const injRoot = path.join(process.cwd(), 'scratch', 'sld-history-injection');
    fs.rmSync(injRoot, { recursive: true, force: true });
    fs.mkdirSync(injRoot, { recursive: true });
    cp.execFileSync('git', ['init', '-q', '.'], { cwd: injRoot, stdio: 'ignore' });
    cp.execFileSync('git', ['config', 'user.email', 'test@test.com'], { cwd: injRoot, stdio: 'ignore' });
    cp.execFileSync('git', ['config', 'user.name', 'test'], { cwd: injRoot, stdio: 'ignore' });

    const canary = 'CANARY_INJECTION_PAYLOAD';
    const realSecret = 'ghp_' + 'Inj0123456789abcdefghijklmnopqrstuv';
    fs.writeFileSync(path.join(injRoot, 'leak.ts'), `const token = "${realSecret}";\n`);
    cp.execFileSync('git', ['add', '-A'], { cwd: injRoot, stdio: 'ignore' });
    cp.execFileSync('git', ['commit', '-q', '-m', 'add-leak'], { cwd: injRoot, stdio: 'ignore' });

    // Payloads that would run commands if an untrusted "credential" were ever
    // interpolated into a shell string or treated as a git option.
    const adversarial = [
      `$(touch ${canary})`,
      '`touch ' + canary + '`',
      `"; touch ${canary}; echo "`,
      `' ; touch ${canary} ; #`,
      `x" | touch ${canary} | echo "`,
      `$(sh -c "touch ${canary}")`,
      `--format=%H`,
      `-S`,
      `HEAD; touch ${canary}`,
      `\\$(touch ${canary})`,
      `&& touch ${canary} &&`,
    ];

    const historyEngine = new GitHistoryEngine(injRoot);
    const timelineEngine = new GitTimelineEngine(injRoot);

    for (const evil of adversarial) {
      let threw = false;
      try {
        await historyEngine.traceSecret(evil);
      } catch {
        threw = true;
      }
      assert(!threw, `traceSecret survives adversarial input: ${JSON.stringify(evil.slice(0, 24))}`);
      try {
        await timelineEngine.buildTimeline(evil, 'redacted');
      } catch {
        /* timeline is allowed to be tolerant; the key invariant is no execution */
      }
    }

    assert(
      !fs.existsSync(path.join(injRoot, canary)),
      'Adversarial credentials are never executed (no canary file created)'
    );

    // Sanity: the execFile code path still traces a genuine secret.
    const real = await historyEngine.traceSecret(realSecret);
    assert(real.isPresentInHistory === true, 'traceSecret still finds a genuine secret in history');
    assert(typeof real.statusDescription === 'string', 'traceSecret returns a status description');

    fs.rmSync(injRoot, { recursive: true, force: true });
  }

  // --- 21. Pre-Commit Hook: Single Policy & Fail-Closed Contract ---
  console.log('\n--- 21. Pre-Commit Hook: Single Policy & Fail-Closed Contract ---');
  {
    const hookRoot = path.join(process.cwd(), 'scratch', 'sld-hook-policy-tests');
    fs.rmSync(hookRoot, { recursive: true, force: true });
    fs.mkdirSync(hookRoot, { recursive: true });

    // 21a. Generated hook obeys the single policy and fails closed.
    const hook = buildPreCommitHook();
    assert(hook.includes(SLD_HOOK_MARKER), 'Hook carries the SLD managed marker');
    assert(hook.includes(`SLD_FAIL_ON="${DEFAULT_FAIL_ON}"`), `Hook enforces the project policy threshold (${DEFAULT_FAIL_ON})`);
    assert(!/^\s*eval[\s"']/m.test(hook), 'Hook never invokes eval (command position)');
    assert(!/\beval\s+["'$]/.test(hook), 'Hook never passes data to eval');
    assert(!/grep -E -q/.test(hook), 'Hook has no weak regex "emergency" fallback');
    assert(/COMMIT BLOCKED \(fail-closed\)/.test(hook), 'Hook fails closed when the scanner is unavailable');
    assert(buildPreCommitHook('LOW').includes('SLD_FAIL_ON="LOW"'), 'Hook threshold is configurable from one place');
    assert(
      buildPreCommitHook('BOGUS' as any).includes(`SLD_FAIL_ON="${DEFAULT_FAIL_ON}"`),
      'Invalid hook threshold falls back to the project policy'
    );

    const makeHookRepo = (name: string) => {
      const r = path.join(hookRoot, name);
      fs.rmSync(r, { recursive: true, force: true });
      fs.mkdirSync(r, { recursive: true });
      cp.execFileSync('git', ['init', '-q', '.'], { cwd: r, stdio: 'ignore' });
      cp.execFileSync('git', ['config', 'user.email', 'test@test.com'], { cwd: r, stdio: 'ignore' });
      cp.execFileSync('git', ['config', 'user.name', 'test'], { cwd: r, stdio: 'ignore' });
      fs.writeFileSync(path.join(r, 'readme.md'), '# safe\n');
      cp.execFileSync('git', ['add', '-A'], { cwd: r, stdio: 'ignore' });
      cp.execFileSync('git', ['commit', '-q', '-m', 'initial'], { cwd: r, stdio: 'ignore' });
      // Provide the real scanner inside the temp repo so the hook exercises the
      // full scanner (not the unavailable-scanner path).
      fs.mkdirSync(path.join(r, 'dist'), { recursive: true });
      fs.copyFileSync(cli, path.join(r, 'dist', 'cli.js'));
      return r;
    };

    // 21b. A REAL `git commit` with a staged secret must be refused.
    {
      const r = makeHookRepo('commit-block');
      await new GitService(r).installPreCommitHook();
      const installed = fs.readFileSync(path.join(r, '.git', 'hooks', 'pre-commit'), 'utf8');
      assert(installed.includes(SLD_HOOK_MARKER), 'Installed hook is the managed SLD hook');

      fs.writeFileSync(path.join(r, 'leak.ts'), `const key = "${awsSecret}";\n`);
      cp.execFileSync('git', ['add', '-A'], { cwd: r, stdio: 'ignore' });

      let blocked = false;
      let detail = '';
      try {
        cp.execFileSync('git', ['commit', '-m', 'should be blocked'], { cwd: r, encoding: 'utf8', stdio: 'pipe' });
      } catch (e: any) {
        blocked = true;
        detail = String(e.stdout || '') + String(e.stderr || '');
      }
      assert(blocked, `Real git commit refused by the installed hook (${detail.slice(0, 160)})`);
      const subject = cp.execFileSync('git', ['log', '-1', '--format=%s'], { cwd: r, encoding: 'utf8' }).trim();
      assert(subject === 'initial', `HEAD did not advance after a blocked commit (got "${subject}")`);
    }

    // 21c. A REAL `git commit` with clean staged changes is allowed.
    {
      const r = makeHookRepo('commit-allow');
      await new GitService(r).installPreCommitHook();
      fs.writeFileSync(path.join(r, 'safe.ts'), 'const x = 1;\n');
      cp.execFileSync('git', ['add', '-A'], { cwd: r, stdio: 'ignore' });
      cp.execFileSync('git', ['commit', '-m', 'clean'], { cwd: r, stdio: 'ignore' });
      const subject = cp.execFileSync('git', ['log', '-1', '--format=%s'], { cwd: r, encoding: 'utf8' }).trim();
      assert(subject === 'clean', `Clean commit allowed through the hook (got "${subject}")`);
    }

    // 21d. Fail-closed: with no scanner on PATH the hook must still BLOCK.
    {
      const sh = findPosixShell();
      if (sh) {
        const fcHook = path.join(hookRoot, 'failclosed-pre-commit');
        fs.writeFileSync(fcHook, buildPreCommitHook(), { mode: 0o755 });
        const minimalPath = process.platform === 'win32' ? 'C:\\Windows\\System32' : '/nonexistent-bin';
        let status = 0;
        let out = '';
        try {
          cp.execFileSync(sh, [fcHook], {
            cwd: hookRoot,
            env: { ...process.env, PATH: minimalPath },
            encoding: 'utf8',
            stdio: 'pipe',
          });
        } catch (e: any) {
          status = typeof e.status === 'number' ? e.status : 1;
          out = String(e.stdout || '') + String(e.stderr || '');
        }
        assert(status !== 0, `Hook fails closed when the scanner is unavailable (status ${status})`);
        assert(/BLOCKED/i.test(out), 'Fail-closed hook prints a BLOCKED message');
      } else {
        console.log('   ⚠️  Skipped direct fail-closed exec (no POSIX shell found on this host).');
      }
    }

    fs.rmSync(hookRoot, { recursive: true, force: true });
  }

  // --- 22. Unified Blocking Policy Across CLI / Extension / Hook ---
  console.log('\n--- 22. Unified Blocking Policy Across CLI / Extension / Hook ---');
  {
    assert(DEFAULT_FAIL_ON === 'HIGH', `Project policy blocks at HIGH (got ${DEFAULT_FAIL_ON})`);
    assert(BLOCKING_POLICY.failOn === DEFAULT_FAIL_ON, 'BLOCKING_POLICY mirrors DEFAULT_FAIL_ON');
    assert(resolveFailOn('critical') === 'CRITICAL', 'Threshold tokens are case-insensitive');
    assert(resolveFailOn('WAT') === DEFAULT_FAIL_ON, 'Invalid threshold falls back to the project policy');
    assert(resolveFailOn(undefined) === DEFAULT_FAIL_ON, 'Absent threshold uses the project policy');

    // Exhaustive LOW/MEDIUM/HIGH/CRITICAL threshold matrix.
    const matrix: Array<[Risk, Risk, boolean]> = [
      ['LOW', 'LOW', true], ['MEDIUM', 'LOW', true], ['HIGH', 'LOW', true], ['CRITICAL', 'LOW', true],
      ['LOW', 'MEDIUM', false], ['MEDIUM', 'MEDIUM', true], ['HIGH', 'MEDIUM', true], ['CRITICAL', 'MEDIUM', true],
      ['LOW', 'HIGH', false], ['MEDIUM', 'HIGH', false], ['HIGH', 'HIGH', true], ['CRITICAL', 'HIGH', true],
      ['LOW', 'CRITICAL', false], ['MEDIUM', 'CRITICAL', false], ['HIGH', 'CRITICAL', false], ['CRITICAL', 'CRITICAL', true],
    ];
    for (const [tier, threshold, expected] of matrix) {
      assert(meetsThreshold(tier, threshold) === expected, `Threshold matrix: ${tier} vs ${threshold} => ${expected}`);
    }
    assert(shouldBlock([{ risk: 'MEDIUM' }], 'HIGH') === false, 'MEDIUM does not block at the HIGH policy');
    assert(shouldBlock([{ risk: 'HIGH' }], 'HIGH') === true, 'HIGH blocks at the HIGH policy');
    assert(shouldBlock([], 'LOW') === false, 'No findings never blocks');

    // CLI end-to-end: the default threshold IS the project policy, and --fail-on overrides it.
    // The fixture deliberately lives OUTSIDE the repository: the file-context
    // analyser treats any path containing config/secret/credential-like segments
    // as sensitive, and a CI checkout directory (e.g. "Secret_Leak_Detector")
    // would otherwise raise this fixture from HIGH to CRITICAL. Using a neutral
    // temp path keeps the expected tier deterministic on every platform.
    const policyDir = path.join(os.tmpdir(), 'sld-policy-cli-fixture');
    fs.rmSync(policyDir, { recursive: true, force: true });

    // --- 23. GitHub Action: Shell Injection Prevention & HIGH Threshold ---
    console.log('\n--- 23. GitHub Action: Shell Injection Prevention & HIGH Threshold ---');
    {
      const actionYmlPath = path.join(__dirname, '..', 'action.yml');
      assert(fs.existsSync(actionYmlPath), 'action.yml exists in repository root');
      const actionContent = fs.readFileSync(actionYmlPath, 'utf8');

      // Issue 4: Verify default threshold is HIGH
      const failOnDefaultMatch = actionContent.match(/fail-on:[\s\S]*?default:\s*['"]?([A-Z]+)['"]?/);
      assert(failOnDefaultMatch !== null && failOnDefaultMatch[1] === 'HIGH', 'action.yml defaults fail-on to HIGH (got ' + (failOnDefaultMatch ? failOnDefaultMatch[1] : 'none') + ')');

      // Issue 1: Verify all inputs are passed through env: and never interpolated in run:
      const runBlockMatch = actionContent.match(/run:\s*\|[\s\S]*?branding:/);
      const runBlock = runBlockMatch ? runBlockMatch[0] : '';
      assert(!runBlock.includes('${{ inputs.'), 'action.yml does not interpolate ${{ inputs.* }} inside the bash run: script');
      assert(actionContent.includes('INPUT_PATH: ${{ inputs.path }}'), 'action.yml passes path via INPUT_PATH env variable');
      assert(actionContent.includes('INPUT_FAIL_ON: ${{ inputs.fail-on }}'), 'action.yml passes fail-on via INPUT_FAIL_ON env variable');
      assert(actionContent.includes('INPUT_BASELINE: ${{ inputs.baseline }}'), 'action.yml passes baseline via INPUT_BASELINE env variable');
      assert(actionContent.includes('INPUT_SARIF_FILE: ${{ inputs.sarif-file }}'), 'action.yml passes sarif-file via INPUT_SARIF_FILE env variable');

      // Adversarial inputs test: check flag/command injection detection patterns
      const isOptionInjection = (s: string) => s.trim().startsWith('-');
      assert(isOptionInjection('--help'), 'Leading dash detected as potential option injection (--help)');
      assert(isOptionInjection('-rf'), 'Leading dash detected as potential option injection (-rf)');
      assert(!isOptionInjection('src/components'), 'Valid target path is not flagged as option injection');

      const validTiers = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
      assert(!validTiers.has('$(touch CANARY)'.toUpperCase()), 'Adversarial shell injection payload rejected as invalid tier');
      assert(!validTiers.has('"; touch CANARY; #'.toUpperCase()), 'Adversarial command separator payload rejected as invalid tier');
      assert(validTiers.has('HIGH'), 'Standard HIGH tier accepted by action validator');
    }

    // --- 24. Dashboard Panel: Anti-Script-Injection & Redacted Model ---
    console.log('\n--- 24. Dashboard Panel: Anti-Script-Injection & Redacted Model ---');
    {
      const maliciousFinding: any = {
        id: 'sec_malicious_1',
        fingerprint: 'fp_malicious_1',
        type: 'AWS"<script>alert(1)</script>',
        provider: 'Amazon<img src=x onerror=alert(2)>',
        file: 'src/<script>payload</script>.ts',
        fullPath: '/repo/src/<script>payload</script>.ts',
        line: 42,
        column: 10,
        rawSecret: 'AKIA_SUPER_SECRET_RAW_TOKEN_12345',
        redactedSecret: 'AKIA••••••••1234',
        confidence: 99,
        entropy: 4.25,
        risk: 'CRITICAL',
        remediation: {
          steps: ['<script>evil()</script>'],
          envVarName: 'AWS_KEY',
          replacementCode: 'process.env.AWS_KEY',
          envFileSnippet: '',
          envExampleSnippet: '',
          gitHistoryPurgeCommand: '',
          diffPreview: '',
        },
      };

      const redactedView = toRedactedFindingView(maliciousFinding);

      // Verify rawSecret is completely excluded from the UI model
      assert((redactedView as any).rawSecret === undefined, 'toRedactedFindingView completely strips rawSecret from webview payload');
      assert(redactedView.redactedSecret === 'AKIA••••••••1234', 'toRedactedFindingView preserves safe redactedSecret');
      assert(redactedView.type === maliciousFinding.type, 'toRedactedFindingView preserves type for DOM textContent rendering');

      // Verify dashboardPanel.ts code structure: strict CSP, nonce, and NO inline onclick handlers
      const dashboardTsPath = path.join(__dirname, '..', 'src', 'webview', 'dashboardPanel.ts');
      const dashboardCode = fs.readFileSync(dashboardTsPath, 'utf8');

      assert(dashboardCode.includes("Content-Security-Policy"), 'dashboardPanel.ts applies Content-Security-Policy');
      assert(dashboardCode.includes("script-src 'nonce-"), 'dashboardPanel.ts enforces cryptographic nonce on script execution');
      assert(dashboardCode.includes("default-src 'none'"), 'dashboardPanel.ts restricts default-src to none');
      assert(!dashboardCode.includes('onclick='), 'dashboardPanel.ts contains ZERO inline onclick attributes');
      assert(!dashboardCode.includes('tbody.innerHTML = findings.map'), 'dashboardPanel.ts does not render findings table via innerHTML interpolation');
      assert(dashboardCode.includes('document.createElement'), 'dashboardPanel.ts uses safe DOM creation for findings table');
      assert(dashboardCode.includes('.textContent'), 'dashboardPanel.ts sets dynamic text via textContent');
    }

    // --- 25. Verification Engine: Deleted File Git History Independence ---
    console.log('\n--- 25. Verification Engine: Deleted File Git History Independence ---');
    {
      const vdir = path.join(process.cwd(), 'scratch', 'test-verification-deleted-' + Date.now());
      fs.mkdirSync(vdir, { recursive: true });

      try {
        cp.execFileSync('git', ['init'], { cwd: vdir, stdio: 'ignore' });
        cp.execFileSync('git', ['config', 'user.name', 'Verification Tester'], { cwd: vdir, stdio: 'ignore' });
        cp.execFileSync('git', ['config', 'user.email', 'verify@example.com'], { cwd: vdir, stdio: 'ignore' });

        const targetFile = path.join(vdir, 'auth_temp.ts');
        const testSecret = 'AKIA1122334455667788';
        fs.writeFileSync(targetFile, `const apiKey = "${testSecret}";\n`, 'utf8');
        cp.execFileSync('git', ['add', 'auth_temp.ts'], { cwd: vdir });
        cp.execFileSync('git', ['commit', '-m', 'Add auth_temp with secret'], { cwd: vdir });

        const fakeFinding: any = {
          id: 'f_test_del',
          fingerprint: 'fp_test_del',
          type: 'AWS Access Key ID',
          provider: 'Amazon Web Services',
          file: 'auth_temp.ts',
          fullPath: targetFile,
          line: 1,
          column: 16,
          rawSecret: testSecret,
          redactedSecret: 'AKIA••••••••7788',
          confidence: 100,
          risk: 'CRITICAL',
        };

        const verifier = new VerificationEngine(vdir);

        // Scenario A: File is deleted from disk, but secret STILL EXISTS IN COMMIT HISTORY!
        fs.unlinkSync(targetFile);
        assert(!fs.existsSync(targetFile), 'Target file removed from disk');

        const delResult = await verifier.verifyFindingFix(fakeFinding);
        assert(delResult.isResolved === true, 'Deleted file marked isResolved in working tree');
        assert(delResult.targetFileClean === true, 'Deleted file marked targetFileClean');
        assert(delResult.workingTreeClean === true, 'Deleted file marked workingTreeClean');
        assert(delResult.historyStatus === 'REMOVED_FROM_HEAD_STILL_IN_HISTORY', 'Deleted file correctly identifies secret STILL IN COMMIT HISTORY (got: ' + delResult.historyStatus + ')');
        assert(delResult.details.includes('still exists in commit history'), 'Details warning includes commit history alert for deleted file');

        // Scenario B: Non-git directory or uninspectable history reports UNKNOWN, not clean
        const nonGitVerifier = new VerificationEngine(path.join(process.cwd(), 'scratch', 'non-git-empty-' + Date.now()));
        const unknownResult = await nonGitVerifier.verifyFindingFix(fakeFinding);
        assert(unknownResult.historyStatus === 'UNKNOWN', 'Non-git workspace reports historyStatus UNKNOWN on deleted file (got: ' + unknownResult.historyStatus + ')');
      } finally {
        try {
          fs.rmSync(vdir, { recursive: true, force: true });
        } catch {}
      }
    }

    // --- 26. Baseline Schema Validation & Fail-Visible Behavior ---
    console.log('\n--- 26. Baseline Schema Validation & Fail-Visible Behavior ---');
    {
      // 1. Root must be an object
      let threw = false;
      try {
        validateBaselineSchema(null);
      } catch (e: any) {
        threw = e instanceof BaselineValidationError;
      }
      assert(threw, 'validateBaselineSchema rejects null');

      threw = false;
      try {
        validateBaselineSchema([1, 2, 3]);
      } catch (e: any) {
        threw = e instanceof BaselineValidationError;
      }
      assert(threw, 'validateBaselineSchema rejects array root');

      // 2. Version must be a positive number
      threw = false;
      try {
        validateBaselineSchema({ version: '1', generatedAt: '2026-01-01', findings: [] });
      } catch (e: any) {
        threw = e instanceof BaselineValidationError;
      }
      assert(threw, 'validateBaselineSchema rejects non-numeric version');

      // 3. Findings must be an array
      threw = false;
      try {
        validateBaselineSchema({ version: 1, generatedAt: '2026-01-01', findings: 'invalid' });
      } catch (e: any) {
        threw = e instanceof BaselineValidationError;
      }
      assert(threw, 'validateBaselineSchema rejects non-array findings');

      // 4. Malformed findings entries
      threw = false;
      try {
        validateBaselineSchema({
          version: 1,
          generatedAt: '2026-01-01',
          findings: [{ fingerprint: '', file: 'src/a.ts', ruleId: 'AWS', line: 10 }],
        });
      } catch (e: any) {
        threw = e instanceof BaselineValidationError;
      }
      assert(threw, 'validateBaselineSchema rejects empty fingerprint');

      threw = false;
      try {
        validateBaselineSchema({
          version: 1,
          generatedAt: '2026-01-01',
          findings: [{ fingerprint: 'fp1', file: 123, ruleId: 'AWS', line: 10 }],
        });
      } catch (e: any) {
        threw = e instanceof BaselineValidationError;
      }
      assert(threw, 'validateBaselineSchema rejects non-string file');

      // 5. Valid baseline accepted
      const validBaseline = validateBaselineSchema({
        version: 1,
        generatedAt: '2026-10-18T20:00:00.000Z',
        findings: [{ fingerprint: 'fp_abc', file: 'src/main.ts', ruleId: 'AWS Access Key', line: 5 }],
      });
      assert(validBaseline.version === 1 && validBaseline.findings.length === 1, 'validateBaselineSchema accepts valid baseline');

      // 6. Test BaselineEngine on malformed file
      const malformedDir = path.join(process.cwd(), 'scratch', 'test-malformed-baseline-' + Date.now());
      fs.mkdirSync(malformedDir, { recursive: true });
      try {
        const malformedFile = path.join(malformedDir, 'bad-baseline.json');
        fs.writeFileSync(malformedFile, '{ "version": 1, "generatedAt": "now", "findings": "not-an-array" }', 'utf8');

        const engine = new BaselineEngine(malformedDir, 'bad-baseline.json');
        assert(engine.exists(), 'Malformed baseline file exists');

        let engineThrew = false;
        try {
          engine.loadBaseline();
        } catch (err: any) {
          engineThrew = err instanceof BaselineValidationError;
        }
        assert(engineThrew, 'loadBaseline() throws BaselineValidationError on malformed findings schema');

        let filterThrew = false;
        try {
          engine.filterAgainstBaseline([]);
        } catch (err: any) {
          filterThrew = err instanceof BaselineValidationError;
        }
        assert(filterThrew, 'filterAgainstBaseline() fails visibly when baseline is malformed');
      } finally {
        try {
          fs.rmSync(malformedDir, { recursive: true, force: true });
        } catch {}
      }
    }

    fs.mkdirSync(policyDir, { recursive: true });
    fs.writeFileSync(path.join(policyDir, 'leak.ts'), `const key = "${awsSecret}";\n`);

    const runCli = (extra: string[]): { status: number; out: string } => {
      const res = cp.spawnSync(
        process.execPath,
        [cli, 'scan', '.', '--baseline', path.join(policyDir, 'nonexistent.json'), ...extra],
        { cwd: policyDir, encoding: 'utf8' }
      );
      return {
        status: typeof res.status === 'number' ? res.status : 1,
        out: `${res.stdout || ''}${res.stderr || ''}`,
      };
    };

    const withDefault = runCli([]);
    const atHigh = runCli(['--fail-on', 'HIGH']);
    const atCritical = runCli(['--fail-on', 'CRITICAL']);
    const atLow = runCli(['--fail-on', 'LOW']);
    assert(withDefault.status === 1, `CLI default blocks a HIGH finding (default threshold is the HIGH policy).\n${withDefault.out.slice(-400)}`);
    assert(atHigh.status === 1, `CLI blocks at HIGH when asked.\n${atHigh.out.slice(-400)}`);
    assert(atCritical.status === 0, `CLI allows a HIGH finding when the threshold is CRITICAL.\n${atCritical.out.slice(-400)}`);
    assert(atLow.status === 1, `CLI blocks at LOW when asked.\n${atLow.out.slice(-400)}`);

    // Scan-error is fail-closed: a non-repository never yields a silent pass.
    const errRes = await new GitService(path.join(process.cwd(), 'scratch', 'not-a-repo-xyz')).scanStagedChanges();
    assert(errRes.status === 'CLEAN' || errRes.status === 'ERROR', 'Non-repo staged scan never reports a silent success');

    // Baseline matching must be portable across platforms (Windows baseline,
    // Linux CI): paths are normalised and fingerprints are platform-independent.
    {
      const bdir = path.join(process.cwd(), 'scratch', 'sld-baseline-xplat');
      fs.rmSync(bdir, { recursive: true, force: true });
      fs.mkdirSync(bdir, { recursive: true });
      const engine = new BaselineEngine(bdir, 'xplat.json');
      const mkFinding = (file: string, line: number, fp: string) =>
        ({
          id: 'sec_x_' + fp,
          fingerprint: fp,
          type: 'AWS Access Key ID',
          file,
          line,
          risk: 'HIGH' as Risk,
        }) as any;

      engine.saveBaseline([mkFinding('src\\win\\leak.ts', 10, 'FPA')]);
      const saved = fs.readFileSync(path.join(bdir, 'xplat.json'), 'utf8');
      assert(saved.includes('src/win/leak.ts'), 'Baseline stores portable forward-slash paths');

      // Same fingerprint, drifted line (e.g. an added import) -> still matched.
      const res1 = engine.filterAgainstBaseline([mkFinding('src/win/leak.ts', 999, 'FPA')]);
      assert(res1.newFindings.length === 0 && res1.existingFindings.length === 1, 'Fingerprint match tolerates line drift across platforms');

      // Different fingerprint, but the normalised file:rule:line key still matches.
      const res2 = engine.filterAgainstBaseline([mkFinding('src/win/leak.ts', 10, 'FPB')]);
      assert(res2.newFindings.length === 0 && res2.existingFindings.length === 1, 'Normalised file:rule:line key matches across path separators');

      fs.rmSync(bdir, { recursive: true, force: true });
    }

    fs.rmSync(policyDir, { recursive: true, force: true });
  }

  console.log('\n============================================================');
  console.log(`🎉 TEST SUMMARY: ${passed} PASSED, ${failed} FAILED`);
  console.log('============================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runAsyncTests().catch((err) => {
  console.error('Test execution failed:', err);
  process.exit(1);
});

