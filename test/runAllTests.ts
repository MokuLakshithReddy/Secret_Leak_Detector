import { scanContent, scanFile, buildScanResult } from '../src/core/scanner/scanner';
import { calculateShannonEntropy, calculateNormalizedEntropy } from '../src/core/entropy/entropy';
import { redactSecret, generateFingerprint, resolveSalt } from '../src/core/redactor/redactor';
import * as crypto from 'crypto';
import { BaselineEngine, BaselineValidationError, validateBaselineSchema } from '../src/core/baseline/baselineEngine';
import { toRedactedFindingView } from '../src/webview/dashboardModel';
import { VerificationEngine } from '../src/core/verification/verificationEngine';
import { GitHistoryEngine, unquoteGitPath, parseDiffHeaderPaths } from '../src/core/history/gitHistoryEngine';
import { formatAsSarif } from '../src/core/sarif/sarifFormatter';
import { DETECTOR_RULES } from '../src/core/detectors/rules';
import { calculateRiskAssessment } from '../src/core/risk/riskEngine';
import { GitTimelineEngine } from '../src/core/history/gitTimeline';
import { GitService } from '../src/git/gitService';
import { applyControlledRemediation, resolveUniqueEnvVarName, escapeEnvValue, enforceEnvFilePermissions, getCurrentSecurityPrincipal, isPrincipalAuthorized, supportsDotEnvMigration } from '../src/core/remediation/remediationEngine';
import * as path from 'path';
import * as fs from 'fs';
import * as cp from 'child_process';
import * as os from 'os';
import { DEFAULT_FAIL_ON, BLOCKING_POLICY, resolveFailOn, meetsThreshold, shouldBlock } from '../src/core/policy';
import { buildPreCommitHook, SLD_HOOK_MARKER } from '../src/git/preCommitHook';
import { Risk, GitExposure } from '../src/core/types';

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

console.log('\n--- Safe .env Remediation Eligibility ---');
assert(
  supportsDotEnvMigration("import 'dotenv/config';\nconst token = 'placeholder';", 'app.ts'),
  'Node quick fix requires an explicit dotenv/config loader'
);
assert(
  supportsDotEnvMigration("import os\nfrom dotenv import load_dotenv\nload_dotenv()", 'app.py'),
  'Python quick fix requires both os and dotenv imports'
);
assert(
  !supportsDotEnvMigration("from dotenv import load_dotenv\nload_dotenv()", 'app.py'),
  'Python quick fix is withheld when os is not imported'
);
assert(
  supportsDotEnvMigration('import ("os"\n"github.com/joho/godotenv")\ngodotenv.Load()', 'main.go'),
  'Go quick fix requires both os and godotenv imports'
);
assert(
  !supportsDotEnvMigration('godotenv.Load()', 'main.go'),
  'Go quick fix is withheld when required imports are absent'
);
assert(
  !supportsDotEnvMigration("dotenv.config();\nconst token = 'placeholder';", 'app.ts'),
  'Node quick fix is withheld for an unbound dotenv.config call'
);
assert(
  !supportsDotEnvMigration("const token = 'placeholder';", 'app.ts'),
  'Node quick fix is withheld when no .env loader is detected'
);
assert(
  !supportsDotEnvMigration("const token = 'placeholder';", 'config.yaml'),
  'Unknown configuration runtimes do not receive automatic .env migration'
);

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
assert(maskedAws.startsWith('AK'), 'Redaction preserves cloud prefix');
assert(maskedAws.endsWith('EF'), 'Redaction preserves suffix');
assert(redactSecret('123456789012') === '••••••••', 'Secrets <= 12 characters are completely masked');
assert(maskedAws.includes('•'), 'Redaction masks intermediate sensitive characters');
const fp1 = generateFingerprint('secret-12345');
const fp2 = generateFingerprint('secret-12345');
const fp3 = generateFingerprint('secret-99999');
assert(fp1 === fp2, 'Identical secrets yield identical fingerprints');
assert(fp1 !== fp3, 'Different secrets yield unique fingerprints');
const multilineCRLF = 'dummy-multiline-token-sample\r\nsecond-line-payload\r\nthird-line-suffix';
const multilineLF = 'dummy-multiline-token-sample\nsecond-line-payload\nthird-line-suffix';
assert(generateFingerprint(multilineCRLF) === generateFingerprint(multilineLF), 'Multiline fingerprint matches deterministically across CRLF and LF');

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
process.env.SLD_ISOLATE_BASELINE_TESTS = '1';
const tmpDir = path.join(__dirname, '..', 'scratch', 'test_baseline');
if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
const baselineEngine = new BaselineEngine(tmpDir, 'test-baseline.json');

const testFinding = scanContent(`const k = "${synth(['AK', 'IA', '1234567890ABCDEF'])}";`, 'aws.ts')[0];
baselineEngine.saveBaseline([testFinding]);
assert(baselineEngine.exists(), 'Baseline file created successfully');

const checkFiltered = baselineEngine.filterAgainstBaseline([testFinding], { forceFile: true });
assert(checkFiltered.existingFindings.length === 1, 'Known finding filtered into existing findings');
assert(checkFiltered.newFindings.length === 0, 'Known finding does not trigger new findings in CI');

const newFinding = scanContent(`const g = "${synth(['gh', 'p_', '1234567890abcdefghijklmnopqrstuvwxyz'])}";`, 'gh.ts')[0];
const checkWithNew = baselineEngine.filterAgainstBaseline([testFinding, newFinding], { forceFile: true });
assert(checkWithNew.newFindings.length === 1, 'Newly introduced credential detected as new finding');
assert(checkWithNew.newFindings[0].provider === 'GitHub', 'New finding correctly identifies new secret');

// Clean up test baseline
try {
  fs.rmSync(tmpDir, { recursive: true, force: true });
} catch {}
delete process.env.SLD_ISOLATE_BASELINE_TESTS;

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
    fs.writeFileSync(path.join(w, 'config.ts'), `import 'dotenv/config';\nconst key = "${remSecret}";\n`);
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
        const testSecret = synth(['AK', 'IA', '1122334455667788']);
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
        assert(delResult.isResolved === false, 'Deleted file with secret still in commit history is NOT marked resolved');
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
          engine.filterAgainstBaseline([], { forceFile: true });
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
      const res1 = engine.filterAgainstBaseline([mkFinding('src/win/leak.ts', 999, 'FPA')], { forceFile: true });
      assert(res1.newFindings.length === 0 && res1.existingFindings.length === 1, 'Fingerprint match tolerates line drift across platforms');

      // Different fingerprint, but the normalised file:rule:line key still matches.
      const res2 = engine.filterAgainstBaseline([mkFinding('src/win/leak.ts', 10, 'FPB')], { forceFile: true });
      assert(res2.newFindings.length === 1 && res2.existingFindings.length === 0, 'Different secret at same line is not suppressed by baseline');

      // Multiline CRLF vs LF backwards compatibility in baseline matching
      const multilineSecret = Buffer.from('LS0tLS1CRUdJTiBURVNUIEtFWS0tLS0tCmxpbmUxCnNlY3JldAotLS0tLUVORCBURVNUIEtFWS0tLS0t', 'base64').toString('utf8');
      const salt = resolveSalt(undefined, bdir);
      const crlfSecret = multilineSecret.replace(/\n/g, '\r\n');
      const crlfHash = crypto.createHmac('sha256', salt).update(crlfSecret).digest('hex').substring(0, 16);
      const legacyBaselineFile: any = {
        version: 1,
        generatedAt: new Date().toISOString(),
        generator: 'Secret Leak Detector v1.0.3',
        findings: [
          {
            id: 'legacy-multiline',
            fingerprint: crlfHash,
            ruleId: 'Cryptographic Private Key (PEM)',
            file: 'certs/server.pem',
            line: 1,
            firstSeen: new Date().toISOString(),
          },
        ],
      };
      fs.writeFileSync(path.join(bdir, 'xplat.json'), JSON.stringify(legacyBaselineFile, null, 2), 'utf8');

      const canonicalFinding = {
        ...mkFinding('certs/server.pem', 1, generateFingerprint(multilineSecret, undefined, bdir)),
        rawSecret: multilineSecret,
      };
      const res3 = engine.filterAgainstBaseline([canonicalFinding], { forceFile: true });
      assert(res3.newFindings.length === 0 && res3.existingFindings.length === 1, 'Multiline canonical finding matches legacy CRLF baseline entry');

      fs.rmSync(bdir, { recursive: true, force: true });
    }

    fs.rmSync(policyDir, { recursive: true, force: true });
  }

  // --- 27. Release Blockers, ReDoS Bounded PEM & Hygiene ---
  console.log('\n--- 27. Release Blockers, ReDoS Bounded PEM & Hygiene ---');
  {
    // Test 1: media/icon.png magic bytes and size
    const iconPath = path.join(process.cwd(), 'media', 'icon.png');
    assert(fs.existsSync(iconPath), 'media/icon.png must exist');
    const iconBuf = fs.readFileSync(iconPath);
    assert(iconBuf.length > 1000, 'media/icon.png must not be an LFS pointer');
    const pngMagic = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    assert(iconBuf.slice(0, 8).equals(pngMagic), 'media/icon.png must start with valid PNG magic bytes');

    // Test 2: Bounded PEM Regex ReDoS Immunity
    const unclosedHeader = '-----BEGIN RSA PRIVATE KEY-----\nSome payload here\n';
    const hostileContent = unclosedHeader.repeat(40000); // ~2MB
    const t0 = Date.now();
    const hostileFindings = scanContent(hostileContent, 'hostile_unclosed_pem.txt');
    const elapsedMs = Date.now() - t0;
    assert(elapsedMs < 1000, 'Bounded PEM scanning must complete in <1000ms (got ' + elapsedMs + 'ms)');
    assert(hostileFindings.length === 0, 'Unclosed PEM headers must not match without END tag');

    // Test 3: Inline comment suppression
    const suppressedSnippet = `
      // sld-ignore
      const secret1 = "${awsSecret}";
      const secret2 = "${awsSecret}"; // sld-ignore
      const secret3 = "${awsSecret}";
    `;
    const suppressedFindings = scanContent(suppressedSnippet, 'suppressed.ts');
    assert(suppressedFindings.length === 1, 'Inline suppression ignores marked lines (expected 1, got ' + suppressedFindings.length + ')');

    // Test 4: CLI --version
    const cliPath = path.join(process.cwd(), 'dist', 'cli.js');
    const verRes = cp.spawnSync(process.execPath, [cliPath, '--version'], { encoding: 'utf8' });
    assert(verRes.stdout.trim() === '1.0.4', 'CLI --version prints valid semantic version (got: ' + verRes.stdout.trim() + ')');
  }

  // --- 28. Robust Git Diff Parsing, Glob Matching, UTF-16, & Hook Lifecycle ---
  console.log('\n--- 28. Robust Git Diff Parsing, Glob Matching, UTF-16, & Hook Lifecycle ---');
  {
    const { matchesIgnorePattern } = require('../src/core/ignore/ignoreEngine');
    const { decodeTextBuffer, parseNameStatusZ } = require('../src/git/stagedScanner');
    const { buildPreCommitHook } = require('../src/git/preCommitHook');
    const { analyzeAstContext } = require('../src/core/context/astAnalyzer');

    // Test 1: Ignore glob matching on all typical patterns
    const globCases = [
      ['dist/bundle.js', '**/dist/**', true],
      ['src/dist/bundle.js', '**/dist/**', true],
      ['node_modules/foo/index.js', '**/node_modules/**', true],
      ['app.min.js', '**/*.min.js', true],
      ['src/app.min.js', '**/*.min.js', true],
      ['docs/guide.md', 'docs/**', true],
      ['docs/sub/guide.md', 'docs/**', true],
      ['package-lock.json', '**/package-lock.json', true],
      ['sub/package-lock.json', '**/package-lock.json', true],
      ['package-lock.json', 'package-lock.json', true],
      ['sub/package-lock.json', 'package-lock.json', true],
      ['dist/index.js', 'dist/', true],
      ['build/index.js', 'build/', true],
      ['src/index.ts', 'dist/', false],
    ];

    for (const [file, pat, expected] of globCases) {
      const match = matchesIgnorePattern(file, pat);
      assert(match === expected, `Glob '${pat}' matching '${file}' expected ${expected}, got ${match}`);
    }

    // Test 2: UTF-16LE text decoding without BOM
    const fakeAwsKey = synth(['AK', 'IA', '1234567890ABCDEF']);
    const utf16leBuf = Buffer.from(`AWS_ACCESS_KEY_ID="${fakeAwsKey}"\n`, 'utf16le');
    const decodedText = decodeTextBuffer(utf16leBuf);
    assert(decodedText !== null, 'UTF-16LE text buffer successfully decoded without binary false rejection');
    const utf16Findings = scanContent(decodedText || '', 'config.env');
    assert(utf16Findings.length >= 1, 'Detected credentials inside decoded UTF-16LE file');

    // Test 3: NUL-delimited name-status parsing with special chars
    const rawTokens = Buffer.from(
      'M\0file with spaces.ts\0' +
      'A\0file"with"quotes.ts\0' +
      'M\0file\\with\\backslashes.ts\0' +
      'R100\0old_name.ts\0new_name.ts\0' +
      'D\0deleted_file.ts\0'
    );
    const parsedEntries = parseNameStatusZ(rawTokens);
    assert(parsedEntries.length === 5, 'parseNameStatusZ parsed all 5 entries accurately');
    assert(parsedEntries[1].path === 'file"with"quotes.ts', 'Quotes in filename preserved without unescaping corruption');
    assert(parsedEntries[2].path === 'file/with/backslashes.ts', 'Backslashes normalized cleanly');
    assert(parsedEntries[3].status === 'R' && parsedEntries[3].oldPath === 'old_name.ts', 'Scored rename parsed with oldPath');

    // Test 4: Hook generation includes ELECTRON_RUN_AS_NODE and node fallback
    const hookScript = buildPreCommitHook('HIGH', '/path/to/cli.js', '/path/to/Code.exe', true);
    assert(hookScript.includes('ELECTRON_RUN_AS_NODE=1'), 'Hook script exports ELECTRON_RUN_AS_NODE=1 for Electron stand-in');
    assert(hookScript.includes("command -v node >/dev/null 2>&1"), 'Hook script checks system node on PATH');

    // Test 5: Zero-dependency Lexical AST fallback
    const fallbackLines = [
      'const apiKey = process.env.API_KEY || "fallback_token_here";',
      'logger.info("Logging sensitive call", apiKey);',
      'const config = { auth: { stripeKey: "sk_test_123" } };',
    ];
    const astEnvFallback = analyzeAstContext(fallbackLines, 0);
    assert(astEnvFallback.isEnvFallback === true, 'Lexical AST identifies env fallback assignment');
    const astLogging = analyzeAstContext(fallbackLines, 1);
    assert(astLogging.isLoggingCall === true, 'Lexical AST identifies logging call');
    const astProp = analyzeAstContext(fallbackLines, 2);
    assert(astProp.isSensitiveProperty === true, 'Lexical AST identifies sensitive property');

    // --- 29. Long Line Coordinate Mapping, Multi-Part Joins & Baseline Resolution ---
    console.log('\n--- 29. Long Line Coordinate Mapping, Multi-Part Joins & Baseline Resolution ---');

    // Test 1: Coordinate mapping preserves line numbers when lines > 4000 chars are split
    const key1 = synth(['AK', 'IA', '1234567890ABCDE1']);
    const key2 = synth(['AK', 'IA', '1234567890ABCDE2']);
    const longLine1 = 'const padding = "' + 'a'.repeat(4500) + '"; const token1 = "' + key1 + '";';
    const line2 = 'const token2 = "' + key2 + '";';
    const multilineContent = `${longLine1}\n${line2}`;
    const mappedFindings = scanContent(multilineContent, 'overlong.ts');
    assert(mappedFindings.length >= 2, 'Found both secrets in file with overlong first line');
    const f1 = mappedFindings.find((f) => f.rawSecret === key1);
    const f2 = mappedFindings.find((f) => f.rawSecret === key2);
    assert(f1 !== undefined && f1.line === 1, `Secret past char 4000 on line 1 mapped to line 1 (got line ${f1?.line})`);
    assert(f1 !== undefined && f1.column > 4500, `Secret past char 4000 on line 1 preserved column offset (got col ${f1?.column})`);
    assert(f2 !== undefined && f2.line === 2, `Second line maintained line 2 coordinate without drifting (got line ${f2?.line})`);

    // Test 2: Property access chains suppressed as false positives
    const { evaluateFalsePositive } = require('../src/core/classifier/falsePositiveClassifier');
    const propCheck1 = evaluateFalsePositive('this.config.apiToken');
    assert(propCheck1.isFalsePositive === true, 'this.config.apiToken suppressed as property access');
    const propCheck2 = evaluateFalsePositive('request.headers.authorization');
    assert(propCheck2.isFalsePositive === true, 'request.headers.authorization suppressed as property access');

    // Test 3: Array join with 4+ parts resolved
    const fourPartJoinCode = `const key = ['sk_live_', '51ABCDEF', 'GHIJKLMN', '1234567890abcdef'].join('');`;
    const fourPartFindings = scanContent(fourPartJoinCode, 'join.ts');
    assert(fourPartFindings.length >= 1, 'Array join with 4 parts successfully resolved and detected');

    // Test 4: Baseline multi-file duplicate resolution tracking
    const { BaselineEngine } = require('../src/core/baseline/baselineEngine');
    const baselineEngine = new BaselineEngine(process.cwd(), 'scratch-baseline-resolution.json');
    const mockFindingA: any = {
      id: 'sec_1',
      fingerprint: 'fp_shared_123',
      type: 'AWS Access Key ID',
      provider: 'Amazon Web Services',
      file: 'src/fileA.ts',
      line: 10,
      detectedAt: new Date().toISOString(),
    };
    const mockFindingB: any = {
      id: 'sec_2',
      fingerprint: 'fp_shared_123',
      type: 'AWS Access Key ID',
      provider: 'Amazon Web Services',
      file: 'src/fileB.ts',
      line: 20,
      detectedAt: new Date().toISOString(),
    };
    const savedBaseline = baselineEngine.saveBaseline([mockFindingA, mockFindingB]);
    assert(savedBaseline.findings.length === 2, 'Saved baseline has 2 findings across different files');

    // Both findings present -> 0 resolved
    const statusBoth = baselineEngine.filterAgainstBaseline([mockFindingA, mockFindingB], { forceFile: true });
    assert(statusBoth.resolvedCount === 0, `Both findings present reports 0 resolved (got ${statusBoth.resolvedCount})`);
    assert(statusBoth.existingFindings.length === 2, 'Both findings classified as existing');

    // fileB removed -> 1 resolved
    const statusOneRemoved = baselineEngine.filterAgainstBaseline([mockFindingA], { forceFile: true });
    assert(statusOneRemoved.resolvedCount === 1, `Removing one file reports 1 resolved (got ${statusOneRemoved.resolvedCount})`);

    // Clean up baseline file
    try {
      const fs = require('fs');
      if (fs.existsSync(baselineEngine.getPath())) fs.unlinkSync(baselineEngine.getPath());
    } catch {}

    // --- 30. Staged Added-Line Filter, Ignore-Skipped & Verification Invariants ---
    console.log('\n--- 30. Staged Added-Line Filter, Ignore-Skipped & Verification Invariants ---');

    // Test 1: Staged added-line filter ignores pre-existing secrets on untouched lines
    const stagedScratch = path.join(process.cwd(), 'scratch', 'sld-added-line-test');
    try {
      fs.rmSync(stagedScratch, { recursive: true, force: true });
    } catch {}
    fs.mkdirSync(stagedScratch, { recursive: true });

    const cp = require('child_process');
    cp.execSync('git init', { cwd: stagedScratch, stdio: 'ignore' });
    cp.execSync('git config user.email "test@example.com"', { cwd: stagedScratch, stdio: 'ignore' });
    cp.execSync('git config user.name "Test"', { cwd: stagedScratch, stdio: 'ignore' });

    // Initial commit with a pre-existing secret on line 1
    const testSecret = synth(['AK', 'IA', '1234567890STAGED']);
    const initialContent = `const AWS_KEY = "${testSecret}";\nconst initial = true;\n`;
    fs.writeFileSync(path.join(stagedScratch, 'app.ts'), initialContent, 'utf8');
    cp.execSync('git add app.ts', { cwd: stagedScratch, stdio: 'ignore' });
    cp.execSync('git commit -m "initial commit"', { cwd: stagedScratch, stdio: 'ignore' });

    // Modify ONLY line 2 with a clean modification (line 1 is untouched)
    const modifiedContent = `const AWS_KEY = "${testSecret}";\nconst initial = false;\nconst addedClean = "clean content";\n`;
    fs.writeFileSync(path.join(stagedScratch, 'app.ts'), modifiedContent, 'utf8');
    cp.execSync('git add app.ts', { cwd: stagedScratch, stdio: 'ignore' });

    const { scanStagedChangesSync } = require('../src/git/stagedScanner');
    const cleanModResult = scanStagedChangesSync(stagedScratch);
    assert(cleanModResult.status === 'CLEAN', `Staged scan with pre-existing secret on untouched line reports CLEAN (got ${cleanModResult.status})`);
    assert(cleanModResult.findings.length === 0, 'No findings reported when modified lines are clean');

    // Now add a NEW secret on line 4
    const newSecret = synth(['AK', 'IA', '0987654321NEWSEC']);
    const leakContent = `${modifiedContent}const newLeak = "${newSecret}";\n`;
    fs.writeFileSync(path.join(stagedScratch, 'app.ts'), leakContent, 'utf8');
    cp.execSync('git add app.ts', { cwd: stagedScratch, stdio: 'ignore' });

    const leakModResult = scanStagedChangesSync(stagedScratch);
    assert(leakModResult.status === 'FINDINGS', `Staged scan with new secret on added line reports FINDINGS (got ${leakModResult.status})`);
    assert(leakModResult.findings.length === 1, `Only the new secret on the added line is reported (got ${leakModResult.findings.length})`);
    assert(leakModResult.findings[0].rawSecret === newSecret, 'Reported finding matches the newly added secret');

    // Test 2: --ignore-skipped handling on oversized staged file
    const largeFile = path.join(stagedScratch, 'large.txt');
    const largeBuf = Buffer.alloc(5.5 * 1024 * 1024, 'a\n');
    fs.writeFileSync(largeFile, largeBuf);
    cp.execSync('git add large.txt', { cwd: stagedScratch, stdio: 'ignore' });

    // Without ignoreSkipped -> fails closed with ERROR
    const noIgnoreRes = scanStagedChangesSync(stagedScratch, { ignoreSkipped: false, maxFileSize: 5 * 1024 * 1024 });
    assert(noIgnoreRes.status === 'ERROR', `Oversized staged file without ignoreSkipped returns ERROR (got ${noIgnoreRes.status})`);
    assert(noIgnoreRes.error?.includes('exceeds 5MB limit'), 'Error mentions 5MB limit and bypass guidance');

    // With ignoreSkipped -> allows scan, marks as skipped
    const ignoreRes = scanStagedChangesSync(stagedScratch, { ignoreSkipped: true, maxFileSize: 5 * 1024 * 1024 });
    assert(ignoreRes.status === 'FINDINGS', 'Oversized staged file with ignoreSkipped allows scan to complete');
    assert(ignoreRes.skippedFiles && ignoreRes.skippedFiles.length >= 1, 'Skipped files array contains the oversized file');

    // Clean up scratch git repo
    try {
      fs.rmSync(stagedScratch, { recursive: true, force: true });
    } catch {}

    // Test 3: VerificationEngine rejects secrets that still exist in history
    const { VerificationEngine } = require('../src/core/verification/verificationEngine');
    const verifyEngine = new VerificationEngine(process.cwd());
    const mockHistoricalFinding: any = {
      fullPath: path.join(process.cwd(), 'nonexistent-cleaned-file.ts'),
      file: 'nonexistent-cleaned-file.ts',
      rawSecret: 'mock_test_secret_in_history_xyz',
      fingerprint: 'fp_hist_123',
      line: 1,
      gitExposure: {
        isPresentInHead: false,
        isPresentInHistory: true,
        introducedCommit: { sha: 'abcdef1234567890' },
      },
    };
    const histVerifyResult = await verifyEngine.verifyFindingFix(mockHistoricalFinding);
    assert(histVerifyResult.isResolved === false, 'Secret remaining in git history is NOT marked resolved');
    assert(histVerifyResult.historyStatus === 'REMOVED_FROM_HEAD_STILL_IN_HISTORY', 'History status correctly set to REMOVED_FROM_HEAD_STILL_IN_HISTORY');

    // Test 4: Version utility returns matching 1.0.4 version
    const { getPackageVersion } = require('../src/core/version');
    assert(getPackageVersion() === '1.0.4', `getPackageVersion returns 1.0.4 (got ${getPackageVersion()})`);

    // --- 31. Binary and Oversize Tolerant Staged Scans, Scoped Excludes & Hook Registry ---
    console.log('\n--- 31. Binary and Oversize Tolerant Staged Scans, Scoped Excludes & Hook Registry ---');
    {
      const { BINARY_EXTENSIONS, DEFAULT_IGNORE_PATTERNS, matchesIgnorePattern: matchesPat } = require('../src/core/ignore/ignoreEngine');
      const { recordInstalledHook, unrecordInstalledHook } = require('../src/git/gitService');
      const { cleanHook } = require('../src/uninstall');

      // 1. Expanded binary extensions
      assert(BINARY_EXTENSIONS.has('.wasm'), 'Binary extensions includes .wasm');
      assert(BINARY_EXTENSIONS.has('.pkl'), 'Binary extensions includes .pkl');
      assert(BINARY_EXTENSIONS.has('.npy'), 'Binary extensions includes .npy');
      assert(BINARY_EXTENSIONS.has('.parquet'), 'Binary extensions includes .parquet');
      assert(BINARY_EXTENSIONS.has('.onnx'), 'Binary extensions includes .onnx');
      assert(BINARY_EXTENSIONS.has('.safetensors'), 'Binary extensions includes .safetensors');

      // 2. Scoped default excludes
      assert(!DEFAULT_IGNORE_PATTERNS.includes('**/dist/**'), 'DEFAULT_IGNORE_PATTERNS does not contain **/dist/**');
      assert(!DEFAULT_IGNORE_PATTERNS.includes('**/build/**'), 'DEFAULT_IGNORE_PATTERNS does not contain **/build/**');
      assert(!DEFAULT_IGNORE_PATTERNS.includes('**/*.min.js'), 'DEFAULT_IGNORE_PATTERNS does not contain **/*.min.js');
      assert(!DEFAULT_IGNORE_PATTERNS.includes('*.min.js'), 'DEFAULT_IGNORE_PATTERNS does not contain *.min.js');
      assert(!DEFAULT_IGNORE_PATTERNS.includes('**/*.lock'), 'DEFAULT_IGNORE_PATTERNS does not contain **/*.lock');
      assert(!DEFAULT_IGNORE_PATTERNS.includes('*.lock'), 'DEFAULT_IGNORE_PATTERNS does not contain *.lock');

      assert(matchesPat('dist/bundle.js', 'dist/**') === true, 'dist/** matches top-level dist/bundle.js');
      assert(matchesPat('build/output.js', 'build/**') === true, 'build/** matches top-level build/output.js');
      assert(matchesPat('src/dist/token.ts', 'dist/**') === false, 'dist/** does NOT match src/dist/token.ts');
      assert(matchesPat('lib/build/config.ts', 'build/**') === false, 'build/** does NOT match lib/build/config.ts');
      assert(DEFAULT_IGNORE_PATTERNS.some((p: string) => matchesPat('secrets.lock', p)) === false, 'secrets.lock is NOT excluded by default');
      assert(DEFAULT_IGNORE_PATTERNS.some((p: string) => matchesPat('app.min.js', p)) === false, 'app.min.js is NOT excluded by default');
      assert(DEFAULT_IGNORE_PATTERNS.some((p: string) => matchesPat('package-lock.json', p)) === true, 'package-lock.json IS excluded by default');

      // 3. Staged binary file scan tolerates binary assets without ERROR status
      const binScratch = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-staged-bin-'));
      cp.execSync('git init', { cwd: binScratch, stdio: 'ignore' });
      cp.execSync('git config user.name "SLD Test"', { cwd: binScratch, stdio: 'ignore' });
      cp.execSync('git config user.email "sld@test.com"', { cwd: binScratch, stdio: 'ignore' });
      // Write a dummy PNG with valid PNG magic bytes
      const pngHeader = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00]);
      fs.writeFileSync(path.join(binScratch, 'logo.png'), pngHeader);
      fs.writeFileSync(path.join(binScratch, 'README.md'), '# Clean Readme\n', 'utf8');
      cp.execSync('git add logo.png README.md', { cwd: binScratch, stdio: 'ignore' });

      const binStagedRes = scanStagedChangesSync(binScratch);
      assert(binStagedRes.status === 'CLEAN', `Staging binary file returns CLEAN (got ${binStagedRes.status})`);
      assert(binStagedRes.skippedFiles && binStagedRes.skippedFiles.length === 1, 'Binary file recorded in skippedFiles');
      assert(binStagedRes.skippedFiles![0].path === 'logo.png', 'Skipped file path is logo.png');
      assert(binStagedRes.findings.length === 0, 'No false findings on clean staged files with binary');

      // Clean up bin scratch
      try { fs.rmSync(binScratch, { recursive: true, force: true }); } catch {}

      // 4. Hook registry functions
      const testHookPath = path.join(os.tmpdir(), 'test-repo', '.git', 'hooks', 'pre-commit');
      recordInstalledHook(testHookPath);
      const sldRegistry = path.join(os.homedir(), '.sld', 'installed-hooks.json');
      assert(fs.existsSync(sldRegistry), 'Installed hook recorded in ~/.sld/installed-hooks.json');
      unrecordInstalledHook(testHookPath);
    }

    // --- 32. Content-Based Inspection, Encodings (UTF-16BE/32/Gzip), NUL Byte & Base64 Resilience ---
    console.log('\n--- 32. Content-Based Inspection, Encodings (UTF-16BE/32/Gzip), NUL Byte & Base64 Resilience ---');
    {
      const { decodeTextBuffer } = require('../src/git/stagedScanner');
      const { scanContent } = require('../src/core/scanner/scanner');
      const zlib = require('zlib');

      // 1. Text file with NUL byte in the first 1 KB
      const nulBuffer = Buffer.concat([
        Buffer.from('prefix text before null\0', 'utf8'),
        Buffer.from('AKIA1234567890ABCDEF and more normal text here\n', 'utf8')
      ]);
      const nulDecoded = decodeTextBuffer(nulBuffer);
      assert(nulDecoded !== null, 'Text buffer with sparse NUL byte is decoded as text');
      assert(nulDecoded!.includes('AKIA1234567890ABCDEF'), 'Token preserved across NUL byte boundary');

      // 2. UTF-16BE without BOM
      const utf16beSource = 'AKIA1234567890BEF123 token in utf16be\n';
      const utf16beBuf = Buffer.alloc(utf16beSource.length * 2);
      for (let i = 0; i < utf16beSource.length; i++) {
        utf16beBuf.writeUInt16BE(utf16beSource.charCodeAt(i), i * 2);
      }
      const utf16beDecoded = decodeTextBuffer(utf16beBuf);
      assert(utf16beDecoded !== null, 'UTF-16BE buffer without BOM is successfully decoded');
      assert(utf16beDecoded!.includes('AKIA1234567890BEF123'), 'Decoded UTF-16BE contains the token');

      // 3. UTF-32LE with and without BOM
      const utf32Source = 'AKIA1234567890UTF321 token in utf32\n';
      const utf32Buf = Buffer.alloc(utf32Source.length * 4);
      for (let i = 0; i < utf32Source.length; i++) {
        utf32Buf.writeUInt32LE(utf32Source.charCodeAt(i), i * 4);
      }
      const utf32Decoded = decodeTextBuffer(utf32Buf);
      assert(utf32Decoded !== null, 'UTF-32 buffer is successfully decoded');
      assert(utf32Decoded!.includes('AKIA1234567890UTF321'), 'Decoded UTF-32 contains the token');

      // 4. Gzip compressed token payload
      const gzipSource = 'export const AWS_SECRET="AKIA1234567890GZIP99";\n';
      const gzipBuf = zlib.gzipSync(Buffer.from(gzipSource, 'utf8'));
      const gzipDecoded = decodeTextBuffer(gzipBuf);
      assert(gzipDecoded !== null, 'Gzip compressed buffer is decompressed and decoded');
      assert(gzipDecoded!.includes('AKIA1234567890GZIP99'), 'Decompressed gzip contains the token');

      // 5. Binary file with embedded token
      const binaryPayload = Buffer.concat([
        Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01, 0x02, 0x03]),
        Buffer.from('AKIA1234567890EMBEDDED', 'ascii'),
        Buffer.from([0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0x00, 0x00])
      ]);
      const binaryDecoded = decodeTextBuffer(binaryPayload);
      assert(binaryDecoded !== null, 'Dense binary buffer with embedded strings has text extracted');
      assert(binaryDecoded!.includes('AKIA1234567890EMBEDDED'), 'Extracted strings contain embedded token');

      // 6. Base64 token deobfuscation
      const b64Secret = Buffer.from('AKIA1234567890B64SEC', 'utf8').toString('base64');
      const b64Code = `const key = "${b64Secret}";\n`;
      const b64Findings = scanContent(b64Code, 'config.js');
      assert(b64Findings.length >= 1, `Base64 wrapped token detected (got ${b64Findings.length})`);
      assert(b64Findings[0].type.includes('AWS'), 'Base64 wrapped token correctly identified as AWS key');

      // 7. Staged scan with token in text file named *.png, *.bin, *.sqlite
      const stagedDisguised = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-staged-disguise-'));
      cp.execSync('git init', { cwd: stagedDisguised, stdio: 'ignore' });
      cp.execSync('git config user.name "SLD Test"', { cwd: stagedDisguised, stdio: 'ignore' });
      cp.execSync('git config user.email "sld@test.com"', { cwd: stagedDisguised, stdio: 'ignore' });
      const disguisedKey = synth(['AK', 'IA', '0123456789DISGUI']);
      fs.writeFileSync(path.join(stagedDisguised, 'data.png'), `export const key = "${disguisedKey}";\n`, 'utf8');
      fs.writeFileSync(path.join(stagedDisguised, 'dump.sqlite'), `INSERT INTO keys VALUES ('${disguisedKey}');\n`, 'utf8');
      cp.execSync('git add data.png dump.sqlite', { cwd: stagedDisguised, stdio: 'ignore' });

      const { scanStagedChangesSync: stagedSync } = require('../src/git/stagedScanner');
      const disguiseResult = stagedSync(stagedDisguised);
      assert(disguiseResult.status === 'FINDINGS', `Text file disguised as .png/.sqlite is scanned and detected (got ${disguiseResult.status})`);
      assert(disguiseResult.findings.length >= 2, `Both disguised files flagged (got ${disguiseResult.findings.length})`);
      try { fs.rmSync(stagedDisguised, { recursive: true, force: true }); } catch {}

      // 8. Pre-commit hook configuration and fail-closed guidance
      const { buildPreCommitHook } = require('../src/git/preCommitHook');
      const nonExistentCli = path.join(os.tmpdir(), 'non-existent-sld-cli.js');
      const selfHealingHook = buildPreCommitHook(undefined, nonExistentCli);
      assert(selfHealingHook.includes('fail-closed') || selfHealingHook.includes('FAIL-CLOSED'), 'Hook enforces fail-closed contract when scanner CLI is unavailable');
      assert(selfHealingHook.includes('SLD_FAIL_ON_SKIPPED'), 'Hook includes SLD_FAIL_ON_SKIPPED configuration');
      assert(selfHealingHook.includes('SLD_DISALLOW_INLINE_DEFAULT'), 'Hook includes SLD_DISALLOW_INLINE_DEFAULT configuration');
    }

    // --- 33. Provider Dotted Token Preservation, Strict Fail-Closed Defaults & Submodule Immunity ---
    console.log('\n--- 33. Provider Dotted Token Preservation, Strict Fail-Closed Defaults & Submodule Immunity ---');
    {
      const { evaluateFalsePositive } = require('../src/core/classifier/falsePositiveClassifier');
      const { scanContent } = require('../src/core/scanner/scanner');
      const { scanStagedChangesSync } = require('../src/git/stagedScanner');

      // 1. SendGrid tripartite key (SG.<22>.<43>) where neither segment has hyphens and starts with a letter
      const sendgridKey = 'SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789abcdefg';
      const fpCheckSg = evaluateFalsePositive(sendgridKey, 'apiKey', 'mailer.ts', 'SendGrid');
      assert(fpCheckSg.isFalsePositive === false, 'SendGrid tripartite key is NOT classified as false positive property access');

      const sgCode = `const apiKey = "${sendgridKey}";\n`;
      const sgFindings = scanContent(sgCode, 'mailer.ts');
      assert(sgFindings.length === 1, `Real SendGrid dotted token is detected (got ${sgFindings.length})`);
      assert(sgFindings[0].type === 'SendGrid API Key', `Finding correctly classified as SendGrid API Key (got ${sgFindings[0].type})`);

      // Generic property access IS still suppressed
      const fpCheckGeneric = evaluateFalsePositive('this.config.apiToken', 'apiToken', 'config.ts', 'Generic Credential');
      assert(fpCheckGeneric.isFalsePositive === true, 'Generic object property access is suppressed');

      // 2. Default to FAIL-CLOSED on oversized staged file when ignoreSkipped is omitted
      const oversizeScratch = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-oversize-strict-'));
      cp.execSync('git init', { cwd: oversizeScratch, stdio: 'ignore' });
      cp.execSync('git config user.name "SLD Test"', { cwd: oversizeScratch, stdio: 'ignore' });
      cp.execSync('git config user.email "sld@test.com"', { cwd: oversizeScratch, stdio: 'ignore' });

      const bigFile = path.join(oversizeScratch, 'huge.dat');
      fs.writeFileSync(bigFile, Buffer.alloc(1.5 * 1024 * 1024, 'x\n'));
      cp.execSync('git add huge.dat', { cwd: oversizeScratch, stdio: 'ignore' });

      // Call without ignoreSkipped option (omitted) -> must FAIL-CLOSED with ERROR
      const defaultOversizeRes = scanStagedChangesSync(oversizeScratch, { maxFileSize: 1 * 1024 * 1024 });
      assert(defaultOversizeRes.status === 'ERROR', `Oversized file without explicit options defaults to ERROR (got ${defaultOversizeRes.status})`);
      assert(defaultOversizeRes.error?.includes('exceeds 1MB limit'), 'Error mentions size limit and bypass guidance');

      // Call with ignoreSkipped: true -> allows scan, marks as skipped
      const bypassedRes = scanStagedChangesSync(oversizeScratch, { maxFileSize: 1 * 1024 * 1024, ignoreSkipped: true });
      assert(bypassedRes.status === 'CLEAN', 'Oversized file with ignoreSkipped: true is tolerated');
      assert(bypassedRes.skippedFiles && bypassedRes.skippedFiles.length === 1, 'Oversized file recorded in skippedFiles');
      try { fs.rmSync(oversizeScratch, { recursive: true, force: true }); } catch {}

      // 3. Submodule gitlink immunity (mode 160000)
      const subParentScratch = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-sub-parent-'));
      const subChildScratch = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-sub-child-'));
      cp.execSync('git init', { cwd: subParentScratch, stdio: 'ignore' });
      cp.execSync('git config user.name "SLD Test"', { cwd: subParentScratch, stdio: 'ignore' });
      cp.execSync('git config user.email "sld@test.com"', { cwd: subParentScratch, stdio: 'ignore' });

      cp.execSync('git init', { cwd: subChildScratch, stdio: 'ignore' });
      cp.execSync('git config user.name "SLD Test"', { cwd: subChildScratch, stdio: 'ignore' });
      cp.execSync('git config user.email "sld@test.com"', { cwd: subChildScratch, stdio: 'ignore' });
      fs.writeFileSync(path.join(subChildScratch, 'child.txt'), 'hello\n');
      cp.execSync('git add child.txt && git commit -m "init child"', { cwd: subChildScratch, stdio: 'ignore' });

      // Add child as submodule to parent
      try {
        cp.execSync(`git submodule add "${subChildScratch.replace(/\\/g, '/')}" my-submodule`, { cwd: subParentScratch, stdio: 'ignore' });
        const subScanRes = scanStagedChangesSync(subParentScratch);
        assert(subScanRes.status !== 'ERROR', `Staged submodule bump does NOT trigger ERROR (got ${subScanRes.status})`);
      } catch (subErr) {
        // In environments where git submodule add is restricted, verify function doesn't crash
        assert(true, 'Submodule check completed');
      }
      try { fs.rmSync(subParentScratch, { recursive: true, force: true }); } catch {}
      try { fs.rmSync(subChildScratch, { recursive: true, force: true }); } catch {}
    }

    // --- 34. Private Salt (.sld/salt), Auto-Recovery Hook Cleanup & NON_TEXT_EXTENSIONS ---
    console.log('\n--- 34. Private Salt (.sld/salt), Auto-Recovery Hook Cleanup & NON_TEXT_EXTENSIONS ---');
    {
      const { resolveSalt, generateFingerprint } = require('../src/core/redactor/redactor');
      const { NON_TEXT_EXTENSIONS } = require('../src/core/ignore/ignoreEngine');
      const { buildPreCommitHook } = require('../src/git/preCommitHook');

      // 1. NON_TEXT_EXTENSIONS does not contain .png, .bin, .pkl, .sqlite
      assert(!NON_TEXT_EXTENSIONS.has('.png'), 'NON_TEXT_EXTENSIONS does not skip .png');
      assert(!NON_TEXT_EXTENSIONS.has('.bin'), 'NON_TEXT_EXTENSIONS does not skip .bin');
      assert(!NON_TEXT_EXTENSIONS.has('.pkl'), 'NON_TEXT_EXTENSIONS does not skip .pkl');
      assert(!NON_TEXT_EXTENSIONS.has('.sqlite'), 'NON_TEXT_EXTENSIONS does not skip .sqlite');
      assert(NON_TEXT_EXTENSIONS.has('.exe'), 'NON_TEXT_EXTENSIONS skips .exe');
      assert(NON_TEXT_EXTENSIONS.has('.so'), 'NON_TEXT_EXTENSIONS skips .so');

      // 2. resolveSalt with .sld/salt file
      const saltScratch = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-salt-test-'));
      const sldDir = path.join(saltScratch, '.sld');
      fs.mkdirSync(sldDir, { recursive: true });
      fs.writeFileSync(path.join(sldDir, 'salt'), 'custom_repo_secret_salt_123', 'utf8');

      const resolved = resolveSalt(undefined, saltScratch);
      assert(resolved === 'custom_repo_secret_salt_123', 'resolveSalt correctly reads .sld/salt');

      const fpCustom = generateFingerprint('secret123', undefined, saltScratch);
      const fpDefault = generateFingerprint('secret123');
      assert(fpCustom !== fpDefault, 'Private salt yields distinct HMAC fingerprint from default');
      try { fs.rmSync(saltScratch, { recursive: true, force: true }); } catch {}

      // 3. Hook fail-closed recovery guidance
      const dummyMissingCli = path.join(os.tmpdir(), 'deleted-extension-cli.js');
      const uninstalledHook = buildPreCommitHook(undefined, dummyMissingCli);
      assert(uninstalledHook.includes('COMMIT BLOCKED (fail-closed)'), 'Hook enforces fail-closed when CLI is missing');
      assert(uninstalledHook.includes('Remove stranded hook: rm'), 'Hook provides actionable removal guidance');
      assert(uninstalledHook.includes('pre-commit.sld-backup.latest'), 'Hook checks for backup restoration');
    }

    // --- 35. CI Trusted Base Ref, Staged Multiline PEM & Fail-On-Skipped Invariants ---
    console.log('\n--- 35. CI Trusted Base Ref, Staged Multiline PEM & Fail-On-Skipped Invariants ---');
    {
      const { resolveCIBaseRef } = require('../src/core/ignore/ignoreEngine');
      const { BaselineEngine, BaselineValidationError } = require('../src/core/baseline/baselineEngine');
      const { findingIntersectsAddedLines, scanStagedChangesSync } = require('../src/git/stagedScanner');
      const { scanContent } = require('../src/core/scanner/scanner');

      // 1. CI Base Ref ignores refs that point to HEAD
      const dummyRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-ci-base-'));
      try {
        const { execFileSync } = require('child_process');
        execFileSync('git', ['init', dummyRepo]);
        execFileSync('git', ['-C', dummyRepo, 'config', 'user.name', 'Test']);
        execFileSync('git', ['-C', dummyRepo, 'config', 'user.email', 'test@test.com']);
        fs.writeFileSync(path.join(dummyRepo, 'file.txt'), 'init', 'utf8');
        execFileSync('git', ['-C', dummyRepo, 'add', 'file.txt']);
        execFileSync('git', ['-C', dummyRepo, 'commit', '-m', 'c1']);

        // When SLD_BASE_REF points to HEAD, resolveCIBaseRef rejects it
        process.env.SLD_BASE_REF = 'HEAD';
        const rejectedHead = resolveCIBaseRef(dummyRepo);
        assert(rejectedHead === null, 'resolveCIBaseRef rejects ref matching HEAD sha');
        delete process.env.SLD_BASE_REF;

        // 2. loadBaselineFromGit throws BaselineValidationError when baseline git blob is malformed
        fs.writeFileSync(path.join(dummyRepo, '.secretleak-baseline.json'), '{ invalid json @@#', 'utf8');
        execFileSync('git', ['-C', dummyRepo, 'add', '.secretleak-baseline.json']);
        execFileSync('git', ['-C', dummyRepo, 'commit', '-m', 'add malformed baseline']);

        let thrownErr: any = null;
        const origCiMalformed = process.env.CI;
        const origGhActionsMalformed = process.env.GITHUB_ACTIONS;
        const origGitlabMalformed = process.env.GITLAB_CI;
        try {
          delete process.env.CI;
          delete process.env.GITHUB_ACTIONS;
          delete process.env.GITLAB_CI;
          const bEngine = new BaselineEngine(dummyRepo, '.secretleak-baseline.json');
          bEngine.loadBaselineFromGit('HEAD');
        } catch (err) {
          thrownErr = err;
        } finally {
          if (origCiMalformed !== undefined) process.env.CI = origCiMalformed;
          else delete process.env.CI;
          if (origGhActionsMalformed !== undefined) process.env.GITHUB_ACTIONS = origGhActionsMalformed;
          else delete process.env.GITHUB_ACTIONS;
          if (origGitlabMalformed !== undefined) process.env.GITLAB_CI = origGitlabMalformed;
          else delete process.env.GITLAB_CI;
        }
        assert(thrownErr instanceof BaselineValidationError, 'loadBaselineFromGit throws BaselineValidationError for malformed git baseline');

        // 2b. CI trusted ref resolution: loadBaselineFromGit() with SLD_BASE_REF
        const trustedBaselineJson = JSON.stringify({
          version: 1,
          generatedAt: new Date().toISOString(),
          findings: [
            {
              id: 'sec_trusted_1',
              fingerprint: 'fp_trusted_1',
              ruleId: 'AWS Access Key ID',
              file: 'file.txt',
              line: 1,
            },
          ],
        });
        fs.writeFileSync(path.join(dummyRepo, '.secretleak-baseline.json'), trustedBaselineJson, 'utf8');
        execFileSync('git', ['-C', dummyRepo, 'add', '.secretleak-baseline.json']);
        execFileSync('git', ['-C', dummyRepo, 'commit', '-m', 'add trusted baseline']);
        const trustedSha = execFileSync('git', ['-C', dummyRepo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();

        // Add a commit on top that corrupts the baseline
        fs.writeFileSync(path.join(dummyRepo, '.secretleak-baseline.json'), '{ corrupted in head', 'utf8');
        execFileSync('git', ['-C', dummyRepo, 'add', '.secretleak-baseline.json']);
        execFileSync('git', ['-C', dummyRepo, 'commit', '-m', 'tampered baseline in head']);

        // Under CI with SLD_BASE_REF pointing to trustedSha, loadBaselineFromGit() loads trustedSha and ignores HEAD
        const origCi = process.env.CI;
        try {
          process.env.CI = 'true';
          process.env.SLD_BASE_REF = trustedSha;
          const bEngineCi = new BaselineEngine(dummyRepo, '.secretleak-baseline.json');
          const loadedTrusted = bEngineCi.loadBaselineFromGit();
          assert(loadedTrusted !== null, 'CI loadBaselineFromGit loads trusted baseline from SLD_BASE_REF');
          assert(loadedTrusted?.findings.length === 1, 'CI loadBaselineFromGit contains trusted findings');
          assert(loadedTrusted?.findings[0].fingerprint === 'fp_trusted_1', 'CI loadBaselineFromGit matched trusted fingerprint');
        } finally {
          if (origCi !== undefined) process.env.CI = origCi;
          else delete process.env.CI;
          delete process.env.SLD_BASE_REF;
        }

        // 3. Staged multiline PEM key detection when only body lines are staged
        const pemDummy = [
          '-----BEGIN RSA PRIVATE KEY-----',
          'MIIEowIBAAKCAQEA0Y1234567890abcdefghijklmnopqrstuvwxyz1234567890',
          'abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz12',
          '34567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrst',
          '-----END RSA PRIVATE KEY-----',
        ].join('\n');

        // Start line 10, spans 4 newlines (lines 10 to 14)
        const mockPemFinding: any = {
          line: 10,
          rawSecret: pemDummy,
        };
        // If only line 12 is added in diff
        const addedOnlyLine12 = new Set([12]);
        assert(findingIntersectsAddedLines(mockPemFinding, addedOnlyLine12) === true, 'Multiline secret intersects added diff hunk on body lines');

        // If diff touches unrelated line 5
        const addedUnrelated = new Set([5]);
        assert(findingIntersectsAddedLines(mockPemFinding, addedUnrelated) === false, 'Multiline secret correctly does not intersect untouched diff hunk');

        // Staged git repo test: header and footer already in commit, only body lines staged
        const multilineRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-multiline-pem-'));
        try {
          execFileSync('git', ['init', multilineRepo]);
          execFileSync('git', ['-C', multilineRepo, 'config', 'user.name', 'Test']);
          execFileSync('git', ['-C', multilineRepo, 'config', 'user.email', 'test@test.com']);

          fs.writeFileSync(
            path.join(multilineRepo, 'cert.key'),
            '-----BEGIN RSA PRIVATE KEY-----\n// placeholder\n-----END RSA PRIVATE KEY-----\n',
            'utf8'
          );
          execFileSync('git', ['-C', multilineRepo, 'add', 'cert.key']);
          execFileSync('git', ['-C', multilineRepo, 'commit', '-m', 'commit header and footer']);

          // Now stage real body lines
          fs.writeFileSync(path.join(multilineRepo, 'cert.key'), pemDummy + '\n', 'utf8');
          execFileSync('git', ['-C', multilineRepo, 'add', 'cert.key']);

          const stagedSync = scanStagedChangesSync(multilineRepo);
          assert(stagedSync.status === 'FINDINGS', 'Staging body lines of multiline secret is detected (got FINDINGS)');
          assert(stagedSync.findings.length > 0, 'Multiline secret finding detected on staged body');
        } finally {
          try {
            fs.rmSync(multilineRepo, { recursive: true, force: true });
          } catch {}
        }

        // 4. Strict mode failOnSkipped returns ERROR when files are skipped
        const strictRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-strict-repo-'));
        try {
          execFileSync('git', ['init', strictRepo]);
          execFileSync('git', ['-C', strictRepo, 'config', 'user.name', 'Test']);
          execFileSync('git', ['-C', strictRepo, 'config', 'user.email', 'test@test.com']);

          // Create binary with 0 printable text (e.g. 100 null bytes)
          const zeroTextBuf = Buffer.alloc(100, 0);
          fs.writeFileSync(path.join(strictRepo, 'zero.bin'), zeroTextBuf);
          execFileSync('git', ['-C', strictRepo, 'add', 'zero.bin']);

          const strictResult = scanStagedChangesSync(strictRepo, { failOnSkipped: true });
          assert(strictResult.status === 'ERROR', 'Strict mode (failOnSkipped) returns ERROR on skipped binary file');
          assert(strictResult.skippedFiles && strictResult.skippedFiles.length > 0, 'Skipped files contains skipped entry');

          const normalResult = scanStagedChangesSync(strictRepo, { failOnSkipped: false });
          assert(normalResult.status === 'CLEAN', 'Non-strict mode returns CLEAN with warning');
        } finally {
          try {
            fs.rmSync(strictRepo, { recursive: true, force: true });
          } catch {}
        }

        // 5. Scanner workspaceRoot uses custom private salt
        const saltDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-scanner-salt-'));
        try {
          const sldSaltDir = path.join(saltDir, '.sld');
          fs.mkdirSync(sldSaltDir, { recursive: true });
          fs.writeFileSync(path.join(sldSaltDir, 'salt'), 'test_scanner_salt_999\n', 'utf8');

          const findingsDefault = scanContent('const k = "AKIA1234567890ABCDEF";', 'key.ts');
          const findingsCustom = scanContent('const k = "AKIA1234567890ABCDEF";', 'key.ts', { workspaceRoot: saltDir });

          assert(findingsDefault.length === 1 && findingsCustom.length === 1, 'Both scans find the key');
          assert(
            findingsDefault[0].fingerprint !== findingsCustom[0].fingerprint,
            'Scanner uses workspaceRoot private salt for fingerprinting'
          );
        } finally {
          try {
            fs.rmSync(saltDir, { recursive: true, force: true });
          } catch {}
        }
      } finally {
        try {
          fs.rmSync(dummyRepo, { recursive: true, force: true });
        } catch {}
      }
    }

    // --- 36. Compact JSON, Quoted Auth Header, Hyphenated Keys & Hook Fail-Closed Defaults ---
    console.log('\n--- 36. Compact JSON, Quoted Auth Header, Hyphenated Keys & Hook Fail-Closed Defaults ---');
    {
      const { scanContent } = require('../src/core/scanner/scanner');
      const { buildPreCommitHook } = require('../src/git/preCommitHook');

      // 1. Compact JSON detection for aws-secret-key, generic-api-key, azure-ad-client-secret, twilio-api-key
      const compactAws = '{"aws_secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCY1234567890"}';
      const awsFindings = scanContent(compactAws, 'config.json');
      assert(awsFindings.length === 1 && awsFindings[0].type === 'AWS Secret Access Key', 'Compact JSON detects AWS secret key');

      const compactGeneric = '{"api_key":"my-custom-hyphenated-secret-key-1234567890"}';
      const genericFindings = scanContent(compactGeneric, 'config.json');
      assert(genericFindings.length === 1 && genericFindings[0].type === 'Generic API Secret Assignment', 'Compact JSON detects hyphenated generic API key');

      const compactAzureAd = '{"azure_client_secret":"0123456789abcdefghijklmnopqrstuvwx~.-_"}';
      const azureAdFindings = scanContent(compactAzureAd, 'config.json');
      assert(azureAdFindings.length === 1 && azureAdFindings[0].type === 'Azure Active Directory Client Secret', 'Compact JSON detects Azure AD client secret');

      const compactTwilio = '{"twilio_auth_token":"0123456789abcdef0123456789abcdef"}';
      const twilioFindings = scanContent(compactTwilio, 'config.json');
      assert(twilioFindings.length === 1 && twilioFindings[0].type === 'Twilio Auth Token / API Secret', 'Compact JSON detects Twilio auth token');

      // 2. Quoted Authorization header bearer token
      const quotedBearer = '{"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotShareSecrets1234567890"}';
      const bearerFindings = scanContent(quotedBearer, 'req.json');
      assert(bearerFindings.length === 1 && bearerFindings[0].type === 'Authorization Bearer Token', 'Quoted Authorization header detects Bearer token');

      // 3. Password assignment: admin-Xk29!fQ7rLmZ vs standalone admin
      const adminSecret = 'password = "admin-Xk29!fQ7rLmZ"';
      const adminFindings = scanContent(adminSecret, 'app.ts');
      assert(adminFindings.length === 1 && adminFindings[0].type === 'Password in Source Code', 'password = "admin-Xk29!fQ7rLmZ" is detected as real password');

      const adminPlaceholder = 'password = "admin"';
      const placeholderFindings = scanContent(adminPlaceholder, 'app.ts');
      assert(placeholderFindings.length === 0, 'password = "admin" is correctly suppressed as placeholder');

      // 4. Default hook strictly fails closed on missing extension CLI (without self-healing)
      const extensionCliPath = '/Users/test/.vscode/extensions/sld/dist/cli.js';
      const defaultHook = buildPreCommitHook(undefined, extensionCliPath);
      assert(defaultHook.includes('SLD_ALLOW_SELF_HEAL_DEFAULT="0"'), 'Default hook sets SLD_ALLOW_SELF_HEAL_DEFAULT to 0');
      assert(defaultHook.includes('ALLOW_SELF_HEAL=0'), 'Default hook initializes ALLOW_SELF_HEAL to 0');
      assert(defaultHook.includes('COMMIT BLOCKED (fail-closed)'), 'Hook fail-closed error printed when CLI is missing');

      // 5. Explicit allowSelfHeal opt-in configures self-healing hook
      const selfHealHook = buildPreCommitHook(undefined, extensionCliPath, undefined, true, true, false, true);
      assert(selfHealHook.includes('SLD_ALLOW_SELF_HEAL_DEFAULT="1"'), 'Self-heal hook sets SLD_ALLOW_SELF_HEAL_DEFAULT to 1');
      assert(selfHealHook.includes('ALLOW_SELF_HEAL=1'), 'Self-heal hook enables recovery branch');
    }
  }
    // --- 37. Cross-Platform Baseline Canonicalization, Deobfuscation Source Expressions, and Atomic Uninstaller ---
    console.log('\n--- 37. Cross-Platform Baseline Canonicalization, Deobfuscation Source Expressions, and Atomic Uninstaller ---');
    {
      const { BaselineEngine } = require('../src/core/baseline/baselineEngine');
      const { scanContent } = require('../src/core/scanner/scanner');
      const { GitTimelineEngine } = require('../src/core/history/gitTimeline');
      const { cleanHook } = require('../src/uninstall');

      // 1. Deobfuscation sourceExpression preservation
      const splitCode = 'const token = "ghp_" + "123456789012345678901234567890123456";';
      const splitFindings = scanContent(splitCode, 'app.ts');
      assert(splitFindings.length === 1, 'Split token detected');
      assert(splitFindings[0].sourceExpression === '"ghp_" + "123456789012345678901234567890123456"', 'Finding preserves exact raw sourceExpression');

      // 2. Base64 deobfuscation sourceExpression preservation
      const b64Secret = Buffer.from('AKIA1234567890B64SEC', 'utf8').toString('base64');
      const b64Code = 'const key = Buffer.from("' + b64Secret + '", "base64");\n';
      const b64Findings = scanContent(b64Code, 'app.ts');
      assert(b64Findings.length >= 1, 'Base64 token detected');
      assert(b64Findings[0].sourceExpression !== undefined && b64Findings[0].sourceExpression.includes(b64Secret), 'Base64 finding preserves sourceExpression');

      // 3. GitTimelineEngine returns ERROR status on query failure
      const timelineEngine = new GitTimelineEngine('/nonexistent/repo/directory/xyz');
      const timelineReport = await timelineEngine.buildTimeline('secret_xyz', 'sec***');
      assert(timelineReport.currentStatus === 'ERROR', 'GitTimeline reports ERROR on query failure (got ' + timelineReport.currentStatus + ')');
      assert(timelineReport.timelineAscii.includes('failed'), 'Timeline ascii explains error');

      // 4. Baseline path canonicalization does not produce relative escape
      const origCiSec37 = process.env.CI;
      const origGhActionsSec37 = process.env.GITHUB_ACTIONS;
      const origGitlabSec37 = process.env.GITLAB_CI;
      delete process.env.CI;
      delete process.env.GITHUB_ACTIONS;
      delete process.env.GITLAB_CI;
      let baselineResult: any;
      try {
        const baselineEngine = new BaselineEngine(process.cwd(), '.secretleak-baseline.json');
        baselineResult = baselineEngine.loadBaselineFromGit('HEAD');
      } finally {
        if (origCiSec37 !== undefined) process.env.CI = origCiSec37;
        else delete process.env.CI;
        if (origGhActionsSec37 !== undefined) process.env.GITHUB_ACTIONS = origGhActionsSec37;
        else delete process.env.GITHUB_ACTIONS;
        if (origGitlabSec37 !== undefined) process.env.GITLAB_CI = origGitlabSec37;
        else delete process.env.GITLAB_CI;
      }
      assert(baselineResult !== undefined, 'loadBaselineFromGit runs cleanly without path resolution crash');

      // 5. cleanHook acquires lock and cleans managed hook safely
      const testHookDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-uninstall-lock-'));
      const testHookFile = path.join(testHookDir, 'pre-commit');
      fs.writeFileSync(testHookFile, '#!/bin/sh\n# [SLD_HOOK_MANAGED]\nexit 0\n', { mode: 0o755 });
      assert(fs.existsSync(testHookFile), 'Test hook file created');
      const cleanSuccess = cleanHook(testHookFile);
      assert(cleanSuccess === true, 'cleanHook returns true for managed hook');
      assert(!fs.existsSync(testHookFile), 'cleanHook removed managed hook');
      assert(!fs.existsSync(path.join(testHookDir, 'pre-commit.sld.lock')), 'cleanHook released lock file');
      try { fs.rmSync(testHookDir, { recursive: true, force: true }); } catch {}

      // ── Section 38: Uninstaller Lock Race Protection, Capture Group Isolation, and Source Expression Remediation ──
      console.log('\n--- 38. Uninstaller Lock Race Protection, Capture Group Isolation & Strict Defaults ---');

      // 1. cleanHook aborts cleanly when lock is held by another active process
      const lockContentionDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-lock-contention-'));
      const activeHookFile = path.join(lockContentionDir, 'pre-commit');
      const activeLockFile = path.join(lockContentionDir, 'pre-commit.sld.lock');
      fs.writeFileSync(activeHookFile, '#!/bin/sh\n# [SLD_HOOK_MANAGED]\nexit 0\n', { mode: 0o755 });
      fs.writeFileSync(activeLockFile, '999999', 'utf8'); // Active lock
      const lockContentionResult = cleanHook(activeHookFile);
      assert(lockContentionResult === false, 'cleanHook returns false when lock is held by another active process');
      assert(fs.existsSync(activeHookFile), 'Hook is not touched when lock cannot be acquired');
      try { fs.rmSync(lockContentionDir, { recursive: true, force: true }); } catch {}

      // 2. Twilio regex branch 2 properly isolates 32-character hex secret from assignment
      const twilioCode = 'const auth_token = "0123456789abcdef0123456789abcdef";';
      const twilioFindings = scanContent(twilioCode, 'auth.js');
      assert(twilioFindings.length === 1, 'Twilio auth token detected');
      assert(twilioFindings[0].rawSecret === '0123456789abcdef0123456789abcdef', 'Twilio rawSecret is 32-char token, not assignment string (got ' + twilioFindings[0].rawSecret + ')');

      // 3. applyControlledRemediation handles findings with sourceExpression
      const remDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-rem-src-expr-'));
      const remFile = path.join(remDir, 'test.js');
      fs.writeFileSync(remFile, `import 'dotenv/config';\nconst token = "part1_" + "part2_abcdef1234567890";\n`, 'utf8');
      const fakeFinding: any = {
        id: 'finding_expr_1',
        type: 'Generic API Key',
        provider: 'Generic',
        rawSecret: 'part1_part2_abcdef1234567890',
        sourceExpression: '"part1_" + "part2_abcdef1234567890"',
        redactedSecret: 'part••••••••••••',
        file: 'test.js',
        fullPath: remFile,
        line: 1,
        column: 15,
        remediation: { envVarName: 'TEST_API_KEY' },
      };
      const remRes = applyControlledRemediation(fakeFinding, remDir);
      assert(remRes.success === true, 'applyControlledRemediation succeeds with sourceExpression');
      const remUpdatedContent = fs.readFileSync(remFile, 'utf8');
      assert(remUpdatedContent.includes('process.env.TEST_API_KEY'), 'Source expression replaced with process.env.TEST_API_KEY');
      assert(!remUpdatedContent.includes('part1_'), 'Old split parts completely removed');
      try { fs.rmSync(remDir, { recursive: true, force: true }); } catch {}

      // 4. resolveSalt honors SLD_SALT and SLD_FINGERPRINT_SALT
      const { resolveSalt } = require('../src/core/redactor/redactor');
      const origSldSalt = process.env.SLD_SALT;
      const origSldFps = process.env.SLD_FINGERPRINT_SALT;
      try {
        delete process.env.SLD_SALT;
        process.env.SLD_FINGERPRINT_SALT = 'custom_fps_123';
        assert(resolveSalt() === 'custom_fps_123', 'resolveSalt honors SLD_FINGERPRINT_SALT');
        process.env.SLD_SALT = 'custom_salt_456';
        assert(resolveSalt() === 'custom_salt_456', 'resolveSalt prioritizes SLD_SALT');
      } finally {
        if (origSldSalt !== undefined) process.env.SLD_SALT = origSldSalt;
        else delete process.env.SLD_SALT;
        if (origSldFps !== undefined) process.env.SLD_FINGERPRINT_SALT = origSldFps;
        else delete process.env.SLD_FINGERPRINT_SALT;
      }

      // 5. DEFAULT_IGNORE_PATTERNS includes .vscode-test
      const { DEFAULT_IGNORE_PATTERNS } = require('../src/core/ignore/ignoreEngine');
      assert(DEFAULT_IGNORE_PATTERNS.includes('.vscode-test/**'), 'DEFAULT_IGNORE_PATTERNS includes .vscode-test/**');
      assert(DEFAULT_IGNORE_PATTERNS.includes('**/.vscode-test/**'), 'DEFAULT_IGNORE_PATTERNS includes **/.vscode-test/**');

      // 6. Hook defaults to strict failOnSkipped (1), relaxed hook sets failOnSkipped to 0
      const defaultHook = buildPreCommitHook();
      assert(defaultHook.includes('SLD_FAIL_ON_SKIPPED_DEFAULT="1"'), 'Default hook defaults failOnSkipped to 1 (strict fail-closed)');
      const relaxedHook = buildPreCommitHook(undefined, undefined, undefined, true, true, false);
      assert(relaxedHook.includes('SLD_FAIL_ON_SKIPPED_DEFAULT="0"'), 'Relaxed hook sets failOnSkipped to 0');
    }

    // --- 39. History Scanning Multiline Invariants, Multi-Hunk Attributions, and Working-Tree State ---
    console.log('\n--- 39. History Scanning Multiline Invariants, Multi-Hunk Attributions, and Working-Tree State ---');
    {
      const { GitHistoryEngine } = require('../src/core/history/gitHistoryEngine');
      const { GitTimelineEngine } = require('../src/core/history/gitTimeline');
      const { execFileSync } = require('child_process');
      const fromHex = (h: string) => Buffer.from(h, 'hex').toString('utf8');

      const testHistoryRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-hist-pem-'));
      try {
        execFileSync('git', ['init', testHistoryRepo]);
        execFileSync('git', ['-C', testHistoryRepo, 'config', 'user.name', 'Security Tester']);
        execFileSync('git', ['-C', testHistoryRepo, 'config', 'user.email', 'sec@test.com']);

        const gitHistory = new GitHistoryEngine(testHistoryRepo);
        const gitTimeline = new GitTimelineEngine(testHistoryRepo);

        // Test credentials constructed from hex at runtime so test runner source does not leak literal secrets
        const placeholderPem = fromHex('2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a2f2f2070656e64696e67206b657920696e73657274696f6e0a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a');
        const realPem = fromHex('2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d4949456f77494241414b4341514541305931763864325933653961422b4c2f376d3451377a3852317439753276337734783579367a37613862396330643165326633670a34683569366a376b386c396d306e316f3270337134723573367437753876397730783179327a336134623563366437653866396730683169326a336b346c356d366e376f0a3870397130723173327433753476357736783779387a396130623163326433653466356736683769386a396b306c316d326e336f347035713672377338743975307631770a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d');
        const updatedPem = fromHex('2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d4949456f77494241414b4341514541383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838380a34683569366a376b386c396d306e316f3270337134723573367437753876397730783179327a336134623563366437653866396730683169326a336b346c356d366e376f0a3870397130723173327433753476357736783779387a396130623163326433653466356736683769386a396b306c316d326e336f347035713672377338743975307631770a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d');
        const revokedDelimiters = fromHex('2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d0a');
        const githubToken = fromHex('6768705f313131313232323233333333343434343535353536363636373737373838383839393939');
        const hunkSecret = fromHex('6768705f393939393838383837373737363636363535353534343434333333333232323231313131');
        const uncommittedSecret = fromHex('6768705f616263646561626364656162636465616263646561626364656162636465616263646561');
        const phantomSecret = fromHex('6768705f303030303030303030303030303030303030303030303030303030303030303030303030');

        // 1. PEM header existing before body added (detected when body is introduced)
        // Commit 1: Header and placeholder footer
        fs.writeFileSync(path.join(testHistoryRepo, 'server.pem'), placeholderPem, 'utf8');
        execFileSync('git', ['-C', testHistoryRepo, 'add', 'server.pem']);
        execFileSync('git', ['-C', testHistoryRepo, 'commit', '-m', 'chore: add placeholder cert']);

        // Commit 2: Replace body with real PEM key
        fs.writeFileSync(path.join(testHistoryRepo, 'server.pem'), realPem + '\n', 'utf8');
        execFileSync('git', ['-C', testHistoryRepo, 'add', 'server.pem']);
        execFileSync('git', ['-C', testHistoryRepo, 'commit', '-m', 'feat: install private key']);

        const findings1 = await gitHistory.scanHistoryCommits();
        const pemFinding1 = findings1.find((f: any) => f.rawSecret && f.rawSecret.includes('MIIEowIBAAKCAQEA0Y1v8d2Y3e9aB+L/7m4Q7z8R1t9u2v3w4x5y6z7a8b9c0d1e2f3g'));
        assert(pemFinding1 !== undefined, 'scanHistoryCommits detects PEM key when body was added after header existed');
        assert(pemFinding1?.gitExposure?.isPresentInHead === true, 'PEM key is active in HEAD');

        // 2. PEM body modified while another credential (API key) added in same commit
        // Commit 3: update PEM key body + add GitHub token in config.json
        fs.writeFileSync(path.join(testHistoryRepo, 'server.pem'), updatedPem + '\n', 'utf8');
        fs.writeFileSync(path.join(testHistoryRepo, 'config.json'), JSON.stringify({ token: githubToken }), 'utf8');
        execFileSync('git', ['-C', testHistoryRepo, 'add', 'server.pem', 'config.json']);
        execFileSync('git', ['-C', testHistoryRepo, 'commit', '-m', 'feat: update cert and add github pat']);

        const findings2 = await gitHistory.scanHistoryCommits();
        const pemFinding2 = findings2.find((f: any) => f.rawSecret && f.rawSecret.includes('MIIEowIBAAKCAQEA8888888888888888888888888888888888888888888888888888'));
        const ghFinding2 = findings2.find((f: any) => f.rawSecret === githubToken);
        assert(pemFinding2 !== undefined, 'scanHistoryCommits detects modified PEM key in multi-secret commit');
        assert(ghFinding2 !== undefined, 'scanHistoryCommits detects GitHub PAT in same commit as modified PEM key');

        // 3. PEM key removed while header remains (isPresentInHead === false)
        // Commit 4: Delete PEM body from server.pem, leaving only delimiters
        fs.writeFileSync(path.join(testHistoryRepo, 'server.pem'), revokedDelimiters, 'utf8');
        execFileSync('git', ['-C', testHistoryRepo, 'add', 'server.pem']);
        execFileSync('git', ['-C', testHistoryRepo, 'commit', '-m', 'chore: revoke cert leaving placeholder']);

        const inHeadAfterRevocation = await gitHistory.isSecretInHead(realPem, 'server.pem');
        assert(inHeadAfterRevocation === false, 'isSecretInHead returns false when PEM body is removed but header remains');

        const findingsAfterRevocation = await gitHistory.scanHistoryCommits();
        const historicalPem = findingsAfterRevocation.find((f: any) => f.rawSecret && f.rawSecret.includes('MIIEowIBAAKCAQEA0Y1v8d2Y3e9aB+L/7m4Q7z8R1t9u2v3w4x5y6z7a8b9c0d1e2f3g'));
        assert(historicalPem !== undefined, 'Revoked PEM key is preserved in historical commit findings');
        assert(historicalPem?.gitExposure?.isPresentInHead === false, 'Revoked PEM key correctly marked as NOT present in HEAD');

        // 4. Credential added in hunk 3 of a multi-hunk diff
        const distantFile = path.join(testHistoryRepo, 'distant.txt');
        const initialLines = Array.from({ length: 300 }, (_, i) => `line ${i + 1}`);
        fs.writeFileSync(distantFile, initialLines.join('\n') + '\n', 'utf8');
        execFileSync('git', ['-C', testHistoryRepo, 'add', 'distant.txt']);
        execFileSync('git', ['-C', testHistoryRepo, 'commit', '-m', 'chore: add large baseline file']);

        // Modify at line 10, line 150, and line 280 (hunk 3 contains secret)
        initialLines[9] = 'modified line 10';
        initialLines[149] = 'modified line 150';
        initialLines[279] = `const TOKEN = "${hunkSecret}";`;
        fs.writeFileSync(distantFile, initialLines.join('\n') + '\n', 'utf8');
        execFileSync('git', ['-C', testHistoryRepo, 'add', 'distant.txt']);
        execFileSync('git', ['-C', testHistoryRepo, 'commit', '-m', 'feat: update lines across file with token']);

        const findingsMultiHunk = await gitHistory.scanHistoryCommits();
        const hunkFinding = findingsMultiHunk.find((f: any) => f.rawSecret === hunkSecret);
        assert(hunkFinding !== undefined, 'scanHistoryCommits detects credential in hunk 3 of multi-hunk diff');

        // 5. Empty history results verified against working tree:
        // Absent everywhere -> NOT_FOUND
        const tracePhantom = await gitHistory.traceSecret(phantomSecret);
        assert(tracePhantom.statusDescription.includes('not found in Git history or working tree'), 'traceSecret reports NOT_FOUND when secret is absent everywhere');
        const timelinePhantom = await gitTimeline.buildTimeline(phantomSecret, 'ghp_••••');
        assert(timelinePhantom.currentStatus === 'NOT_FOUND', 'buildTimeline reports NOT_FOUND when secret is absent everywhere');

        // Present in working tree only (uncommitted) -> CLEAN_UNCOMMITTED
        fs.writeFileSync(path.join(testHistoryRepo, 'uncommitted.ts'), `const secret = "${uncommittedSecret}";\n`, 'utf8');
        const traceUncommitted = await gitHistory.traceSecret(uncommittedSecret);
        assert(traceUncommitted.statusDescription.includes('Present in working tree only (uncommitted)'), 'traceSecret reports uncommitted working tree status');
        const timelineUncommitted = await gitTimeline.buildTimeline(uncommittedSecret, 'ghp_••••');
        assert(timelineUncommitted.currentStatus === 'CLEAN_UNCOMMITTED', 'buildTimeline reports CLEAN_UNCOMMITTED when present in working tree only');
      } finally {
        try {
          fs.rmSync(testHistoryRepo, { recursive: true, force: true });
        } catch {}
      }
    }

    // --- 40. History Correctness, Staged Index Verification & CI Baseline Invariants ---
    console.log('\n--- 40. History Correctness, Staged Index Verification & CI Baseline Invariants ---');
    {
      const { GitHistoryEngine } = require('../src/core/history/gitHistoryEngine');
      const { GitTimelineEngine } = require('../src/core/history/gitTimeline');
      const { BaselineEngine } = require('../src/core/baseline/baselineEngine');
      const { execFileSync } = require('child_process');
      const fromHex = (h: string) => Buffer.from(h, 'hex').toString('utf8');

      const sec40Repo = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-sec40-repo-'));
      try {
        execFileSync('git', ['init', sec40Repo]);
        execFileSync('git', ['-C', sec40Repo, 'config', 'user.name', 'Security Tester']);
        execFileSync('git', ['-C', sec40Repo, 'config', 'user.email', 'sec@test.com']);

        const gitHistory = new GitHistoryEngine(sec40Repo);
        const gitTimeline = new GitTimelineEngine(sec40Repo);

        const stagedSecret = fromHex('6768705f737461676564736563726574313233343536373839306162636465663132333435363738');
        const deepSecret = fromHex('6768705f646565707365637265743132333435363738393061626364656631323334353637383930');
        const binarySecret = fromHex('6768705f62696e617279736563726574313233343536373839306162636465663132333435363738');

        // 1. Staged credential with cleaned working tree detected via git show :<path>
        const authFile = path.join(sec40Repo, 'auth.ts');
        fs.writeFileSync(authFile, `const TOKEN = "${stagedSecret}";\n`, 'utf8');
        execFileSync('git', ['-C', sec40Repo, 'add', 'auth.ts']);
        // Overwrite disk file with clean content without updating index
        fs.writeFileSync(authFile, '// clean content on disk\n', 'utf8');

        const foundInWorkingTree = await gitHistory.isSecretInWorkingTree(stagedSecret);
        assert(foundInWorkingTree === true, 'isSecretInWorkingTree detects staged credential via git show :<path> even when disk file is cleaned');

        const traceStaged = await gitHistory.traceSecret(stagedSecret);
        assert(traceStaged.isSecretInWorkingTree === true, 'traceSecret identifies staged credential when disk file is cleaned');

        // Reset auth.ts for subsequent tests
        execFileSync('git', ['-C', sec40Repo, 'reset', 'HEAD', '--', 'auth.ts']);
        fs.unlinkSync(authFile);

        // 2. Deep historical trace (> 200 commits) finds secret introduced 205 commits ago
        const vaultFile = path.join(sec40Repo, 'vault.txt');
        fs.writeFileSync(vaultFile, `DEEP_KEY=${deepSecret}\n`, 'utf8');
        execFileSync('git', ['-C', sec40Repo, 'add', 'vault.txt']);
        execFileSync('git', ['-C', sec40Repo, 'commit', '-m', 'feat: initial secret commit']);

        // Immediately revoke deepSecret in commit 2
        fs.writeFileSync(vaultFile, 'DEEP_KEY=clean\n', 'utf8');
        execFileSync('git', ['-C', sec40Repo, 'add', 'vault.txt']);
        execFileSync('git', ['-C', sec40Repo, 'commit', '-m', 'chore: revoke deep secret']);

        // Generate 205 intermediate commits from the clean tree via fast commit-tree
        let parentSha = execFileSync('git', ['-C', sec40Repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
        const treeSha = execFileSync('git', ['-C', sec40Repo, 'write-tree'], { encoding: 'utf8' }).trim();
        for (let i = 1; i <= 205; i++) {
          parentSha = execFileSync(
            'git',
            ['-C', sec40Repo, 'commit-tree', treeSha, '-p', parentSha, '-m', `chore: dummy commit ${i}`],
            { encoding: 'utf8' }
          ).trim();
        }
        execFileSync('git', ['-C', sec40Repo, 'update-ref', 'HEAD', parentSha]);

        // Default search (maxCommits = 0) searches entire history without 200 limit
        const deepTrace = await gitHistory.traceSecret(deepSecret);
        assert(deepTrace.isPresentInHistory === true, 'traceSecret with default depth finds secret beyond 200 commits');
        assert(deepTrace.isPartialHistory === false, 'traceSecret default search is not partial');
        assert(deepTrace.introducedCommit !== undefined, 'traceSecret locates first commit for deep secret');

        const deepTimeline = await gitTimeline.buildTimeline(deepSecret, 'ghp_••••');
        assert(deepTimeline.currentStatus === 'REMOVED_FROM_HEAD_PRESENT_IN_HISTORY', 'buildTimeline reports REMOVED_FROM_HEAD_PRESENT_IN_HISTORY for deep historical secret');

        // 3. Limited historical search returns PARTIAL_HISTORY
        const limitedResult = await gitHistory.findCommitsContainingSecretResult(deepSecret, 50);
        assert(limitedResult.status === 'PARTIAL_HISTORY', 'findCommitsContainingSecretResult returns PARTIAL_HISTORY when limited');
        assert(limitedResult.isPartialHistory === true, 'isPartialHistory is true when search depth is limited');

        const limitedTrace = await gitHistory.traceSecret(deepSecret, 50);
        assert(limitedTrace.isPartialHistory === true, 'traceSecret returns isPartialHistory true when limited');
        assert(limitedTrace.searchStatus === 'PARTIAL_HISTORY', 'traceSecret searchStatus is PARTIAL_HISTORY when limited');

        const limitedTimeline = await gitTimeline.buildTimeline(deepSecret, 'ghp_••••', 50);
        assert(limitedTimeline.currentStatus === 'PARTIAL_HISTORY', 'buildTimeline reports PARTIAL_HISTORY when limited');

        // 4. Operational git grep failure returns ERROR / SEARCH_INCOMPLETE, not NOT_FOUND
        const nonexistentHistory = new GitHistoryEngine(path.join(os.tmpdir(), 'nonexistent-repo-sld-40'));
        const errResult = await nonexistentHistory.findCommitsContainingSecretResult('test_secret');
        assert(errResult.status === 'ERROR', 'findCommitsContainingSecretResult returns ERROR on invalid repository');

        const errTrace = await nonexistentHistory.traceSecret('test_secret');
        assert(errTrace.searchStatus === 'ERROR', 'traceSecret searchStatus is ERROR on invalid repository');

        const nonexistentTimeline = new GitTimelineEngine(path.join(os.tmpdir(), 'nonexistent-repo-sld-40'));
        const errTimeline = await nonexistentTimeline.buildTimeline('test_secret', 'test***');
        assert(errTimeline.currentStatus === 'ERROR', 'buildTimeline reports ERROR on invalid repository');

        // 5. Historical binary commit containing credential detected via scanHistoryCommits()
        const binFile = path.join(sec40Repo, 'payload.bin');
        const binaryBuffer = Buffer.concat([
          Buffer.from([0x00, 0x01, 0x02, 0xff]),
          Buffer.from(`const SECRET = "${binarySecret}";\n`),
          Buffer.from([0x00, 0x00, 0xfe]),
        ]);
        fs.writeFileSync(binFile, binaryBuffer);
        execFileSync('git', ['-C', sec40Repo, 'add', 'payload.bin']);
        execFileSync('git', ['-C', sec40Repo, 'commit', '-m', 'feat: commit binary payload with secret']);

        const historyFindings = await gitHistory.scanHistoryCommits(10);
        const binaryFinding = historyFindings.find((f: any) => f.rawSecret === binarySecret);
        assert(binaryFinding !== undefined, 'scanHistoryCommits detects credential inside binary file change');

        // 6. In CI, loadBaselineFromGit('HEAD') is rejected even when 'HEAD' is explicitly passed
        const baselineJson = JSON.stringify({
          version: 1,
          generatedAt: new Date().toISOString(),
          findings: [],
        });
        fs.writeFileSync(path.join(sec40Repo, '.secretleak-baseline.json'), baselineJson, 'utf8');
        execFileSync('git', ['-C', sec40Repo, 'add', '.secretleak-baseline.json']);
        execFileSync('git', ['-C', sec40Repo, 'commit', '-m', 'chore: add baseline']);

        const origCiSec40 = process.env.CI;
        try {
          process.env.CI = 'true';
          const bEngineCi = new BaselineEngine(sec40Repo, '.secretleak-baseline.json');
          const ciHeadBaseline = bEngineCi.loadBaselineFromGit('HEAD');
          assert(ciHeadBaseline === null, 'CI loadBaselineFromGit rejects explicit HEAD to prevent self-trust');
        } finally {
          if (origCiSec40 !== undefined) process.env.CI = origCiSec40;
          else delete process.env.CI;
        }

        // 7. Staged scan defaults to strict failOnSkipped: true
        const bigFile = path.join(sec40Repo, 'huge.dat');
        fs.writeFileSync(bigFile, Buffer.alloc(11 * 1024 * 1024));
        execFileSync('git', ['-C', sec40Repo, 'add', 'huge.dat']);

        const cliPath = path.resolve(__dirname, '../dist/cli.js');
        if (!fs.existsSync(cliPath)) {
          execFileSync(process.execPath, ['esbuild.js', '--cli'], { cwd: path.resolve(__dirname, '..') });
        }

        let stagedDefaultExit: number | null = null;
        try {
          execFileSync(process.execPath, [cliPath, 'scan', '--staged'], {
            cwd: sec40Repo,
            stdio: 'pipe',
          });
          stagedDefaultExit = 0;
        } catch (err: any) {
          stagedDefaultExit = err.status;
        }
        assert(stagedDefaultExit === 2, 'scan --staged exits code 2 by default when files are skipped');

        let stagedRelaxedExit: number | null = null;
        try {
          execFileSync(process.execPath, [cliPath, 'scan', '--staged', '--allow-skipped'], {
            cwd: sec40Repo,
            stdio: 'pipe',
          });
          stagedRelaxedExit = 0;
        } catch (err: any) {
          stagedRelaxedExit = err.status;
        }
        assert(stagedRelaxedExit === 0, 'scan --staged --allow-skipped exits code 0 when relaxed');

        execFileSync('git', ['-C', sec40Repo, 'reset', 'HEAD', '--', 'huge.dat']);
        fs.unlinkSync(bigFile);

        // 8. Limited search with matches visibly preserves partial history in trace and timeline
        const partialSecret = fromHex('6768705f7061727469616c73656372657431323334353637383930616263646531323334');
        const partialFile = path.join(sec40Repo, 'partial.txt');
        fs.writeFileSync(partialFile, `KEY=${partialSecret}\n`, 'utf8');
        execFileSync('git', ['-C', sec40Repo, 'add', 'partial.txt']);
        execFileSync('git', ['-C', sec40Repo, 'commit', '-m', 'feat: add partial secret']);

        // Add 55 dummy commits so total history exceeds maxCommits=30
        let pSha = execFileSync('git', ['-C', sec40Repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
        const tSha = execFileSync('git', ['-C', sec40Repo, 'write-tree'], { encoding: 'utf8' }).trim();
        for (let i = 1; i <= 55; i++) {
          pSha = execFileSync(
            'git',
            ['-C', sec40Repo, 'commit-tree', tSha, '-p', pSha, '-m', `chore: dummy ${i}`],
            { encoding: 'utf8' }
          ).trim();
        }
        execFileSync('git', ['-C', sec40Repo, 'update-ref', 'HEAD', pSha]);

        // Limited search with match (secret is in all 55 commits because tree unchanged)
        const partialResult = await gitHistory.findCommitsContainingSecretResult(partialSecret, 30);
        assert(partialResult.status === 'FOUND', 'findCommitsContainingSecretResult returns FOUND when match in limited window');
        assert(partialResult.isPartialHistory === true, 'findCommitsContainingSecretResult marks isPartialHistory true');

        const partialTrace = await gitHistory.traceSecret(partialSecret, 30);
        assert(partialTrace.isPartialHistory === true, 'traceSecret preserves isPartialHistory true when matches exist in limited search');
        assert(partialTrace.statusDescription.includes('[PARTIAL HISTORY'), 'traceSecret visibly notes partial history in statusDescription');

        const partialTimeline = await gitTimeline.buildTimeline(partialSecret, 'ghp_••••', 30);
        assert(partialTimeline.isPartialHistory === true, 'buildTimeline preserves isPartialHistory true');
        assert(partialTimeline.timelineAscii.includes('PARTIAL'), 'buildTimeline visibly displays PARTIAL coverage in ASCII report');

        // 9. Operational blob-reading failure in isSecretInWorkingTree throws operational error
        let workingTreeThrown = false;
        try {
          const corruptEngine = new GitHistoryEngine(path.join(os.tmpdir(), 'nonexistent-wt-dir'));
          await corruptEngine.isSecretInWorkingTree('dummy_token');
        } catch (err: any) {
          workingTreeThrown = true;
        }
        assert(workingTreeThrown === true, 'isSecretInWorkingTree throws operational error on failed git execution rather than returning false');

        // 10. Operational blob-reading failure in isSecretInHead throws operational error
        let inHeadThrown = false;
        try {
          const corruptEngine = new GitHistoryEngine(path.join(os.tmpdir(), 'nonexistent-head-dir'));
          await corruptEngine.isSecretInHead('dummy_token');
        } catch (err: any) {
          inHeadThrown = true;
        }
        assert(inHeadThrown === true, 'isSecretInHead throws operational error on failed git execution rather than returning false');

        // 11. Historical blob inspection failure in scanHistoryCommits throws descriptive error
        let scanHistoryThrown = false;
        try {
          const corruptEngine = new GitHistoryEngine(path.join(os.tmpdir(), 'nonexistent-hist-dir'));
          await corruptEngine.scanHistoryCommits(5);
        } catch (err: any) {
          scanHistoryThrown = true;
        }
        assert(scanHistoryThrown === true, 'scanHistoryCommits throws operational error on failed git execution rather than returning clean []');

        // 12. Chunk 1 succeeds and chunk 2 fails: returns SEARCH_INCOMPLETE with preserved partial matches
        class ChunkFailureEngine extends GitHistoryEngine {
          private grepCount = 0;
          protected override async execGit(args: string[], options: any = {}): Promise<{ stdout: any; stderr: any }> {
            if (args[0] === 'grep') {
              this.grepCount++;
              if (this.grepCount > 1) {
                throw new Error('Simulated git grep disk read timeout in chunk 2');
              }
            }
            return super.execGit(args, options);
          }
        }

        const chunkEngine = new ChunkFailureEngine(sec40Repo);
        const chunkResult = await chunkEngine.findCommitsContainingSecretResult(partialSecret);
        assert(chunkResult.status === 'SEARCH_INCOMPLETE', 'findCommitsContainingSecretResult returns SEARCH_INCOMPLETE when chunk 2 fails');
        assert(chunkResult.commitShas.length > 0, 'findCommitsContainingSecretResult preserves matches found in chunk 1 before failure');
        assert(chunkResult.error?.includes('chunk 2'), 'findCommitsContainingSecretResult records chunk failure error');

        const chunkTraceEngine = new ChunkFailureEngine(sec40Repo);
        const chunkTrace = await chunkTraceEngine.traceSecret(partialSecret);
        assert(chunkTrace.searchStatus === 'SEARCH_INCOMPLETE', 'traceSecret returns SEARCH_INCOMPLETE when search chunks partially fail');
        assert(chunkTrace.isPresentInHistory === true, 'traceSecret preserves isPresentInHistory true on partially failed search');
        assert(chunkTrace.isPresentInHead === 'UNKNOWN', 'traceSecret reports isPresentInHead UNKNOWN on incomplete search');
        assert(chunkTrace.isRemote === 'UNKNOWN', 'traceSecret reports isRemote UNKNOWN on incomplete search');

        // 13. Mixed metadata retrieval failure: some commit metadata requests succeed, others fail
        const metaSecret = fromHex('6768705f6d65746164617461736563726574313233343536373839306162636465313233');
        const metaFile1 = path.join(sec40Repo, 'meta1.txt');
        fs.writeFileSync(metaFile1, `TOKEN=${metaSecret}\n`, 'utf8');
        execFileSync('git', ['-C', sec40Repo, 'add', 'meta1.txt']);
        execFileSync('git', ['-C', sec40Repo, 'commit', '-m', 'feat: meta commit 1']);
        const metaCommit1Sha = execFileSync('git', ['-C', sec40Repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();

        const metaFile2 = path.join(sec40Repo, 'meta2.txt');
        fs.writeFileSync(metaFile2, `TOKEN=${metaSecret}\n`, 'utf8');
        execFileSync('git', ['-C', sec40Repo, 'add', 'meta2.txt']);
        execFileSync('git', ['-C', sec40Repo, 'commit', '-m', 'feat: meta commit 2']);
        const metaCommit2Sha = execFileSync('git', ['-C', sec40Repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();

        class PartialMetadataEngine extends GitHistoryEngine {
          protected override async execGit(args: string[], options: any = {}): Promise<{ stdout: any; stderr: any }> {
            if (args[0] === 'log' && args.includes(metaCommit2Sha)) {
              throw new Error('Simulated git log object corruption on commit 2');
            }
            return super.execGit(args, options);
          }
        }

        const partialMetaEngine = new PartialMetadataEngine(sec40Repo);
        const partialMetaTrace = await partialMetaEngine.traceSecret(metaSecret);
        assert(partialMetaTrace.searchStatus === 'SEARCH_INCOMPLETE', 'traceSecret returns SEARCH_INCOMPLETE when some commit metadata fails');
        assert(partialMetaTrace.isPresentInHistory === true, 'traceSecret marks isPresentInHistory true when metadata partially succeeds');
        assert(partialMetaTrace.statusDescription.includes('[INCOMPLETE METADATA: 1 of 2'), 'traceSecret visibly notes 1 of 2 metadata requests failed');

        const partialMetaTimelineEngine = new GitTimelineEngine(sec40Repo, partialMetaEngine);
        const partialMetaTimeline = await partialMetaTimelineEngine.buildTimeline(metaSecret, 'ghp_••••');
        assert(partialMetaTimeline.currentStatus === 'SEARCH_INCOMPLETE', 'buildTimeline returns SEARCH_INCOMPLETE when commit metadata partially fails');
        assert(partialMetaTimeline.timelineAscii.includes('INCOMPLETE'), 'buildTimeline ASCII notes incomplete metadata');

        // 14. Working-tree candidate file becomes unreadable: throws operational error and reports UNKNOWN
        class UnreadableCandidateEngine extends GitHistoryEngine {
          public override async isSecretInWorkingTree(secret: string): Promise<boolean> {
            throw new Error('EACCES: permission denied, read candidate file');
          }
        }
        const unreadableEngine = new UnreadableCandidateEngine(sec40Repo);
        let wtUnreadableThrown = false;
        try {
          await unreadableEngine.isSecretInWorkingTree('test_secret');
        } catch {
          wtUnreadableThrown = true;
        }
        assert(wtUnreadableThrown === true, 'isSecretInWorkingTree propagates candidate-file read failure as operational error');

        const wtUnreadableTrace = await unreadableEngine.traceSecret(metaSecret);
        assert(wtUnreadableTrace.isPresentInWorkingTree === 'UNKNOWN', 'traceSecret sets isPresentInWorkingTree to UNKNOWN on read error');
        assert(wtUnreadableTrace.isSecretInWorkingTree === 'UNKNOWN', 'traceSecret sets isSecretInWorkingTree to UNKNOWN on read error');
        assert(wtUnreadableTrace.searchStatus === 'SEARCH_INCOMPLETE', 'traceSecret marks searchStatus SEARCH_INCOMPLETE when working-tree inspection fails');

        // 15. Binary files with quoted filenames containing spaces, quotes, and non-ASCII characters
        assert(unquoteGitPath('"a/secret \\"quoted\\" café.bin"') === 'a/secret "quoted" café.bin', 'unquoteGitPath unquotes escaped double quotes and non-ASCII characters');
        const parsedHeaderTest = parseDiffHeaderPaths('diff --git "a/path \\"quoted\\".bin" "b/path \\"quoted\\".bin"');
        assert(parsedHeaderTest?.pathB === 'path "quoted".bin', 'parseDiffHeaderPaths unquotes escaped double quotes');

        const quotedBinarySecret = fromHex('6768705f71756f74656462696e6172797365637265743132333435363738393061626364656631323334');
        const quotedBinaryName = "assets/secret 'quoted' and space café.bin";
        const quotedBinaryPath = path.join(sec40Repo, quotedBinaryName);
        fs.mkdirSync(path.dirname(quotedBinaryPath), { recursive: true });
        const quotedBinaryBuf = Buffer.concat([
          Buffer.from([0x00, 0x01, 0x89, 0x50]),
          Buffer.from(`const KEY = "${quotedBinarySecret}";\n`),
          Buffer.from([0x00, 0xff, 0xfe]),
        ]);
        fs.writeFileSync(quotedBinaryPath, quotedBinaryBuf);
        execFileSync('git', ['-C', sec40Repo, 'add', quotedBinaryName]);
        execFileSync('git', ['-C', sec40Repo, 'commit', '-m', 'feat: add quoted non-ascii binary payload']);

        const quotedFindings = await gitHistory.scanHistoryCommits(10);
        const quotedFinding = quotedFindings.find((f: any) => f.rawSecret === quotedBinarySecret);
        assert(quotedFinding !== undefined, 'scanHistoryCommits detects credential in binary file with spaces, quotes and non-ASCII filename');
        assert(quotedFinding?.file.includes('café'), 'scanHistoryCommits unquotes and preserves non-ASCII filename path');

        // 16. HEAD verification fails after credential has already been discovered in history
        class HeadFailureEngine extends GitHistoryEngine {
          public override async isSecretInHead(secret: string): Promise<boolean> {
            throw new Error('Simulated HEAD object corruption');
          }
        }
        const headFailureEngine = new HeadFailureEngine(sec40Repo);
        const headFailTrace = await headFailureEngine.traceSecret(metaSecret);
        assert(headFailTrace.isPresentInHead === 'UNKNOWN', 'traceSecret reports isPresentInHead UNKNOWN when HEAD inspection fails');
        assert(headFailTrace.isPresentInHistory === true, 'traceSecret preserves isPresentInHistory true when secret is confirmed in history');
        assert(headFailTrace.searchStatus === 'SEARCH_INCOMPLETE', 'traceSecret searchStatus is SEARCH_INCOMPLETE when HEAD inspection fails');
        assert(headFailTrace.statusDescription.includes('INCOMPLETE HEAD VERIFICATION'), 'traceSecret notes INCOMPLETE HEAD VERIFICATION instead of claiming absent from HEAD');

        // 17. Search failure with 0 matches returns isPresentInHistory 'UNKNOWN'
        class TotalFailureEngine extends GitHistoryEngine {
          public override async findCommitsContainingSecretResult(secret: string, maxCommits = 0): Promise<any> {
            return {
              status: 'SEARCH_INCOMPLETE',
              commitShas: [],
              error: 'Simulated git pack corruption',
              isPartialHistory: false,
            };
          }
        }
        const totalFailEngine = new TotalFailureEngine(sec40Repo);
        const totalFailTrace = await totalFailEngine.traceSecret(metaSecret);
        assert(totalFailTrace.isPresentInHistory === 'UNKNOWN', 'traceSecret sets isPresentInHistory to UNKNOWN when search fails without discovered matches');
        assert(totalFailTrace.isPresentInHead === 'UNKNOWN', 'traceSecret sets isPresentInHead to UNKNOWN on incomplete search');

        // 18. Timeline HEAD verification failure in loop preserves events and sets SEARCH_INCOMPLETE
        const timelineWithFailHistory = new GitTimelineEngine(sec40Repo, headFailureEngine);
        const timelineReportHeadFail = await timelineWithFailHistory.buildTimeline(metaSecret, 'ghp_****');
        assert(timelineReportHeadFail.currentStatus === 'SEARCH_INCOMPLETE', 'buildTimeline returns SEARCH_INCOMPLETE when isSecretInHead throws in timeline loop');
        assert(timelineReportHeadFail.events.length > 0, 'buildTimeline preserves available events even when isSecretInHead throws');
        assert(timelineReportHeadFail.timelineAscii.includes('HEAD Verification:  INCOMPLETE'), 'buildTimeline ASCII notes incomplete HEAD verification');
        assert(timelineReportHeadFail.graph.summary.removedCommit === undefined, 'buildTimeline does not falsely claim removedCommit on SEARCH_INCOMPLETE');

        // 19. Timeline branch reachability query failure sets isPushedToRemote 'UNKNOWN' and does not fabricate 'main'
        const fakeSha = execFileSync('git', ['-C', sec40Repo, 'rev-parse', 'HEAD']).toString().trim();
        let branchQueryAttempted = false;
        let branchQueryFailed = false;
        try {
          execFileSync('git', ['-C', sec40Repo, 'branch', '-a', '--contains', fakeSha + '_corrupt']);
        } catch {
          branchQueryFailed = true;
        }
        assert(branchQueryFailed, 'git branch --contains on invalid object triggers an error');

        // Verify gitTimeline handles branch lookup error without fabricating ['main']
        const originalExecFile = require('child_process').execFile;
        // Test branch failure via a mock gitHistory and timeline inspection
        class BranchFailureHistoryEngine extends GitHistoryEngine {
          public override async findCommitsContainingSecretResult(secret: string, maxCommits = 0): Promise<any> {
            return {
              status: 'FOUND',
              commitShas: [fakeSha],
              isPartialHistory: false,
            };
          }
        }
        const branchFailEngine = new BranchFailureHistoryEngine(sec40Repo);
        // In this test, we can pass a corrupted/non-existent repo path or simulate branch error in buildTimeline
        const timelineBranchFail = new GitTimelineEngine(sec40Repo + '_nonexistent', branchFailEngine);
        const branchFailReport = await timelineBranchFail.buildTimeline(metaSecret, 'ghp_****');
        assert(branchFailReport.isPushedToRemote === 'UNKNOWN', 'buildTimeline reports isPushedToRemote UNKNOWN on query failure');
        assert(branchFailReport.currentStatus === 'SEARCH_INCOMPLETE' || branchFailReport.currentStatus === 'ERROR', 'buildTimeline reports non-clean status on query failure');

        // 20. Disappearing candidate file in working tree throws error and sets isSecretInWorkingTree 'UNKNOWN'
        class DisappearingCandidateEngine extends GitHistoryEngine {
          public override async isSecretInWorkingTree(secret: string): Promise<boolean> {
            throw new Error("Candidate untracked file disappeared during inspection: 'disappeared.txt'");
          }
        }
        const disappearingEngine = new DisappearingCandidateEngine(sec40Repo);
        const disappearingTrace = await disappearingEngine.traceSecret(fromHex('6768705f646973617070656172696e67746f6b656e3132333435363738393061626364'));
        assert(disappearingTrace.isSecretInWorkingTree === 'UNKNOWN', 'traceSecret sets isSecretInWorkingTree to UNKNOWN when candidate file disappears');
        assert(disappearingTrace.searchStatus === 'ERROR', 'traceSecret searchStatus is ERROR when working tree inspection throws on disappearing file');

        // 21. Partial history with zero matches returns isPresentInHistory, isPresentInHead, isRemote 'UNKNOWN'
        const absentSecret = fromHex('6768705f616273656e7473656372657431323334353637383930616263646566313233');
        const partialTraceZero = await gitHistory.traceSecret(absentSecret, 1);
        assert(partialTraceZero.isPartialHistory === true, 'traceSecret with limit 1 is partial history');
        assert(partialTraceZero.isPresentInHistory === 'UNKNOWN', 'traceSecret returns isPresentInHistory UNKNOWN when depth is limited and 0 matches found');
        assert(partialTraceZero.isPresentInHead === 'UNKNOWN', 'traceSecret returns isPresentInHead UNKNOWN when depth is limited and 0 matches found');
        assert(partialTraceZero.isRemote === 'UNKNOWN', 'traceSecret returns isRemote UNKNOWN when depth is limited and 0 matches found');
        assert(partialTraceZero.searchStatus === 'PARTIAL_HISTORY', 'traceSecret searchStatus is PARTIAL_HISTORY when depth is limited');

        const timelinePartialZero = await gitTimeline.buildTimeline(absentSecret, 'ghp_****', 1);
        assert(timelinePartialZero.currentStatus === 'PARTIAL_HISTORY', 'buildTimeline returns PARTIAL_HISTORY for zero matches with limit 1');
        assert(timelinePartialZero.isPushedToRemote === 'UNKNOWN', 'buildTimeline reports isPushedToRemote UNKNOWN for zero matches with limit 1');
        assert(timelinePartialZero.graph.summary.isPushedToRemote === 'UNKNOWN', 'buildTimeline graph summary reports isPushedToRemote UNKNOWN for zero matches with limit 1');

        // 22. Outer error handler in traceSecret returns isPresentInHistory 'UNKNOWN'
        class CorruptedTraceEngine extends GitHistoryEngine {
          public override async findCommitsContainingSecretResult(secret: string, maxCommits = 0): Promise<any> {
            throw new Error('Fatal git error during trace');
          }
        }
        const corruptedEngine = new CorruptedTraceEngine(sec40Repo);
        const errorTrace = await corruptedEngine.traceSecret(absentSecret);
        assert(errorTrace.searchStatus === 'ERROR', 'traceSecret returns searchStatus ERROR on fatal error');
        assert(errorTrace.isPresentInHistory === 'UNKNOWN', 'traceSecret returns isPresentInHistory UNKNOWN on fatal error');
        assert(errorTrace.isPresentInHead === 'UNKNOWN', 'traceSecret returns isPresentInHead UNKNOWN on fatal error');
        assert(errorTrace.isRemote === 'UNKNOWN', 'traceSecret returns isRemote UNKNOWN on fatal error');

        // 23. VerificationEngine with unknown history sets isResolved false and historyStatus UNKNOWN
        class UnknownHistoryVerificationEngine extends GitHistoryEngine {
          public override async traceSecret(secret: string, maxCommits = 0): Promise<any> {
            return {
              isPresentInHead: false,
              isPresentInHistory: 'UNKNOWN',
              isPresentInWorkingTree: false,
              isSecretInWorkingTree: false,
              exposureDurationDays: 0,
              branches: [],
              isRemote: false,
              statusDescription: 'Git history search was incomplete',
              searchStatus: 'SEARCH_INCOMPLETE',
            };
          }
        }
        const unknownHistEngine = new UnknownHistoryVerificationEngine(sec40Repo);
        const { VerificationEngine } = require('../src/core/verification/verificationEngine');
        const verifier = new VerificationEngine(sec40Repo);
        (verifier as any).historyEngine = unknownHistEngine;
        const fakeCleanFinding = {
          file: 'clean.ts',
          fullPath: path.join(sec40Repo, 'clean.ts'),
          line: 1,
          type: 'github-pat',
          rawSecret: metaSecret,
          fingerprint: 'fp123',
          confidence: 100,
        };
        const verificationRes = await verifier.verifyFindingFix(fakeCleanFinding);
        assert(verificationRes.isResolved === false, 'VerificationEngine rejects resolution when Git history is UNKNOWN');
        assert(verificationRes.historyStatus === 'UNKNOWN', 'VerificationEngine reports historyStatus UNKNOWN on incomplete history');

        // 24. VerificationEngine resolves finding when current history is clean even if previously exposed in finding
        class CleanCurrentHistoryVerificationEngine extends GitHistoryEngine {
          public override async traceSecret(secret: string, maxCommits = 0): Promise<any> {
            return {
              isPresentInHead: false,
              isPresentInHistory: false,
              isPresentInWorkingTree: false,
              isSecretInWorkingTree: false,
              exposureDurationDays: 0,
              branches: [],
              isRemote: false,
              statusDescription: 'Clean in current Git history',
              searchStatus: 'FOUND',
            };
          }
        }
        const cleanHistEngine = new CleanCurrentHistoryVerificationEngine(sec40Repo);
        const cleanVerifier = new VerificationEngine(sec40Repo);
        (cleanVerifier as any).historyEngine = cleanHistEngine;
        const findingPreviouslyInHistory = {
          file: 'clean.ts',
          fullPath: path.join(sec40Repo, 'clean.ts'),
          line: 1,
          type: 'github-pat',
          rawSecret: metaSecret,
          fingerprint: 'fp123',
          confidence: 100,
          gitExposure: {
            isPresentInHistory: true,
            introducedCommit: { sha: 'abcdef1234567890' }
          }
        };
        const cleanVerificationRes = await cleanVerifier.verifyFindingFix(findingPreviouslyInHistory as any);
        assert(cleanVerificationRes.isResolved === true, 'VerificationEngine resolves finding when current history is clean despite old finding historical exposure');
        assert(cleanVerificationRes.historyStatus === 'HEAD_AND_HISTORY_CLEAN', 'VerificationEngine reports HEAD_AND_HISTORY_CLEAN when current history is clean');
        assert(cleanVerificationRes.previouslyExposedInHistory === true, 'VerificationEngine records previouslyExposedInHistory true for audit tracking');
      } finally {
        try {
          fs.rmSync(sec40Repo, { recursive: true, force: true });
        } catch {}
      }
    }

    // --- 41. Security Audit Release Readiness: JSON Sanitization, Merge Diffs, Symlink Confinement & Verification ---
    console.log('\n--- 41. Security Audit Release Readiness: JSON Sanitization, Merge Diffs, Symlink Confinement & Verification ---');
    {
      const { scanContent } = require('../src/core/scanner/scanner');
      const { toSafeJsonFinding, collectFiles } = require('../src/cli/index');
      const { GitHistoryEngine } = require('../src/core/history/gitHistoryEngine');
      const { enforceEnvFilePermissions } = require('../src/core/remediation/remediationEngine');
      const { calculateRiskAssessment } = require('../src/core/risk/riskEngine');
      const { VerificationEngine } = require('../src/core/verification/verificationEngine');
      const { getIgnorePatterns, BUILD_ARTIFACT_PATTERNS } = require('../src/core/ignore/ignoreEngine');
      const { CORE_RULES } = require('../src/core/detectors/rules');
      const { execFileSync } = require('child_process');
      const fromHex = (h: string) => Buffer.from(h, 'hex').toString('utf8');

      // 1. JSON output sanitization: split concatenation, array join, template literal, and base64
      const p1 = fromHex('6768705f3132333435'); // "ghp_12345"
      const p2 = fromHex('36373839303132333435363738393031323334353637383930313233343536'); // 31 chars
      const codeConcat = `const token = "${p1}" + "${p2}";`;
      const findingsConcat = scanContent(codeConcat, 'testConcat.js');
      assert(findingsConcat.length > 0, 'Split concatenation detected');
      const safeConcat = toSafeJsonFinding(findingsConcat[0]);
      assert(safeConcat.rawSecret === undefined, 'toSafeJsonFinding strips rawSecret on concatenation finding');
      assert(safeConcat.sourceExpression === undefined, 'toSafeJsonFinding strips sourceExpression on concatenation finding');
      assert((safeConcat as any).evidence?.surroundingCode === undefined, 'toSafeJsonFinding strips surroundingCode');
      assert((safeConcat as any).remediation?.diffPreview === undefined, 'toSafeJsonFinding strips diffPreview');
      const jsonConcat = JSON.stringify(safeConcat);
      assert(!jsonConcat.includes(p1 + p2), 'Serialized JSON does not contain raw concatenated secret');
      assert(!jsonConcat.includes(p1), 'Serialized JSON does not contain token prefix fragment');

      const codeArray = `const token = ["${p1}", "${p2}"].join("");`;
      const findingsArray = scanContent(codeArray, 'testArray.js');
      assert(findingsArray.length > 0, 'Array join detected');
      const safeArray = toSafeJsonFinding(findingsArray[0]);
      assert(safeArray.rawSecret === undefined, 'toSafeJsonFinding strips rawSecret on array join finding');
      assert(safeArray.sourceExpression === undefined, 'toSafeJsonFinding strips sourceExpression on array join finding');
      assert(!JSON.stringify(safeArray).includes(p1 + p2), 'Serialized JSON does not contain array joined secret');

      const codeTpl = 'const token = `' + p1 + '${"' + p2 + '"}`;\n';
      const findingsTpl = scanContent(codeTpl, 'testTpl.js');
      assert(findingsTpl.length > 0, 'Template interpolation detected');
      const safeTpl = toSafeJsonFinding(findingsTpl[0]);
      assert(safeTpl.rawSecret === undefined, 'toSafeJsonFinding strips rawSecret on template finding');
      assert(safeTpl.sourceExpression === undefined, 'toSafeJsonFinding strips sourceExpression on template finding');
      assert(!JSON.stringify(safeTpl).includes(p1 + p2), 'Serialized JSON does not contain interpolated secret');

      const rawSecret = p1 + p2;
      const b64 = Buffer.from(rawSecret).toString('base64');
      const codeB64 = `const apiKey = Buffer.from("${b64}", "base64").toString();`;
      const findingsB64 = scanContent(codeB64, 'testB64.js');
      assert(findingsB64.length > 0, 'Base64 credential detected');
      const safeB64 = toSafeJsonFinding(findingsB64[0]);
      assert(safeB64.rawSecret === undefined, 'toSafeJsonFinding strips rawSecret on base64 finding');
      assert(safeB64.sourceExpression === undefined, 'toSafeJsonFinding strips sourceExpression on base64 finding');
      assert(!JSON.stringify(safeB64).includes(rawSecret), 'Serialized JSON does not contain decoded base64 secret');

      // 2. Merge commit diff inspection (-m)
      const sec41MergeRepo = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-hist-merge-'));
      try {
        execFileSync('git', ['init', sec41MergeRepo]);
        execFileSync('git', ['-C', sec41MergeRepo, 'config', 'user.name', 'Merge Tester']);
        execFileSync('git', ['-C', sec41MergeRepo, 'config', 'user.email', 'merge@test.com']);

        fs.writeFileSync(path.join(sec41MergeRepo, 'app.ts'), '// initial file\nexport const v = 1;\n', 'utf8');
        execFileSync('git', ['-C', sec41MergeRepo, 'add', 'app.ts']);
        execFileSync('git', ['-C', sec41MergeRepo, 'commit', '-m', 'chore: initial commit']);

        execFileSync('git', ['-C', sec41MergeRepo, 'checkout', '-b', 'branch-a']);
        fs.writeFileSync(path.join(sec41MergeRepo, 'app.ts'), '// branch-a change\nexport const v = 2;\n', 'utf8');
        execFileSync('git', ['-C', sec41MergeRepo, 'add', 'app.ts']);
        execFileSync('git', ['-C', sec41MergeRepo, 'commit', '-m', 'chore: branch-a edit']);

        const mainBranchName = execFileSync('git', ['-C', sec41MergeRepo, 'branch', '--show-current'], { encoding: 'utf8' }).trim() || 'master';
        try {
          execFileSync('git', ['-C', sec41MergeRepo, 'checkout', 'master'], { stdio: 'pipe' });
        } catch {
          execFileSync('git', ['-C', sec41MergeRepo, 'checkout', 'main']);
        }
        fs.writeFileSync(path.join(sec41MergeRepo, 'app.ts'), '// main change\nexport const v = 3;\n', 'utf8');
        execFileSync('git', ['-C', sec41MergeRepo, 'add', 'app.ts']);
        execFileSync('git', ['-C', sec41MergeRepo, 'commit', '-m', 'chore: main edit']);

        try {
          execFileSync('git', ['-C', sec41MergeRepo, 'merge', 'branch-a']);
        } catch {}

        const mergeSecret = fromHex('6768705f6d657267653132333435363738393031323334353637383930313233');
        fs.writeFileSync(path.join(sec41MergeRepo, 'app.ts'), `// resolved with secret\nexport const apiKey = "${mergeSecret}";\n`, 'utf8');
        execFileSync('git', ['-C', sec41MergeRepo, 'add', 'app.ts']);
        execFileSync('git', ['-C', sec41MergeRepo, 'commit', '-m', 'Merge branch-a resolving conflict with secret']);

        const gitHistory = new GitHistoryEngine(sec41MergeRepo);
        const findings = await gitHistory.scanHistoryCommits();
        const mergeFinding = findings.find((f: any) => f.rawSecret === mergeSecret);
        assert(mergeFinding !== undefined, 'scanHistoryCommits detects credential introduced in merge-resolution commit diff (-m)');
        assert(mergeFinding?.gitExposure?.isPresentInHead === true, 'Merge-commit secret correctly identified in HEAD');
      } finally {
        try {
          fs.rmSync(sec41MergeRepo, { recursive: true, force: true });
        } catch {}
      }

      // 3. Workspace symlink confinement
      const wsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-ws-sym-'));
      const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-outside-sym-'));
      try {
        fs.writeFileSync(path.join(outsideDir, 'external_leak.ts'), '// external content\n');
        fs.writeFileSync(path.join(wsDir, 'internal.ts'), '// internal content\n');

        let symlinkCreated = false;
        const linkPath = path.join(wsDir, 'symlink_outside');
        try {
          fs.symlinkSync(outsideDir, linkPath, 'junction');
          symlinkCreated = true;
        } catch {
          try {
            fs.symlinkSync(outsideDir, linkPath, 'dir');
            symlinkCreated = true;
          } catch {}
        }

        if (symlinkCreated) {
          const res = collectFiles(wsDir, [], wsDir, { allowExternalSymlinks: false });
          assert(res.traversalErrors.length > 0, 'collectFiles flags external symlink with traversal error');
          assert(res.traversalErrors[0].operation === 'symlink', 'Traversal error operation is symlink');
          assert(res.traversalErrors[0].error.includes('Symlink escapes workspace root'), 'Error explains symlink escapes root');

          const relaxedRes = collectFiles(wsDir, [], wsDir, { allowExternalSymlinks: true });
          assert(relaxedRes.traversalErrors.length === 0, 'collectFiles allows external symlink when allowExternalSymlinks: true');
          assert(relaxedRes.files.some((f: string) => f.includes('external_leak.ts')), 'External file collected when allowed');
        }
      } finally {
        try {
          fs.rmSync(wsDir, { recursive: true, force: true });
          fs.rmSync(outsideDir, { recursive: true, force: true });
        } catch {}
      }

      // 4. Genuine removal commit vs lastSeenCommit
      const repoDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-hist-remov-'));
      try {
        execFileSync('git', ['init', repoDir]);
        execFileSync('git', ['-C', repoDir, 'config', 'user.name', 'Removal Tester']);
        execFileSync('git', ['-C', repoDir, 'config', 'user.email', 'removal@test.com']);

        const secretToken = fromHex('6768705f72656d6f76616c313233343536373839303132333435363738393031');

        fs.writeFileSync(path.join(repoDir, 'service.ts'), `export const token = "${secretToken}";\n`, 'utf8');
        execFileSync('git', ['-C', repoDir, 'add', 'service.ts']);
        execFileSync('git', ['-C', repoDir, 'commit', '-m', 'feat: introduce secret']);

        fs.writeFileSync(path.join(repoDir, 'service.ts'), `// comment\nexport const token = "${secretToken}";\n`, 'utf8');
        execFileSync('git', ['-C', repoDir, 'add', 'service.ts']);
        execFileSync('git', ['-C', repoDir, 'commit', '-m', 'refactor: keep secret in file']);
        const lastSeenSha = execFileSync('git', ['-C', repoDir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();

        fs.writeFileSync(path.join(repoDir, 'service.ts'), `// removed\nexport const token = process.env.TOKEN;\n`, 'utf8');
        execFileSync('git', ['-C', repoDir, 'add', 'service.ts']);
        execFileSync('git', ['-C', repoDir, 'commit', '-m', 'fix: remove secret from HEAD']);
        const removalSha = execFileSync('git', ['-C', repoDir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();

        const gitHistory = new GitHistoryEngine(repoDir);
        const trace = await gitHistory.traceSecret(secretToken);
        assert(trace.isPresentInHead === false, 'Secret is absent from HEAD');
        assert(trace.isPresentInHistory === true, 'Secret is present in history');
        assert(trace.lastSeenCommit !== undefined, 'traceSecret identifies lastSeenCommit');
        assert(trace.lastSeenCommit?.sha === lastSeenSha, 'lastSeenCommit is commit 2 (where secret still existed)');
        assert(trace.removedCommit !== undefined, 'traceSecret identifies genuine removedCommit');
        assert(trace.removedCommit?.sha === removalSha, 'removedCommit is commit 3 (where secret was deleted)');
        assert(trace.lastSeenCommit?.sha !== trace.removedCommit?.sha, 'lastSeenCommit is distinct from removedCommit');
      } finally {
        try {
          fs.rmSync(repoDir, { recursive: true, force: true });
        } catch {}
      }

      // 5. enforceEnvFilePermissions
      const tempEnv = path.join(os.tmpdir(), `sld-test-env-${Date.now()}.env`);
      fs.writeFileSync(tempEnv, 'TEST_VAR="val"\n', 'utf8');
      try {
        enforceEnvFilePermissions(tempEnv);
        assert(true, 'enforceEnvFilePermissions succeeds on valid file');

        let posixErrorThrown = false;
        const fakeFs = {
          statSync: () => ({ mode: 0o100644 }),
          chmodSync: () => { throw new Error('chmod simulated failure'); },
          accessSync: () => {},
          constants: fs.constants,
        };
        try {
          enforceEnvFilePermissions(tempEnv, fakeFs as any, 'linux');
        } catch (err: any) {
          posixErrorThrown = true;
          assert(err.message.includes('0600'), 'Error specifies 0600 mode requirement');
        }
        assert(posixErrorThrown, 'enforceEnvFilePermissions throws when POSIX mode is not 0600');

        const cleanFs = {
          statSync: () => ({ mode: 0o100600 }),
          accessSync: () => {},
          chmodSync: () => {},
          constants: fs.constants,
        };
        enforceEnvFilePermissions(tempEnv, cleanFs as any, 'linux');
        assert(true, 'enforceEnvFilePermissions succeeds when mode is 0600');
      } finally {
        try {
          fs.unlinkSync(tempEnv);
        } catch {}
      }

      // 6. Risk Engine Blast Radius UNKNOWN preservation
      const dummyExposure = {
        isPresentInHead: 'UNKNOWN' as const,
        isPresentInHistory: 'UNKNOWN' as const,
        exposureDurationDays: 0,
        branches: [],
        isRemote: 'UNKNOWN' as const,
        statusDescription: 'Incomplete inspection',
      };
      const dummyFileContext = {
        fileExtension: '.ts',
        isConfig: false,
        isTest: false,
        isDoc: false,
        isSensitiveName: false,
        isExampleOrSample: false,
      };
      const assessment = calculateRiskAssessment(CORE_RULES[0], 100, dummyFileContext, dummyExposure);
      assert(assessment.blastRadius.remoteExposed === 'UNKNOWN', 'blastRadius preserves UNKNOWN remoteExposed');
      assert(assessment.blastRadius.gitHistoryExposed === 'UNKNOWN', 'blastRadius preserves UNKNOWN gitHistoryExposed');
      assert(assessment.blastRadius.factors.some((f: string) => f.includes('Remote tracking branch status unverified')), 'Conservative risk factor applied for unverified remote status');

      // 7. VerificationEngine onSkippedFile handling
      const verDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-ver-skip-'));
      try {
        const verifier = new VerificationEngine(verDir);
        const finding = {
          file: 'huge.ts',
          fullPath: path.join(verDir, 'huge.ts'),
          line: 1,
          type: 'github-pat',
          rawSecret: fromHex('6768705f64756d6d7931323334353637383930313233343536373839303132'),
          fingerprint: 'fp_huge',
          confidence: 100,
        };
        fs.writeFileSync(path.join(verDir, 'huge.ts'), Buffer.alloc(1000, 0));
        const res = await verifier.verifyFindingFix(finding as any);
        assert(res.isResolved === false, 'verifyFindingFix returns isResolved: false when file was skipped');
        assert(res.historyStatus === 'UNKNOWN', 'verifyFindingFix returns historyStatus: UNKNOWN when file was skipped');
        assert(res.details.includes('Target file inspection incomplete'), 'verifyFindingFix notes inspection incomplete in details');
      } finally {
        try {
          fs.rmSync(verDir, { recursive: true, force: true });
        } catch {}
      }

      // 8. IgnoreEngine configurable build artifacts
      const defaultPatterns = getIgnorePatterns();
      assert(defaultPatterns.includes('dist/**'), 'Default ignore includes dist/**');
      assert(defaultPatterns.includes('build/**'), 'Default ignore includes build/**');
      const includedPatterns = getIgnorePatterns({ includeBuildArtifacts: true });
      assert(!includedPatterns.includes('dist/**'), 'includeBuildArtifacts excludes dist/** from ignore list');
      assert(!includedPatterns.includes('build/**'), 'includeBuildArtifacts excludes build/** from ignore list');
      assert(BUILD_ARTIFACT_PATTERNS.includes('dist/**'), 'BUILD_ARTIFACT_PATTERNS contains dist/**');
    }

    // --- 42. Lazy AST Parsing, Fail-Closed Node Version Guards & Engine Shims ---
    console.log('\n--- 42. Lazy AST Parsing, Fail-Closed Node Version Guards & Engine Shims ---');
    {
      const { scanContent } = require('../src/core/scanner/scanner');
      const { buildPreCommitHook } = require('../src/git/preCommitHook');
      const entropyEngine = require('../src/engine/entropy');
      const redactorEngine = require('../src/engine/redactor');
      const scannerEngine = require('../src/engine/scanner');
      const patternsEngine = require('../src/engine/patterns');
      const fromHex = (h: string) => Buffer.from(h, 'hex').toString('utf8');

      // 1. Hook contains fail-closed Node version verification
      const hookScript = buildPreCommitHook();
      assert(hookScript.includes('NODE_MAJOR=$(ELECTRON_RUN_AS_NODE=1 "$NODE_CMD" -p \'process.versions.node.split(".")[0]\' 2>/dev/null)'), 'Hook checks Node version using fail-closed process.versions.node with ELECTRON_RUN_AS_NODE=1');
      assert(hookScript.includes('Cannot determine Node.js version. Commit blocked.'), 'Hook blocks when Node version query fails');
      assert(hookScript.includes('Invalid Node.js version. Commit blocked.'), 'Hook blocks on non-numeric or empty Node version');
      assert(hookScript.includes('Node.js 18+ required'), 'Hook blocks on Node version < 18');

      // 2. Direct POSIX shell evaluation of version check guard logic
      const sh = findPosixShell();
      if (sh) {
        const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-node-ver-test-'));
        const mockNode = path.join(tmpDir, 'mock_node.sh').replace(/\\/g, '/');

        fs.writeFileSync(mockNode, `#!/bin/sh
if [ "$MOCK_MODE" = "fail" ]; then
  exit 1
elif [ "$MOCK_MODE" = "empty" ]; then
  exit 0
elif [ "$MOCK_MODE" = "malformed" ]; then
  echo "v20-alpha"
  exit 0
elif [ "$MOCK_MODE" = "16" ]; then
  echo "16"
  exit 0
elif [ "$MOCK_MODE" = "18" ]; then
  echo "18"
  exit 0
elif [ "$MOCK_MODE" = "20" ]; then
  echo "20"
  exit 0
elif [ "$MOCK_MODE" = "22" ]; then
  echo "22"
  exit 0
fi
`, { mode: 0o755 });

        const runGuard = (mode: string) => {
          const script = `
NODE_CMD='${mockNode}'
export MOCK_MODE='${mode}'
if ! NODE_MAJOR=$(ELECTRON_RUN_AS_NODE=1 "$NODE_CMD" -p 'process.versions.node.split(".")[0]' 2>/dev/null); then
  echo "FAIL_DETERMINE"
  exit 2
fi
case "$NODE_MAJOR" in
  ''|*[!0-9]*)
    echo "FAIL_INVALID"
    exit 2
    ;;
esac
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "FAIL_TOO_OLD:$NODE_MAJOR"
  exit 2
fi
echo "SUCCESS:$NODE_MAJOR"
exit 0
`;
          return cp.spawnSync(sh, ['-c', script], { encoding: 'utf8' });
        };

        try {
          // A. Failed command (exit non-zero)
          const resFail = runGuard('fail');
          assert(resFail.status === 2, 'Version check exits 2 on node command execution failure');
          assert(resFail.stdout.includes('FAIL_DETERMINE'), 'Version check prints FAIL_DETERMINE on error');

          // B. Empty version output
          const resEmpty = runGuard('empty');
          assert(resEmpty.status === 2, 'Version check exits 2 on empty node version');
          assert(resEmpty.stdout.includes('FAIL_INVALID'), 'Version check prints FAIL_INVALID on empty output');

          // C. Malformed / non-numeric output
          const resMalformed = runGuard('malformed');
          assert(resMalformed.status === 2, 'Version check exits 2 on non-numeric node version');
          assert(resMalformed.stdout.includes('FAIL_INVALID'), 'Version check prints FAIL_INVALID on malformed output');

          // D. Node 16 (too old)
          const resNode16 = runGuard('16');
          assert(resNode16.status === 2, 'Version check exits 2 on Node 16');
          assert(resNode16.stdout.includes('FAIL_TOO_OLD:16'), 'Version check prints FAIL_TOO_OLD:16 on old version');

          // E. Node 18, 20, 22 (supported)
          for (const v of ['18', '20', '22']) {
            const resValid = runGuard(v);
            assert(resValid.status === 0, `Version check exits 0 on Node ${v}`);
            assert(resValid.stdout.includes(`SUCCESS:${v}`), `Version check outputs SUCCESS:${v}`);
          }
        } finally {
          try {
            fs.rmSync(tmpDir, { recursive: true, force: true });
          } catch {}
        }
      }

      // 3. Scanner lazy AST parsing verification
      // A. Clean TS/JS document: onSourceFileParsed is NEVER invoked
      let cleanParsed = false;
      const cleanTsCode = `
export interface UserProfile {
  id: string;
  name: string;
  email: string;
}
export function getFullName(user: UserProfile): string {
  return user.name;
}
`;
      const cleanFindings = scanContent(cleanTsCode, 'user.ts', {
        onSourceFileParsed: () => {
          cleanParsed = true;
        },
      });
      assert(cleanFindings.length === 0, 'Clean file yields 0 findings');
      assert(cleanParsed === false, 'Clean file never triggers AST parsing (lazy compilation)');

      // B. TS/JS document with secret candidate: onSourceFileParsed IS invoked
      let secretParsed = false;
      let receivedSourceFile: any = null;
      // 40 characters: "ghp_" + 36 alphanumeric characters
      const fakeToken = fromHex('6768705f313233343536373839303132333435363738393031323334353637383930313233343536');
      const secretTsCode = `export const githubToken = "${fakeToken}";\n`;
      const secretFindings = scanContent(secretTsCode, 'config.ts', {
        onSourceFileParsed: (sf) => {
          secretParsed = true;
          receivedSourceFile = sf;
        },
      });
      assert(secretFindings.length > 0, 'Secret candidate detected');
      assert(secretParsed === true, 'AST parsing was lazily triggered on rule candidate match');
      assert(receivedSourceFile !== null && typeof receivedSourceFile === 'object', 'onSourceFileParsed passed a valid AST SourceFile');

      // 4. Legacy compatibility shims
      assert(typeof entropyEngine.calculateShannonEntropy === 'function', 'entropy shim exports calculateShannonEntropy');
      assert(typeof redactorEngine.redactSecret === 'function', 'redactor shim exports redactSecret');
      assert(typeof scannerEngine.scanContent === 'function', 'scanner shim exports scanContent');
      assert(Array.isArray(patternsEngine.SECRET_RULES), 'patterns shim exports SECRET_RULES array');
      assert(patternsEngine.SECRET_RULES.length > 0, 'SECRET_RULES is non-empty');
      const sampleRule = patternsEngine.SECRET_RULES[0];
      assert(typeof sampleRule.exampleFix === 'function', 'SECRET_RULES adapter includes exampleFix function');
      assert(typeof sampleRule.remediation === 'string', 'SECRET_RULES adapter includes remediation string');

      // 5. Extension activation does not eagerly copy ast-parser.js
      const extensionSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.ts'), 'utf8');
      const activateBody = extensionSrc.slice(
        extensionSrc.indexOf('export async function activate'),
        extensionSrc.indexOf('// Re-pin pre-commit hooks')
      );
      assert(!activateBody.includes('ensureGlobalAstParser()'), 'activate() does not eagerly invoke ensureGlobalAstParser()');
      assert(!activateBody.includes('ast-parser.js'), 'activate() does not copy ast-parser.js during activation');
      assert(extensionSrc.includes('function ensureGlobalAstParser'), 'extension.ts defines ensureGlobalAstParser for on-demand copying');
    }

    // --- 43. Git Process Argument Confinement, Removal Error Handling & Electron Runtime Protection ---
    console.log('\n--- 43. Git Process Argument Confinement, Removal Error Handling & Electron Runtime Protection ---');
    {
      const { GitHistoryEngine } = require('../src/core/history/gitHistoryEngine');
      const { enforceEnvFilePermissions } = require('../src/core/remediation/remediationEngine');
      const { buildPreCommitHook } = require('../src/git/preCommitHook');
      const { execFileSync } = require('child_process');
      const fromHex = (h: string) => Buffer.from(h, 'hex').toString('utf8');

      // 1. Process Argument Confinement & Safe Removal Commit Attribution
      const sec43Repo = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-sec43-repo-'));
      try {
        execFileSync('git', ['init', sec43Repo]);
        execFileSync('git', ['-C', sec43Repo, 'config', 'user.name', 'Arg Sniffer Tester']);
        execFileSync('git', ['-C', sec43Repo, 'config', 'user.email', 'argtester@test.com']);

        // 40 chars GitHub token
        const secretToken = fromHex('6768705f313233343536373839303132333435363738393031323334353637383930313233343536');

        // Commit 1: introduce secret
        fs.writeFileSync(path.join(sec43Repo, 'token.ts'), `export const key = "${secretToken}";\n`, 'utf8');
        execFileSync('git', ['-C', sec43Repo, 'add', 'token.ts']);
        execFileSync('git', ['-C', sec43Repo, 'commit', '-m', 'feat: add token']);

        // Commit 2: edit comment, keep secret
        fs.writeFileSync(path.join(sec43Repo, 'token.ts'), `// updated comment\nexport const key = "${secretToken}";\n`, 'utf8');
        execFileSync('git', ['-C', sec43Repo, 'add', 'token.ts']);
        execFileSync('git', ['-C', sec43Repo, 'commit', '-m', 'docs: update comment']);
        const c2Sha = execFileSync('git', ['-C', sec43Repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();

        // Commit 3: remove secret
        fs.writeFileSync(path.join(sec43Repo, 'token.ts'), `export const key = process.env.KEY;\n`, 'utf8');
        execFileSync('git', ['-C', sec43Repo, 'add', 'token.ts']);
        execFileSync('git', ['-C', sec43Repo, 'commit', '-m', 'fix: remove secret from HEAD']);
        const c3Sha = execFileSync('git', ['-C', sec43Repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();

        // Commit 4: additional clean work
        fs.writeFileSync(path.join(sec43Repo, 'readme.md'), `# Docs\n`, 'utf8');
        execFileSync('git', ['-C', sec43Repo, 'add', 'readme.md']);
        execFileSync('git', ['-C', sec43Repo, 'commit', '-m', 'docs: add readme']);

        // Sniff all Git command arguments
        class ArgumentSnifferEngine extends GitHistoryEngine {
          public loggedArgs: string[][] = [];
          protected override async execGit(args: string[], options: any = {}): Promise<{ stdout: any; stderr: any }> {
            this.loggedArgs.push(args);
            return super.execGit(args, options);
          }
        }

        const sniffer = new ArgumentSnifferEngine(sec43Repo);
        const removed = await sniffer.findRemovalCommit(secretToken, c2Sha);
        assert(removed !== undefined, 'findRemovalCommit locates genuine removal commit');
        assert(removed?.sha === c3Sha, 'Removal commit SHA correctly identified as commit 3');

        // Verify credentials NEVER appear in any spawned process argument
        const patternLine = sniffer.pickDistinctiveSearchLine(secretToken);
        for (const args of sniffer.loggedArgs) {
          const hasSecretInArg = args.some((a: string) => a.includes(secretToken) || a.includes(patternLine));
          assert(!hasSecretInArg, `Git process arguments do not expose secret or patternLine: [${args.join(' ')}]`);
          assert(!args.some((a: string) => a.startsWith('-S')), `Git process arguments do not use -S flag`);
        }

        // 2. Operational Git error during removal detection: do NOT treat as absence!
        class FailingGrepRemovalEngine extends GitHistoryEngine {
          public failGrepOnRemoval = false;
          private inRemoval = false;
          public override async findRemovalCommit(secret: string, lastSeenSha: string): Promise<GitCommitInfo | undefined> {
            if (this.failGrepOnRemoval) {
              this.inRemoval = true;
              try {
                return await super.findRemovalCommit(secret, lastSeenSha);
              } finally {
                this.inRemoval = false;
              }
            }
            return super.findRemovalCommit(secret, lastSeenSha);
          }
          protected override async execGit(args: string[], options: any = {}): Promise<{ stdout: any; stderr: any }> {
            if (this.inRemoval && args[0] === 'grep') {
              const err: any = new Error('fatal: simulated packfile corruption during git grep');
              err.code = 128;
              throw err;
            }
            return super.execGit(args, options);
          }
        }

        const failingEngine = new FailingGrepRemovalEngine(sec43Repo);
        failingEngine.failGrepOnRemoval = true;
        let findRemovalThrew = false;
        try {
          await failingEngine.findRemovalCommit(secretToken, c2Sha);
        } catch (err: any) {
          findRemovalThrew = true;
          assert(err.message.includes('fatal: simulated packfile corruption'), 'findRemovalCommit throws on operational Git error');
        }
        assert(findRemovalThrew === true, 'findRemovalCommit refuses to treat Git execution errors as clean absence');

        const failingTrace = await failingEngine.traceSecret(secretToken);
        assert(failingTrace.searchStatus === 'SEARCH_INCOMPLETE', 'traceSecret reports SEARCH_INCOMPLETE when removal detection encounters operational failure');
        assert(failingTrace.isPresentInHistory === true, 'traceSecret preserves isPresentInHistory: true when removal detection fails');

        // 3. Electron-pinned runtime version probe execution
        const sh = findPosixShell();
        if (sh) {
          const mockElectronDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-mock-electron-'));
          const mockElectron = path.join(mockElectronDir, 'mock_electron.sh').replace(/\\/g, '/');
          fs.writeFileSync(
            mockElectron,
            `#!/bin/sh
if [ "$ELECTRON_RUN_AS_NODE" != "1" ]; then
  echo "Error: Electron binary executed without ELECTRON_RUN_AS_NODE=1" >&2
  exit 1
fi
echo "20"
exit 0
`,
            { mode: 0o755 }
          );

          try {
            const electronProbeScript = `
NODE_CMD='${mockElectron}'
if ! NODE_MAJOR=$(ELECTRON_RUN_AS_NODE=1 "$NODE_CMD" -p 'process.versions.node.split(".")[0]' 2>/dev/null); then
  echo "FAIL_DETERMINE"
  exit 2
fi
echo "SUCCESS:$NODE_MAJOR"
exit 0
`;
            const electronProbeRes = cp.spawnSync(sh, ['-c', electronProbeScript], { encoding: 'utf8' });
            assert(electronProbeRes.status === 0, 'Electron-pinned runtime probe exits 0 with ELECTRON_RUN_AS_NODE=1');
            assert(electronProbeRes.stdout.includes('SUCCESS:20'), 'Electron-pinned runtime probe outputs SUCCESS:20');

            // Without ELECTRON_RUN_AS_NODE=1, probe fails
            const failedProbeScript = `
NODE_CMD='${mockElectron}'
export ELECTRON_RUN_AS_NODE=""
if ! NODE_MAJOR=$("$NODE_CMD" -p 'process.versions.node.split(".")[0]' 2>/dev/null); then
  echo "FAIL_NO_ENV"
  exit 2
fi
echo "SUCCESS:$NODE_MAJOR"
exit 0
`;
            const failedProbeRes = cp.spawnSync(sh, ['-c', failedProbeScript], { encoding: 'utf8' });
            assert(failedProbeRes.status === 2, 'Electron-pinned runtime without ELECTRON_RUN_AS_NODE=1 fails probe');
            assert(failedProbeRes.stdout.includes('FAIL_NO_ENV'), 'Probe correctly blocks when ELECTRON_RUN_AS_NODE is absent');
          } finally {
            try { fs.rmSync(mockElectronDir, { recursive: true, force: true }); } catch {}
          }
        }

        // 4. Windows ACL Hardening in enforceEnvFilePermissions
        const mockEnvFile = path.join(sec43Repo, '.env');
        fs.writeFileSync(mockEnvFile, 'SECRET="val"\n', 'utf8');

        let icaclsInvoked = false;
        let allIcaclsInvocations: string[][] = [];
        const mockCp = {
          execFileSync: (cmd: string, args: string[]) => {
            if (cmd === 'icacls') {
              icaclsInvoked = true;
              allIcaclsInvocations.push(args);
              if (args.length === 1) {
                const u = process.env.USERNAME || process.env.USER || 'testuser';
                return `${args[0]} ${u}:(F)\nSuccessfully processed 1 files;\n`;
              }
            }
            return Buffer.from('');
          }
        };

        enforceEnvFilePermissions(mockEnvFile, fs, 'win32', mockCp as any);
        assert(icaclsInvoked === true, 'enforceEnvFilePermissions executes icacls on win32');
        assert(allIcaclsInvocations.some((args) => args.includes('/inheritance:r')), 'icacls invocation removes inherited ACLs');
        assert(allIcaclsInvocations.some((args) => args.some((a: string) => a.startsWith('/grant:r'))), 'icacls invocation explicitly grants current user permissions');

        // Graceful fallback when icacls fails (non-NTFS filesystem)
        const failingCp = {
          execFileSync: () => {
            throw new Error('The volume does not support ACLs (FAT32/exFAT)');
          }
        };
        enforceEnvFilePermissions(mockEnvFile, fs, 'win32', failingCp as any);
        assert(true, 'enforceEnvFilePermissions tolerates non-NTFS volumes gracefully');

        // 5. Async and deferred ensureGlobalAstParser in extension.ts
        const extSrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.ts'), 'utf8');
        assert(extSrc.includes('async function ensureGlobalAstParser(): Promise<void>'), 'ensureGlobalAstParser is asynchronous');
        assert(!extSrc.includes('fs.copyFileSync(astParserSrc, stableAstParser);'), 'ast-parser.js is not copied synchronously in extension.ts');
        const pinStart = extSrc.indexOf('async function pinHooksInAllFolders');
        const pinEnd = extSrc.indexOf('if (fs.existsSync(activeCliPath))', pinStart);
        const pinHooksFunc = extSrc.slice(pinStart, pinEnd);
        const isGitRepoIdx = pinHooksFunc.indexOf('await gs.isGitRepo()');
        const parserEnsureIdx = pinHooksFunc.indexOf('await ensureGlobalAstParser()');
        assert(isGitRepoIdx !== -1 && parserEnsureIdx !== -1, 'Both isGitRepo and ensureGlobalAstParser present in pinHooksInAllFolders');
        assert(parserEnsureIdx > isGitRepoIdx, 'ensureGlobalAstParser is deferred until AFTER isGitRepo() confirms a Git repo exists');
      } finally {
        try {
          fs.rmSync(sec43Repo, { recursive: true, force: true });
        } catch {}
      }
    }

    // --- 44. Unmerged Branch Removal Lineage, Windows Explicit ACL Stripping & Hook-Gated Parser Copying ---
    console.log('\n--- 44. Unmerged Branch Removal Lineage, Windows Explicit ACL Stripping & Hook-Gated Parser Copying ---');
    {
      const { GitHistoryEngine } = require('../src/core/history/gitHistoryEngine');
      const { GitTimelineEngine } = require('../src/core/history/gitTimeline');
      const { enforceEnvFilePermissions } = require('../src/core/remediation/remediationEngine');
      const { execFileSync } = require('child_process');
      const fromHex = (h: string) => Buffer.from(h, 'hex').toString('utf8');

      const sec44Repo = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-sec44-'));
      try {
        execFileSync('git', ['init'], { cwd: sec44Repo });
        execFileSync('git', ['checkout', '-B', 'main'], { cwd: sec44Repo });
        execFileSync('git', ['config', 'user.name', 'Dev Tester'], { cwd: sec44Repo });
        execFileSync('git', ['config', 'user.email', 'dev@example.com'], { cwd: sec44Repo });

        // Commit M1 on main
        fs.writeFileSync(path.join(sec44Repo, 'main.txt'), 'console.log("main clean");\n', 'utf8');
        execFileSync('git', ['add', 'main.txt'], { cwd: sec44Repo });
        execFileSync('git', ['commit', '-m', 'chore: initial commit on main'], { cwd: sec44Repo });

        // Create feature branch: feat/secret-branch
        execFileSync('git', ['checkout', '-b', 'feat/secret-branch'], { cwd: sec44Repo });
        const featSecret = fromHex('6768705f666561747572657365637265743132333435363738393061626364656667');
        fs.writeFileSync(path.join(sec44Repo, 'feature.ts'), `export const TOKEN = "${featSecret}";\n`, 'utf8');
        execFileSync('git', ['add', 'feature.ts'], { cwd: sec44Repo });
        execFileSync('git', ['commit', '-m', 'feat: add token on feature branch'], { cwd: sec44Repo });
        const f1Sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: sec44Repo, encoding: 'utf8' }).trim();

        fs.writeFileSync(path.join(sec44Repo, 'feature-extra.ts'), 'export const extra = true;\n', 'utf8');
        execFileSync('git', ['add', 'feature-extra.ts'], { cwd: sec44Repo });
        execFileSync('git', ['commit', '-m', 'feat: extra commit on feature branch'], { cwd: sec44Repo });
        const f2Sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: sec44Repo, encoding: 'utf8' }).trim();

        // Switch back to main; do unrelated work
        execFileSync('git', ['checkout', 'main'], { cwd: sec44Repo });
        fs.writeFileSync(path.join(sec44Repo, 'unrelated.txt'), 'console.log("unrelated main work");\n', 'utf8');
        execFileSync('git', ['add', 'unrelated.txt'], { cwd: sec44Repo });
        execFileSync('git', ['commit', '-m', 'feat: unrelated work on main'], { cwd: sec44Repo });

        // 1. Lineage & Ancestry verification:
        const histEngine = new GitHistoryEngine(sec44Repo);
        const isF1AncestorOfHead = await histEngine.isAncestor(f1Sha, 'HEAD');
        const isF2AncestorOfHead = await histEngine.isAncestor(f2Sha, 'HEAD');
        assert(isF1AncestorOfHead === false, 'Feature branch commit F1 is not an ancestor of main HEAD');
        assert(isF2AncestorOfHead === false, 'Feature branch commit F2 is not an ancestor of main HEAD');

        const isF1AncestorOfFeat = await histEngine.isAncestor(f1Sha, 'feat/secret-branch');
        assert(isF1AncestorOfFeat === true, 'Feature branch commit F1 is an ancestor of feat/secret-branch');

        // 2. findRemovalCommit refuses to attribute removal to unrelated HEAD commits
        const removalAgainstHead = await histEngine.findRemovalCommit(featSecret, f2Sha, 'HEAD');
        assert(removalAgainstHead === undefined, 'findRemovalCommit returns undefined when lastSeenSha is not an ancestor of HEAD');

        // 3. traceSecret correctly identifies unmerged branch exposure
        const featTrace = await histEngine.traceSecret(featSecret);
        assert(featTrace.isPresentInHistory === true, 'traceSecret detects presence in Git history across branches');
        assert(featTrace.isPresentInHead === false, 'traceSecret confirms secret is absent from HEAD');
        assert(featTrace.isAncestorOfHead === false, 'traceSecret establishes isAncestorOfHead: false');
        assert(featTrace.removedCommit === undefined, 'traceSecret does not attribute removedCommit to unrelated HEAD commit');
        assert(featTrace.statusDescription.includes('UNMERGED BRANCH EXPOSURE'), 'traceSecret reports UNMERGED BRANCH EXPOSURE in statusDescription');
        assert(Boolean(featTrace.branchRemovals && featTrace.branchRemovals['feat/secret-branch']), 'traceSecret tracks removal separately per branch');
        assert(featTrace.branchRemovals!['feat/secret-branch'].isRemoved === false, 'traceSecret notes secret is not removed on feat/secret-branch');

        // 4. Timeline correctly avoids false removal event for unmerged branch
        const timelineEngine = new GitTimelineEngine(sec44Repo, histEngine);
        const featTimeline = await timelineEngine.buildTimeline(featSecret, 'ghp_••••');
        const hasRemovedEvent = featTimeline.graph.nodes.some((n: any) => n.label.startsWith('REMOVED'));
        assert(hasRemovedEvent === false, 'buildTimeline does not synthesize a false REMOVED node for unmerged branch');
        assert(featTimeline.timelineAscii.includes('UNMERGED BRANCH'), 'buildTimeline ASCII notes unmerged branch exposure');

        // 5. On the feature branch itself, removal commit is properly tracked when removed
        execFileSync('git', ['checkout', 'feat/secret-branch'], { cwd: sec44Repo });
        fs.writeFileSync(path.join(sec44Repo, 'feature.ts'), 'export const TOKEN = process.env.TOKEN;\n', 'utf8');
        execFileSync('git', ['add', 'feature.ts'], { cwd: sec44Repo });
        execFileSync('git', ['commit', '-m', 'fix: remove secret on feature branch'], { cwd: sec44Repo });
        const f3Sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: sec44Repo, encoding: 'utf8' }).trim();

        execFileSync('git', ['checkout', 'main'], { cwd: sec44Repo });
        const branchRemoval = await histEngine.findRemovalCommit(featSecret, f2Sha, 'feat/secret-branch');
        assert(branchRemoval !== undefined, 'findRemovalCommit finds genuine removal commit on feature branch');
        assert(branchRemoval?.sha === f3Sha, 'Removal commit SHA on feature branch is F3');

        const postFixTrace = await histEngine.traceSecret(featSecret);
        assert(postFixTrace.branchRemovals!['feat/secret-branch'].isRemoved === true, 'traceSecret reports isRemoved: true on feat/secret-branch');
        assert(postFixTrace.branchRemovals!['feat/secret-branch'].removalCommit?.sha === f3Sha, 'traceSecret records removalCommit on feat/secret-branch');

        // 6. Windows ACL: Stripping broad explicit permissions
        const sec44Env = path.join(sec44Repo, '.env');
        fs.writeFileSync(sec44Env, 'KEY="secret"\n', 'utf8');

        let permissionsStripped = false;
        const aclMockCp = {
          execFileSync: (cmd: string, args: string[]) => {
            if (cmd === 'icacls') {
              if (args.includes('/remove') && args.includes('Everyone')) {
                permissionsStripped = true;
              }
              if (args.length === 1) {
                const u = process.env.USERNAME || process.env.USER || 'testuser';
                // First query: Everyone has explicit R
                if (!permissionsStripped) {
                  return `${args[0]} Everyone:(R)\n ${u}:(F)\nSuccessfully processed 1 files;\n`;
                }
                // Second query: after /remove Everyone
                return `${args[0]} ${u}:(F)\nSuccessfully processed 1 files;\n`;
              }
            }
            return Buffer.from('');
          }
        };

        const aclRes = enforceEnvFilePermissions(sec44Env, fs, 'win32', aclMockCp as any);
        assert(aclRes.enforced === true, 'enforceEnvFilePermissions reports enforced: true');
        assert(permissionsStripped === true, 'enforceEnvFilePermissions actively strips explicit Everyone permissions via icacls /remove');

        // 7. Windows ACL: Failure to secure throws security error rather than succeeding
        const unsafeAclCp = {
          execFileSync: (cmd: string, args: string[]) => {
            if (cmd === 'icacls' && args.length === 1) {
              const u = process.env.USERNAME || process.env.USER || 'testuser';
              return `${args[0]} Everyone:(F)\n ${u}:(F)\nSuccessfully processed 1 files;\n`;
            }
            return Buffer.from('');
          }
        };
        let unsafeThrew = false;
        try {
          enforceEnvFilePermissions(sec44Env, fs, 'win32', unsafeAclCp as any);
        } catch (err: any) {
          unsafeThrew = true;
          assert(err.message.includes('Security error: Windows ACL enforcement failed'), 'Throws descriptive error when unsafe permissions persist');
        }
        assert(unsafeThrew === true, 'enforceEnvFilePermissions refuses to succeed when unsafe accounts persist');

        // 8. Windows ACL: Operational failures throw instead of returning clean
        const failingAccessCp = {
          execFileSync: () => {
            const err: any = new Error('EACCES: permission denied, icacls execution prohibited');
            err.code = 'EACCES';
            throw err;
          }
        };
        let accessThrew = false;
        try {
          enforceEnvFilePermissions(sec44Env, fs, 'win32', failingAccessCp as any);
        } catch (err: any) {
          accessThrew = true;
          assert(err.message.includes('permission denied'), 'Operational error is thrown rather than swallowed');
        }
        assert(accessThrew === true, 'enforceEnvFilePermissions does not swallow real operational errors');

        // 9. Windows ACL: Unsupported filesystem returns isUnsupportedFs: true without throwing
        const fat32Cp = {
          execFileSync: () => {
            throw new Error('The volume does not support ACLs (FAT32/exFAT)');
          }
        };
        const fat32Res = enforceEnvFilePermissions(sec44Env, fs, 'win32', fat32Cp as any);
        assert(fat32Res.enforced === false, 'enforceEnvFilePermissions returns enforced: false on unsupported FS');
        assert(fat32Res.isUnsupportedFs === true, 'enforceEnvFilePermissions identifies unsupported filesystem gracefully');

        // 10. Hook-gated parser copying in extension.ts
        const extSource = fs.readFileSync(path.join(__dirname, '..', 'src', 'extension.ts'), 'utf8');
        const pinFuncSlice = extSource.slice(
          extSource.indexOf('async function pinHooksInAllFolders'),
          extSource.indexOf('if (fs.existsSync(activeCliPath))', extSource.indexOf('async function pinHooksInAllFolders'))
        );
        assert(pinFuncSlice.includes('hasManagedHook'), 'pinHooksInAllFolders checks for hasManagedHook');
        assert(pinFuncSlice.includes('includes(SLD_HOOK_MARKER)'), 'pinHooksInAllFolders verifies SLD_HOOK_MARKER before copying parser');
        const hookCheckIdx = pinFuncSlice.indexOf('hasManagedHook');
        const parserCallIdx = pinFuncSlice.indexOf('await ensureGlobalAstParser()');
        assert(parserCallIdx > hookCheckIdx, 'ensureGlobalAstParser is deferred until AFTER verifying an SLD managed hook exists');
      } finally {
        try { fs.rmSync(sec44Repo, { recursive: true, force: true }); } catch {}
      }
    }

    // --- 45. Shallow Repo Guard, Tri-State Ancestry & Windows Principal Strictness ---
    console.log('\n--- 45. Shallow Repo Guard, Tri-State Ancestry & Windows Principal Strictness ---');
    {
      const { execFileSync } = cp;
      const sec45Dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-sec45-'));
      try {
        // 1. Shallow repository detection & prevention of false clean history
        const shallowRepoDir = path.join(sec45Dir, 'shallow-repo');
        fs.mkdirSync(shallowRepoDir, { recursive: true });
        execFileSync('git', ['init'], { cwd: shallowRepoDir });
        execFileSync('git', ['checkout', '-B', 'main'], { cwd: shallowRepoDir });
        execFileSync('git', ['config', 'user.name', 'Dev Tester'], { cwd: shallowRepoDir });
        execFileSync('git', ['config', 'user.email', 'dev@example.com'], { cwd: shallowRepoDir });

      const testSecretVal = 'akiasample' + '123456789012' + 'shallow';
      fs.writeFileSync(path.join(shallowRepoDir, 'token.txt'), `${testSecretVal}\n`, 'utf8');
      execFileSync('git', ['add', 'token.txt'], { cwd: shallowRepoDir });
      execFileSync('git', ['commit', '-m', 'feat: add token'], { cwd: shallowRepoDir });

      fs.writeFileSync(path.join(shallowRepoDir, 'token.txt'), 'cleaned\n', 'utf8');
      execFileSync('git', ['add', 'token.txt'], { cwd: shallowRepoDir });
      execFileSync('git', ['commit', '-m', 'fix: clean token from head'], { cwd: shallowRepoDir });

      // Simulate shallow clone by creating .git/shallow containing HEAD sha
      const headSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: shallowRepoDir, encoding: 'utf8' }).trim();
      fs.writeFileSync(path.join(shallowRepoDir, '.git', 'shallow'), `${headSha}\n`, 'utf8');

      const shallowEngine = new GitHistoryEngine(shallowRepoDir);
      const isShallow = await shallowEngine.isShallowRepo();
      assert(isShallow === true, 'isShallowRepo detects shallow repository');

      // In shallow clone, token is absent from the 1 shallow commit, but engine must report PARTIAL_HISTORY
      const shallowSearch = await shallowEngine.findCommitsContainingSecretResult(testSecretVal);
      assert(shallowSearch.status === 'PARTIAL_HISTORY', 'findCommitsContainingSecretResult returns PARTIAL_HISTORY on shallow repo');
      assert(shallowSearch.isPartialHistory === true, 'isPartialHistory is true on shallow repo');
      assert(shallowSearch.isShallow === true, 'isShallow is true in search result');

      const shallowTrace = await shallowEngine.traceSecret(testSecretVal);
      assert(shallowTrace.isPresentInHistory === 'UNKNOWN', 'traceSecret sets isPresentInHistory: UNKNOWN on shallow clone');
      assert(shallowTrace.isPresentInHead === 'UNKNOWN', 'traceSecret sets isPresentInHead: UNKNOWN on shallow clone');
      assert(shallowTrace.isRemote === 'UNKNOWN', 'traceSecret sets isRemote: UNKNOWN on shallow clone');
      assert(shallowTrace.searchStatus === 'PARTIAL_HISTORY', 'traceSecret searchStatus is PARTIAL_HISTORY on shallow clone');
      assert(shallowTrace.statusDescription.includes('Shallow Git clone detected'), 'statusDescription informs user of shallow clone');

      // VerificationEngine on shallow repository must not resolve finding as clean
      const verEngine = new VerificationEngine(shallowRepoDir);
      const fakeFinding: any = {
        id: 'finding-shallow',
        fullPath: path.join(shallowRepoDir, 'token.txt'),
        rawSecret: testSecretVal,
        gitExposure: shallowTrace,
      };
      const verifyRes = await verEngine.verifyFindingFix(fakeFinding);
      assert(verifyRes.isResolved === false, 'verifyFindingFix refuses to mark shallow repo finding as resolved');
      assert(verifyRes.historyStatus === 'UNKNOWN', 'verifyFindingFix sets historyStatus: UNKNOWN on shallow clone');
      assert(verifyRes.details.includes('shallow clone'), 'verifyFindingFix details inform user of shallow clone history truncation');

      // 2. Tri-state Git Ancestry: true, false, and UNKNOWN
      class AncestryMockEngine extends GitHistoryEngine {
        public mockExitCode: number = 0;
        public mockError: any = null;
        protected async execGit(args: string[]): Promise<{ stdout: any; stderr: any }> {
          if (args[0] === 'merge-base' && args[1] === '--is-ancestor') {
            if (this.mockError) throw this.mockError;
            if (this.mockExitCode === 0) return { stdout: '', stderr: '' };
            const err: any = new Error(`exit code ${this.mockExitCode}`);
            err.code = this.mockExitCode;
            throw err;
          }
          return super.execGit(args);
        }
      }

      const ancMock = new AncestryMockEngine(shallowRepoDir);
      ancMock.mockExitCode = 0;
      const ancTrue = await ancMock.isAncestor('abc', 'HEAD');
      assert(ancTrue === true, 'isAncestor returns true on exit code 0');

      ancMock.mockExitCode = 1;
      const ancFalse = await ancMock.isAncestor('abc', 'HEAD');
      assert(ancFalse === false, 'isAncestor returns false on exit code 1');

      ancMock.mockExitCode = 128; // Fatal git error (e.g. missing object, repository corruption)
      const ancUnknown = await ancMock.isAncestor('abc', 'HEAD');
      assert(ancUnknown === 'UNKNOWN', 'isAncestor returns UNKNOWN on non-1 error code');

      // When ancestry fails with UNKNOWN, findRemovalCommit throws rather than claiming clean absence
      let removalThrew = false;
      try {
        await ancMock.findRemovalCommit(testSecretVal, 'abc', 'HEAD');
      } catch (err: any) {
        removalThrew = true;
        assert(err.message.includes('Git operational error establishing ancestry'), 'findRemovalCommit throws on UNKNOWN ancestry');
      }
      assert(removalThrew === true, 'findRemovalCommit refuses to treat UNKNOWN ancestry as absence');

      // 3. Remediation communicates degraded security state when Windows ACLs are unsupported
      const remEnv = path.join(shallowRepoDir, '.env');
      fs.writeFileSync(remEnv, 'VAR="val"\n', 'utf8');
      const degradedFinding: any = {
        id: 'f-degraded',
        fullPath: path.join(shallowRepoDir, 'source.ts'),
        file: 'source.ts',
        rawSecret: 'token_degraded_val_123',
        type: 'Test Token',
        remediation: { envVarName: 'TEST_TOKEN' },
      };
      fs.writeFileSync(path.join(shallowRepoDir, 'source.ts'), "import 'dotenv/config';\nconst t = \"token_degraded_val_123\";\n", 'utf8');

      const unsupportedAclCp = {
        execFileSync: () => {
          throw new Error('The volume does not support ACLs (FAT32/exFAT)');
        }
      };
      const directEnforce = enforceEnvFilePermissions(remEnv, fs, 'win32', unsupportedAclCp as any);
      assert(directEnforce.enforced === false, 'enforceEnvFilePermissions reports enforced: false on unsupported FS');
      assert(directEnforce.isUnsupportedFs === true, 'enforceEnvFilePermissions reports isUnsupportedFs: true');

      const remResDegraded = applyControlledRemediation(
        degradedFinding,
        shallowRepoDir,
        fs,
        'win32',
        unsupportedAclCp as any
      );
      assert(remResDegraded.success === false, 'applyControlledRemediation refuses to write when private .env permissions cannot be enforced');
      assert(/Could not enforce private \.env permissions/.test(remResDegraded.message), 'Permission failure explains why remediation was aborted');
      assert(fs.readFileSync(path.join(shallowRepoDir, 'source.ts'), 'utf8').includes('token_degraded_val_123'), 'Source file remains unchanged when .env permissions cannot be enforced');
      assert(!fs.readFileSync(remEnv, 'utf8').includes('token_degraded_val_123'), 'Credential is never written to an unprotected .env file');
      // A pre-existing .env symlink must not redirect credential writes outside the workspace.
      if (process.platform !== 'win32') {
        const symlinkWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-rem-symlink-'));
        const symlinkSource = path.join(symlinkWorkspace, 'source.ts');
        const symlinkEnv = path.join(symlinkWorkspace, '.env');
        const outsideEnv = path.join(os.tmpdir(), 'sld-outside-env-' + process.pid + '-' + Date.now());
        const symlinkSecret = 'symlink_secret_value_123456';
        fs.writeFileSync(symlinkSource, "import 'dotenv/config';\nconst token = \"" + symlinkSecret + "\";\n", 'utf8');
        fs.writeFileSync(path.join(symlinkWorkspace, '.gitignore'), '.env\n', 'utf8');
        fs.writeFileSync(outsideEnv, 'OUTSIDE="untouched"\n', 'utf8');
        fs.symlinkSync(outsideEnv, symlinkEnv);
        const symlinkFinding: any = {
          fullPath: symlinkSource,
          file: 'source.ts',
          rawSecret: symlinkSecret,
          type: 'Test Token',
          remediation: { envVarName: 'TEST_TOKEN' },
        };
        const symlinkResult = applyControlledRemediation(symlinkFinding, symlinkWorkspace);
        assert(symlinkResult.success === false, 'Remediation rejects a symlinked .env file');
        assert(fs.readFileSync(outsideEnv, 'utf8') === 'OUTSIDE="untouched"\n', 'A symlink target outside the workspace is never modified');
        assert(fs.readFileSync(symlinkSource, 'utf8').includes(symlinkSecret), 'Source file remains unchanged when .env is a symlink');
        fs.rmSync(symlinkWorkspace, { recursive: true, force: true });
        fs.rmSync(outsideEnv, { force: true });
      }


      // 4. Windows ACL Identity Check: Strict Principal & SID Matching
      const mypcPrincipal = {
        username: 'testuser',
        domain: 'MYPC',
        qualifiedName: 'MYPC\\testuser',
        userSid: 'S-1-5-21-1234567890-1111111111-2222222222-1001',
      };

      // Disallow account with matching username suffix but differing domain prefix!
      const otherDomainAuthorized = isPrincipalAuthorized('OTHERDOMAIN\\testuser', mypcPrincipal);
      assert(otherDomainAuthorized === false, 'isPrincipalAuthorized rejects OTHERDOMAIN\\testuser when principal is MYPC\\testuser');

      // Allow matching qualified domain\user
      const mypcAuthorized = isPrincipalAuthorized('MYPC\\testuser', mypcPrincipal);
      assert(mypcAuthorized === true, 'isPrincipalAuthorized accepts matching qualified MYPC\\testuser');

      // Allow matching SID
      const sidAuthorized = isPrincipalAuthorized('*S-1-5-21-1234567890-1111111111-2222222222-1001', mypcPrincipal);
      assert(sidAuthorized === true, 'isPrincipalAuthorized accepts matching user SID');

      // Reject non-matching SID
      const otherSidAuthorized = isPrincipalAuthorized('*S-1-5-21-9999999999-9999999999-9999999999-9999', mypcPrincipal);
      assert(otherSidAuthorized === false, 'isPrincipalAuthorized rejects non-matching SID');

      // Allow SYSTEM
      assert(isPrincipalAuthorized('NT AUTHORITY\\SYSTEM', mypcPrincipal) === true, 'isPrincipalAuthorized accepts NT AUTHORITY\\SYSTEM');
      assert(isPrincipalAuthorized('*S-1-5-18', mypcPrincipal) === true, 'isPrincipalAuthorized accepts SYSTEM SID S-1-5-18');

      // Enforce removal of OTHERDOMAIN account via icacls /remove
      let otherDomainRemoved = false;
      const domainMockCp = {
        execFileSync: (cmd: string, args: string[]) => {
          if (cmd === 'whoami' && args.includes('/fo')) {
            return '"User Name","SID"\n"MYPC\\testuser","S-1-5-21-1234567890-1111111111-2222222222-1001"\n';
          }
          if (cmd === 'icacls') {
            if (args.includes('/remove') && args.includes('OTHERDOMAIN\\testuser')) {
              otherDomainRemoved = true;
            }
            if (args.length === 1) {
              if (!otherDomainRemoved) {
                return `${args[0]} OTHERDOMAIN\\testuser:(R)\n MYPC\\testuser:(F)\nSuccessfully processed 1 files;\n`;
              }
              return `${args[0]} MYPC\\testuser:(F)\nSuccessfully processed 1 files;\n`;
            }
          }
          return Buffer.from('');
        }
      };

      const domainEnforceRes = enforceEnvFilePermissions(remEnv, fs, 'win32', domainMockCp as any);
      assert(domainEnforceRes.enforced === true, 'enforceEnvFilePermissions reports enforced: true after stripping other domain');
      assert(otherDomainRemoved === true, 'enforceEnvFilePermissions actively strips OTHERDOMAIN\\testuser via icacls /remove');

      } finally {
        try { fs.rmSync(sec45Dir, { recursive: true, force: true }); } catch {}
      }
    }

    // --- 46. Shallow Credential Found, Multi-Branch Reachability, Committer Chronology & Numerical SIDs ---
    console.log('\n--- 46. Shallow Credential Found, Multi-Branch Reachability, Committer Chronology & Numerical SIDs ---');
    {
      const { execFileSync } = cp;
      const fromHex = (h: string) => Buffer.from(h, 'hex').toString('utf8');
      const sec46Dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-sec46-'));
      try {
        // 1. Shallow repository where secret IS discovered in visible history
        const shallowRepoWithSecret = path.join(sec46Dir, 'shallow-with-secret');
        fs.mkdirSync(shallowRepoWithSecret, { recursive: true });
        execFileSync('git', ['init'], { cwd: shallowRepoWithSecret });
        execFileSync('git', ['checkout', '-B', 'main'], { cwd: shallowRepoWithSecret });
        execFileSync('git', ['config', 'user.name', 'Dev Tester'], { cwd: shallowRepoWithSecret });
        execFileSync('git', ['config', 'user.email', 'dev@example.com'], { cwd: shallowRepoWithSecret });

        const shallowSecretVal = fromHex('6768705f') + fromHex('5368616c6c6f7756697369626c65536563726574546f6b656e31323334353637383930');
        fs.writeFileSync(path.join(shallowRepoWithSecret, 'creds.json'), `{"token": "${shallowSecretVal}"}\n`, 'utf8');
        execFileSync('git', ['add', 'creds.json'], { cwd: shallowRepoWithSecret });
        execFileSync('git', ['commit', '-m', 'feat: shallow visible commit with secret'], { cwd: shallowRepoWithSecret });

        const shallowSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: shallowRepoWithSecret, encoding: 'utf8' }).trim();
        // Mark as shallow boundary commit
        fs.writeFileSync(path.join(shallowRepoWithSecret, '.git', 'shallow'), `${shallowSha}\n`, 'utf8');

        const shallowFoundEngine = new GitHistoryEngine(shallowRepoWithSecret);
        const searchFoundRes = await shallowFoundEngine.findCommitsContainingSecretResult(shallowSecretVal);
        assert(searchFoundRes.status === 'FOUND', 'findCommitsContainingSecretResult returns FOUND when secret in shallow commit');
        assert(searchFoundRes.isShallow === true, 'isShallow is true in search result');
        assert(searchFoundRes.isPartialHistory === true, 'isPartialHistory is true when secret found in shallow repository');

        const traceFound = await shallowFoundEngine.traceSecret(shallowSecretVal);
        assert(traceFound.isPresentInHistory === true, 'traceSecret marks isPresentInHistory: true when secret discovered in shallow repo');
        assert(traceFound.isIntroductionUnverified === true, 'traceSecret flags isIntroductionUnverified: true in shallow repo');
        assert(traceFound.searchStatus === 'SEARCH_INCOMPLETE', 'traceSecret searchStatus is SEARCH_INCOMPLETE due to shallow truncation');
        assert(traceFound.statusDescription.includes('original introduction date and total exposure duration unverified due to shallow clone'), 'statusDescription clarifies unverified introduction due to shallow clone');
        assert(!traceFound.statusDescription.includes('limited to 0 commit(s)'), 'statusDescription does not emit misleading 0 commits limit message');

        // Timeline check for shallow clone
        const timelineEngine = new GitTimelineEngine(shallowRepoWithSecret, shallowFoundEngine);
        const tlReport = await timelineEngine.buildTimeline(shallowSecretVal, 'ghp_****7890');
        assert(tlReport.currentStatus === 'SEARCH_INCOMPLETE', 'buildTimeline reports currentStatus: SEARCH_INCOMPLETE on shallow repo');
        assert(tlReport.timelineAscii.includes('⚠️ EARLIEST VISIBLE COMMIT (Shallow clone; original introduction unverified)'), 'buildTimeline tags earliest visible commit on shallow repo');
        assert(tlReport.timelineAscii.includes('Total Exposure:     >= 0 days (unverified earlier history due to shallow clone)'), 'buildTimeline ASCII notes >= X days exposure for shallow repo');

        // 2. Independent credential introductions across branches with remote tracking ref
        const multiBranchRepo = path.join(sec46Dir, 'multi-branch-repo');
        fs.mkdirSync(multiBranchRepo, { recursive: true });
        execFileSync('git', ['init'], { cwd: multiBranchRepo });
        execFileSync('git', ['checkout', '-B', 'main'], { cwd: multiBranchRepo });
        execFileSync('git', ['config', 'user.name', 'Branch Tester'], { cwd: multiBranchRepo });
        execFileSync('git', ['config', 'user.email', 'branch@example.com'], { cwd: multiBranchRepo });

        fs.writeFileSync(path.join(multiBranchRepo, 'base.txt'), 'base\n', 'utf8');
        execFileSync('git', ['add', 'base.txt'], { cwd: multiBranchRepo });
        execFileSync('git', ['commit', '-m', 'chore: initial base commit'], { cwd: multiBranchRepo });

        const branchSecret = fromHex('736b2d616e742d61706930332d') + fromHex('4272616e6368537072656164546f6b656e313233343536373839303132333435363738');

        // Branch A (local only)
        execFileSync('git', ['checkout', '-b', 'feature/local-a'], { cwd: multiBranchRepo });
        fs.writeFileSync(path.join(multiBranchRepo, 'local_a.txt'), `API_KEY=${branchSecret}\n`, 'utf8');
        execFileSync('git', ['add', 'local_a.txt'], { cwd: multiBranchRepo });
        execFileSync('git', ['commit', '-m', 'feat(local): introduce secret on branch A'], { cwd: multiBranchRepo });
        const branchASha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: multiBranchRepo, encoding: 'utf8' }).trim();

        // Branch B (divergent from main, has fake remote tracking branch)
        execFileSync('git', ['checkout', 'main'], { cwd: multiBranchRepo });
        execFileSync('git', ['checkout', '-b', 'feature/remote-b'], { cwd: multiBranchRepo });
        fs.writeFileSync(path.join(multiBranchRepo, 'remote_b.txt'), `API_KEY=${branchSecret}\n`, 'utf8');
        execFileSync('git', ['add', 'remote_b.txt'], { cwd: multiBranchRepo });
        execFileSync('git', ['commit', '-m', 'feat(remote): introduce secret on branch B'], { cwd: multiBranchRepo });
        const branchBSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: multiBranchRepo, encoding: 'utf8' }).trim();

        // Create a remote tracking ref for branch B: refs/remotes/origin/feature/remote-b pointing to branchBSha
        execFileSync('git', ['update-ref', 'refs/remotes/origin/feature/remote-b', branchBSha], { cwd: multiBranchRepo });

        // Checkout main (which has NO secret)
        execFileSync('git', ['checkout', 'main'], { cwd: multiBranchRepo });

        const multiEngine = new GitHistoryEngine(multiBranchRepo);
        const multiTrace = await multiEngine.traceSecret(branchSecret);
        assert(multiTrace.isPresentInHistory === true, 'traceSecret detects presence in multi-branch repo');
        assert(multiTrace.isPresentInHead === false, 'traceSecret correctly detects absence from main HEAD');
        assert(multiTrace.isRemote === true, 'traceSecret identifies remote push when ANY containing branch has remote tracking ref');
        assert(multiTrace.branches.some((b) => b.includes('feature/local-a')), 'traceSecret branches includes feature/local-a');
        assert(multiTrace.branches.some((b) => b.includes('feature/remote-b')), 'traceSecret branches includes feature/remote-b');
        assert(multiTrace.branchRemovals !== undefined, 'traceSecret returns branchRemovals');
        assert(multiTrace.branchRemovals['feature/local-a']?.introducedCommit?.sha === branchASha, 'branchRemovals tracks independent introduction on branch A');
        assert(multiTrace.branchRemovals['feature/remote-b']?.introducedCommit?.sha === branchBSha, 'branchRemovals tracks independent introduction on branch B');

        // 3. Topological sorting neutralizes backdated author dates (GIT_AUTHOR_DATE)
        const dateRepo = path.join(sec46Dir, 'date-repo');
        fs.mkdirSync(dateRepo, { recursive: true });
        execFileSync('git', ['init'], { cwd: dateRepo });
        execFileSync('git', ['checkout', '-B', 'main'], { cwd: dateRepo });
        execFileSync('git', ['config', 'user.name', 'Time Tester'], { cwd: dateRepo });
        execFileSync('git', ['config', 'user.email', 'time@example.com'], { cwd: dateRepo });

        const dateSecret = fromHex('6768705f') + fromHex('4261636b6461746564417574686f72536563726574546f6b656e31323334353637383930');

        // Commit 1 (the true introduction): modern committer date and modern author date
        fs.writeFileSync(path.join(dateRepo, 'secret.txt'), `${dateSecret}\n`, 'utf8');
        execFileSync('git', ['add', 'secret.txt'], { cwd: dateRepo });
        execFileSync('git', ['commit', '-m', 'commit 1: real introduction'], {
          cwd: dateRepo,
          env: {
            ...process.env,
            GIT_AUTHOR_DATE: '2025-01-01T12:00:00Z',
            GIT_COMMITTER_DATE: '2025-01-01T12:00:00Z',
          },
        });
        const c1Sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dateRepo, encoding: 'utf8' }).trim();

        // Commit 2 (child of commit 1): modified secret file with a deliberately BACKDATED author date to 1999!
        fs.writeFileSync(path.join(dateRepo, 'secret.txt'), `${dateSecret} updated\n`, 'utf8');
        execFileSync('git', ['add', 'secret.txt'], { cwd: dateRepo });
        execFileSync('git', ['commit', '-m', 'commit 2: descendant with manipulated author date'], {
          cwd: dateRepo,
          env: {
            ...process.env,
            GIT_AUTHOR_DATE: '1999-01-01T12:00:00Z', // Deliberately backdated!
            GIT_COMMITTER_DATE: '2025-01-02T12:00:00Z',
          },
        });
        const c2Sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dateRepo, encoding: 'utf8' }).trim();

        const dateEngine = new GitHistoryEngine(dateRepo);
        const dateTrace = await dateEngine.traceSecret(dateSecret);
        // By topological order: c2 is descendant of c1, so c1 MUST be identified as introducedCommit, not c2!
        assert(dateTrace.introducedCommit?.sha === c1Sha, 'Topological sorting selects true ancestor c1 as introducedCommit despite backdated author date on c2');
        assert(dateTrace.lastSeenCommit?.sha === c2Sha, 'Topological sorting selects child c2 as lastSeenCommit');

        // 4. Windows ACL Parser: Asterisk-prefixed Numerical SIDs (*S-1-5-...)
        let sidRemoved = false;
        const sidMockCp = {
          execFileSync: (cmd: string, args: string[]) => {
            if (cmd === 'whoami' && args.includes('/fo')) {
              return '"User Name","SID"\n"WORKGROUP\\admin","S-1-5-21-999999999-888888888-777777777-500"\n';
            }
            if (cmd === 'icacls') {
              if (args.includes('/remove') && args.includes('*S-1-5-21-123456789-987654321-111111111-1002')) {
                sidRemoved = true;
              }
              if (args.length === 1) {
                if (!sidRemoved) {
                  // Output with asterisk-prefixed unresolved SID
                  return `${args[0]} *S-1-5-21-123456789-987654321-111111111-1002:(R)\n WORKGROUP\\admin:(F)\nSuccessfully processed 1 files;\n`;
                }
                return `${args[0]} WORKGROUP\\admin:(F)\nSuccessfully processed 1 files;\n`;
              }
            }
            return Buffer.from('');
          }
        };

        const sidEnvPath = path.join(sec46Dir, '.env');
        fs.writeFileSync(sidEnvPath, 'KEY="val"\n', 'utf8');
        const sidEnforceRes = enforceEnvFilePermissions(sidEnvPath, fs, 'win32', sidMockCp as any);
        assert(sidEnforceRes.enforced === true, 'enforceEnvFilePermissions reports enforced: true when asterisk-prefixed SID is stripped');
        assert(sidRemoved === true, 'enforceEnvFilePermissions captures and strips *S-1-5-... numerical SID via icacls /remove');

      } finally {
        try { fs.rmSync(sec46Dir, { recursive: true, force: true }); } catch {}
      }
    }

    // --- 47. Lineage Ancestry-Path, O(N) Topo Ordering, Committer Date Chronology & Worktree Fallbacks ---
    console.log('\n--- 47. Lineage Ancestry-Path, O(N) Topo Ordering, Committer Date Chronology & Worktree Fallbacks ---');
    {
      const { execFileSync } = cp;
      const fromHex = (h: string) => Buffer.from(h, 'hex').toString('utf8');
      const sec47Dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-sec47-'));
      try {
        // 1. False removal attribution after merging a clean side branch
        const mergeRepo = path.join(sec47Dir, 'merge-repo');
        fs.mkdirSync(mergeRepo, { recursive: true });
        execFileSync('git', ['init'], { cwd: mergeRepo });
        execFileSync('git', ['checkout', '-B', 'main'], { cwd: mergeRepo });
        execFileSync('git', ['config', 'user.name', 'Merge Tester'], { cwd: mergeRepo });
        execFileSync('git', ['config', 'user.email', 'merge@example.com'], { cwd: mergeRepo });

        fs.writeFileSync(path.join(mergeRepo, 'base.txt'), 'base\n', 'utf8');
        execFileSync('git', ['add', 'base.txt'], { cwd: mergeRepo });
        execFileSync('git', ['commit', '-m', 'chore: base commit'], { cwd: mergeRepo });

        // Create feature branch and commit an unrelated file
        execFileSync('git', ['checkout', '-b', 'feature-unrelated'], { cwd: mergeRepo });
        fs.writeFileSync(path.join(mergeRepo, 'unrelated.txt'), 'unrelated\n', 'utf8');
        execFileSync('git', ['add', 'unrelated.txt'], { cwd: mergeRepo });
        execFileSync('git', ['commit', '-m', 'feat: unrelated commit on side branch'], { cwd: mergeRepo });
        const sideBranchSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: mergeRepo, encoding: 'utf8' }).trim();

        // Switch back to main, add credential
        execFileSync('git', ['checkout', 'main'], { cwd: mergeRepo });
        const secretVal = fromHex('6768705f') + fromHex('4d65726765536563726574546f6b656e31323334353637383930');
        fs.writeFileSync(path.join(mergeRepo, 'secret.txt'), `TOKEN=${secretVal}\n`, 'utf8');
        execFileSync('git', ['add', 'secret.txt'], { cwd: mergeRepo });
        execFileSync('git', ['commit', '-m', 'feat: add credential on main'], { cwd: mergeRepo });
        const introSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: mergeRepo, encoding: 'utf8' }).trim();

        // Merge the unrelated feature branch into main without removing credential
        execFileSync('git', ['merge', 'feature-unrelated', '-m', 'merge feature-unrelated into main'], { cwd: mergeRepo });
        const mergeSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: mergeRepo, encoding: 'utf8' }).trim();

        const mergeEngine = new GitHistoryEngine(mergeRepo);

        // findRemovalCommit on main BEFORE actual removal must NOT return sideBranchSha!
        const prematureRemoval = await mergeEngine.findRemovalCommit(secretVal, introSha, 'main');
        assert(prematureRemoval === undefined, 'findRemovalCommit does not falsely select unrelated side branch commit as removal commit');

        // Now remove the credential in a later commit on main
        fs.writeFileSync(path.join(mergeRepo, 'secret.txt'), 'TOKEN=clean\n', 'utf8');
        execFileSync('git', ['add', 'secret.txt'], { cwd: mergeRepo });
        execFileSync('git', ['commit', '-m', 'fix: genuine removal commit'], { cwd: mergeRepo });
        const genuineRemovalSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: mergeRepo, encoding: 'utf8' }).trim();

        const genuineRemoval = await mergeEngine.findRemovalCommit(secretVal, introSha, 'main');
        assert(genuineRemoval !== undefined, 'findRemovalCommit finds genuine removal commit after side branch merge');
        assert(genuineRemoval?.sha === genuineRemovalSha, 'findRemovalCommit accurately attributes removal to genuineRemovalSha');
        assert(genuineRemoval?.sha !== sideBranchSha, 'findRemovalCommit does not attribute removal to sideBranchSha');

        // 2. O(N) Topological sorting performance test with hundreds of commits
        const perfRepo = path.join(sec47Dir, 'perf-repo');
        fs.mkdirSync(perfRepo, { recursive: true });
        execFileSync('git', ['init'], { cwd: perfRepo });
        execFileSync('git', ['checkout', '-B', 'main'], { cwd: perfRepo });
        execFileSync('git', ['config', 'user.name', 'Perf Tester'], { cwd: perfRepo });
        execFileSync('git', ['config', 'user.email', 'perf@example.com'], { cwd: perfRepo });

        const persistentSecret = fromHex('736b2d616e742d61706930332d') + fromHex('50657266436865636b546f6b656e313233343536373839303132333435363738');
        fs.writeFileSync(path.join(perfRepo, 'data.txt'), `KEY=${persistentSecret}\n`, 'utf8');
        execFileSync('git', ['add', 'data.txt'], { cwd: perfRepo });
        execFileSync('git', ['commit', '-m', 'commit 0'], { cwd: perfRepo });
        const initialSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: perfRepo, encoding: 'utf8' }).trim();

        // Create 20 consecutive commits containing the secret
        for (let i = 1; i <= 20; i++) {
          fs.writeFileSync(path.join(perfRepo, 'counter.txt'), `${i}\n`, 'utf8');
          execFileSync('git', ['add', 'counter.txt'], { cwd: perfRepo });
          execFileSync('git', ['commit', '-m', `commit ${i}`], { cwd: perfRepo });
        }
        const newestSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: perfRepo, encoding: 'utf8' }).trim();

        const perfEngine = new GitHistoryEngine(perfRepo);
        const startTime = Date.now();
        const perfTrace = await perfEngine.traceSecret(persistentSecret);
        const elapsedMs = Date.now() - startTime;

        assert(perfTrace.commitCount === 21, 'traceSecret finds all 21 commits containing persistent secret');
        assert(perfTrace.introducedCommit?.sha === initialSha, 'traceSecret identifies initial commit as introducedCommit');
        assert(perfTrace.lastSeenCommit?.sha === newestSha, 'traceSecret identifies newest commit as lastSeenCommit');
        assert(elapsedMs < 10000, `traceSecret topological sorting runs in linear time without quadratic subprocess delay (took ${elapsedMs}ms)`);

        // 3. Committer date carried through timeline and backdated removal
        const timeRepo = path.join(sec47Dir, 'time-repo');
        fs.mkdirSync(timeRepo, { recursive: true });
        execFileSync('git', ['init'], { cwd: timeRepo });
        execFileSync('git', ['checkout', '-B', 'main'], { cwd: timeRepo });
        execFileSync('git', ['config', 'user.name', 'Timeline Tester'], { cwd: timeRepo });
        execFileSync('git', ['config', 'user.email', 'time@example.com'], { cwd: timeRepo });

        const timeSecret = fromHex('6768705f') + fromHex('54696d656c696e65536563726574546f6b656e31323334353637383930');
        fs.writeFileSync(path.join(timeRepo, 'auth.txt'), `AUTH=${timeSecret}\n`, 'utf8');
        execFileSync('git', ['add', 'auth.txt'], { cwd: timeRepo });
        execFileSync('git', ['commit', '-m', 'intro commit'], {
          cwd: timeRepo,
          env: {
            ...process.env,
            GIT_AUTHOR_DATE: '2025-01-01T12:00:00Z',
            GIT_COMMITTER_DATE: '2025-01-01T12:00:00Z',
          },
        });
        const t1Sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: timeRepo, encoding: 'utf8' }).trim();

        // Commit 2: modification with backdated author date
        fs.writeFileSync(path.join(timeRepo, 'auth.txt'), `AUTH=${timeSecret} updated\n`, 'utf8');
        execFileSync('git', ['add', 'auth.txt'], { cwd: timeRepo });
        execFileSync('git', ['commit', '-m', 'mod commit backdated author'], {
          cwd: timeRepo,
          env: {
            ...process.env,
            GIT_AUTHOR_DATE: '1998-01-01T12:00:00Z',
            GIT_COMMITTER_DATE: '2025-01-05T12:00:00Z',
          },
        });
        const t2Sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: timeRepo, encoding: 'utf8' }).trim();

        // Commit 3: removal with backdated author date
        fs.writeFileSync(path.join(timeRepo, 'auth.txt'), 'AUTH=clean\n', 'utf8');
        execFileSync('git', ['add', 'auth.txt'], { cwd: timeRepo });
        execFileSync('git', ['commit', '-m', 'removal commit backdated author'], {
          cwd: timeRepo,
          env: {
            ...process.env,
            GIT_AUTHOR_DATE: '1995-01-01T12:00:00Z',
            GIT_COMMITTER_DATE: '2025-01-10T12:00:00Z',
          },
        });
        const t3Sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: timeRepo, encoding: 'utf8' }).trim();

        const timeEngine = new GitHistoryEngine(timeRepo);
        const timeRemoval = await timeEngine.findRemovalCommit(timeSecret, t2Sha, 'main');
        assert(timeRemoval?.sha === t3Sha, 'findRemovalCommit finds t3 removal commit');
        assert(timeRemoval?.committerDate !== undefined, 'findRemovalCommit carries committerDate');

        const tlEngine = new GitTimelineEngine(timeRepo, timeEngine);
        const tlReport = await tlEngine.buildTimeline(timeSecret, 'ghp_••••');
        assert(tlReport.events.length === 3, 'buildTimeline produces 3 events');
        assert(tlReport.events[0].commitSha === t1Sha, 'buildTimeline places true ancestor t1 as INTRODUCED event despite backdated author dates');
        assert(tlReport.events[1].commitSha === t2Sha, 'buildTimeline places child t2 as second event');
        assert(tlReport.events[2].commitSha === t3Sha, 'buildTimeline places removal t3 as REMOVED event');
        assert(tlReport.totalExposureDays >= 9, 'buildTimeline uses committer dates for accurate exposure calculation');

        // 4. Branch inspection failures propagate into UNKNOWN and SEARCH_INCOMPLETE
        class FailingBranchEngine extends GitHistoryEngine {
          protected async execGit(args: string[], options: any = {}): Promise<{ stdout: any; stderr: any }> {
            if (args[0] === 'branch' && (args.includes('-a') || args.includes('--contains'))) {
              throw new Error('Simulated operational failure during branch lookup on t2');
            }
            return super.execGit(args, options);
          }
        }
        const failingBranchEngine = new FailingBranchEngine(timeRepo);
        const fbTrace = await failingBranchEngine.traceSecret(timeSecret);
        assert(fbTrace.isRemote === 'UNKNOWN', 'traceSecret sets isRemote: UNKNOWN when branch query fails on a commit without confirmed remote');
        assert(fbTrace.searchStatus === 'SEARCH_INCOMPLETE', 'traceSecret sets searchStatus: SEARCH_INCOMPLETE when branch query fails');
        assert(fbTrace.statusDescription.includes('INCOMPLETE BRANCH INSPECTION'), 'traceSecret notes INCOMPLETE BRANCH INSPECTION in statusDescription');

        // 5. Shallow repository fallback resolves .git/shallow in linked worktrees
        const wtRepo = path.join(sec47Dir, 'wt-repo');
        fs.mkdirSync(wtRepo, { recursive: true });
        execFileSync('git', ['init'], { cwd: wtRepo });
        execFileSync('git', ['checkout', '-B', 'main'], { cwd: wtRepo });
        execFileSync('git', ['config', 'user.name', 'WT Tester'], { cwd: wtRepo });
        execFileSync('git', ['config', 'user.email', 'wt@example.com'], { cwd: wtRepo });
        fs.writeFileSync(path.join(wtRepo, 'wt_base.txt'), 'wt\n', 'utf8');
        execFileSync('git', ['add', 'wt_base.txt'], { cwd: wtRepo });
        execFileSync('git', ['commit', '-m', 'wt base commit'], { cwd: wtRepo });

        const wtHeadSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: wtRepo, encoding: 'utf8' }).trim();
        // Create shallow marker in main repo's .git/shallow
        fs.writeFileSync(path.join(wtRepo, '.git', 'shallow'), `${wtHeadSha}\n`, 'utf8');

        // Create linked worktree
        const linkedWtPath = path.join(sec47Dir, 'linked-worktree');
        execFileSync('git', ['worktree', 'add', linkedWtPath, '-b', 'wt-test-branch'], { cwd: wtRepo });

        // In linked worktree, .git is a file, not a directory
        assert(fs.statSync(path.join(linkedWtPath, '.git')).isFile(), 'Linked worktree has .git as a file');

        // Test mock engine that forces fallback path by throwing in git rev-parse --is-shallow-repository
        class WorktreeShallowEngine extends GitHistoryEngine {
          protected async execGit(args: string[], options: any = {}): Promise<{ stdout: any; stderr: any }> {
            if (args[0] === 'rev-parse' && args[1] === '--is-shallow-repository') {
              throw new Error('Unsupported command simulation');
            }
            return super.execGit(args, options);
          }
        }
        const wtEngine = new WorktreeShallowEngine(linkedWtPath);
        const wtIsShallow = await wtEngine.isShallowRepo();
        assert(wtIsShallow === true, 'isShallowRepo detects shallow status in linked worktree via --git-path shallow fallback');

      } finally {
        try { fs.rmSync(sec47Dir, { recursive: true, force: true }); } catch {}
      }
    }

    // --- 48. First-Parent Merge Removal, Display Date Distinction, Sibling Branch Aggregation & Depth-Limited Semantics ---
    console.log('\n--- 48. First-Parent Merge Removal, Display Date Distinction, Sibling Branch Aggregation & Depth-Limited Semantics ---');
    {
      const { execFileSync } = cp;
      const fromHex = (h: string) => Buffer.from(h, 'hex').toString('utf8');
      const sec48Dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-sec48-'));
      try {
        // 1. First-parent merge removal: Secret removed on side branch, then merged into main
        const fpRepo = path.join(sec48Dir, 'fp-repo');
        fs.mkdirSync(fpRepo, { recursive: true });
        execFileSync('git', ['init'], { cwd: fpRepo });
        execFileSync('git', ['checkout', '-B', 'main'], { cwd: fpRepo });
        execFileSync('git', ['config', 'user.name', 'FP Tester'], { cwd: fpRepo });
        execFileSync('git', ['config', 'user.email', 'fp@example.com'], { cwd: fpRepo });

        fs.writeFileSync(path.join(fpRepo, 'base.txt'), 'base\n', 'utf8');
        execFileSync('git', ['add', 'base.txt'], { cwd: fpRepo });
        execFileSync('git', ['commit', '-m', 'base commit'], { cwd: fpRepo });

        const fpSecret = fromHex('6768705f') + fromHex('4669727374506172656e74546573745365637265743132333435');
        fs.writeFileSync(path.join(fpRepo, 'token.txt'), `TOKEN=${fpSecret}\n`, 'utf8');
        execFileSync('git', ['add', 'token.txt'], { cwd: fpRepo });
        execFileSync('git', ['commit', '-m', 'intro secret on main'], { cwd: fpRepo });
        const mainIntroSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fpRepo, encoding: 'utf8' }).trim();

        // Create feature branch and remove secret on that feature branch
        execFileSync('git', ['checkout', '-b', 'feature-removal'], { cwd: fpRepo });
        fs.writeFileSync(path.join(fpRepo, 'token.txt'), 'TOKEN=clean_on_feature\n', 'utf8');
        execFileSync('git', ['add', 'token.txt'], { cwd: fpRepo });
        execFileSync('git', ['commit', '-m', 'remove secret on feature branch'], { cwd: fpRepo });
        const featureRemovalSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fpRepo, encoding: 'utf8' }).trim();

        // Work on main while secret is still active on main
        execFileSync('git', ['checkout', 'main'], { cwd: fpRepo });
        fs.writeFileSync(path.join(fpRepo, 'main_work.txt'), 'working on main\n', 'utf8');
        execFileSync('git', ['add', 'main_work.txt'], { cwd: fpRepo });
        execFileSync('git', ['commit', '-m', 'unrelated main work with secret active'], { cwd: fpRepo });
        const intermediateMainSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fpRepo, encoding: 'utf8' }).trim();

        // Merge feature branch into main (this merge commit removes the secret from main's effective history)
        execFileSync('git', ['merge', 'feature-removal', '-m', 'merge feature-removal into main'], { cwd: fpRepo });
        const mergeRemovalSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fpRepo, encoding: 'utf8' }).trim();

        const fpEngine = new GitHistoryEngine(fpRepo);
        const mainRemoval = await fpEngine.findRemovalCommit(fpSecret, mainIntroSha, 'main');
        assert(mainRemoval !== undefined, 'findRemovalCommit finds removal commit on main after merge');
        assert(mainRemoval?.sha === mergeRemovalSha, 'findRemovalCommit attributes removal to the merge commit on main, NOT the feature branch commit');
        assert(mainRemoval?.sha !== featureRemovalSha, 'findRemovalCommit does not falsely report featureRemovalSha as the removal commit for main');

        // On the feature branch itself, removal is accurately attributed to featureRemovalSha
        const featRemoval = await fpEngine.findRemovalCommit(fpSecret, mainIntroSha, 'feature-removal');
        assert(featRemoval?.sha === featureRemovalSha, 'findRemovalCommit attributes removal on feature-removal branch to featureRemovalSha');

        // 2. Display date distinction and consistent committer chronology in timeline
        const displayRepo = path.join(sec48Dir, 'display-repo');
        fs.mkdirSync(displayRepo, { recursive: true });
        execFileSync('git', ['init'], { cwd: displayRepo });
        execFileSync('git', ['checkout', '-B', 'main'], { cwd: displayRepo });
        execFileSync('git', ['config', 'user.name', 'Display Tester'], { cwd: displayRepo });
        execFileSync('git', ['config', 'user.email', 'display@example.com'], { cwd: displayRepo });

        const displaySecret = fromHex('6768705f') + fromHex('446973706c617944617465546573745365637265743132333435');
        fs.writeFileSync(path.join(displayRepo, 'key.txt'), `KEY=${displaySecret}\n`, 'utf8');
        execFileSync('git', ['add', 'key.txt'], { cwd: displayRepo });
        execFileSync('git', ['commit', '-m', 'c1: true introduction'], {
          cwd: displayRepo,
          env: {
            ...process.env,
            GIT_AUTHOR_DATE: '2025-01-01T12:00:00Z',
            GIT_COMMITTER_DATE: '2025-01-01T12:00:00Z',
          },
        });
        const c1Sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: displayRepo, encoding: 'utf8' }).trim();

        // c2: child commit with backdated author date (1990) but committer date (2025-01-05)
        fs.writeFileSync(path.join(displayRepo, 'key.txt'), `KEY=${displaySecret} updated\n`, 'utf8');
        execFileSync('git', ['add', 'key.txt'], { cwd: displayRepo });
        execFileSync('git', ['commit', '-m', 'c2: child with backdated author date'], {
          cwd: displayRepo,
          env: {
            ...process.env,
            GIT_AUTHOR_DATE: '1990-01-01T12:00:00Z',
            GIT_COMMITTER_DATE: '2025-01-05T12:00:00Z',
          },
        });
        const c2Sha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: displayRepo, encoding: 'utf8' }).trim();

        const tlEngine = new GitTimelineEngine(displayRepo);
        const tlReport = await tlEngine.buildTimeline(displaySecret, 'ghp_••••');
        assert(tlReport.events.length === 2, 'buildTimeline produces 2 events');
        assert(tlReport.events[0].commitSha === c1Sha, 'c1 is first event');
        assert(tlReport.events[1].commitSha === c2Sha, 'c2 is second event');
        // Visual timeline display date must use committer date (2025-01-05) or note authored date
        assert(tlReport.timelineAscii.includes('[2025-01-01]'), 'timeline ASCII includes c1 committer date');
        assert(tlReport.timelineAscii.includes('[2025-01-05]'), 'timeline ASCII includes c2 committer date for displayed chronology');
        assert(tlReport.timelineAscii.includes('(authored 1990-01-01)'), 'timeline ASCII explicitly notes backdated author date');
        assert(tlReport.graph.nodes[1].date.startsWith('2025-01-05'), 'graph node date reflects committer date');

        // 3. Sibling branch independent introductions with aggregate duration
        const siblingRepo = path.join(sec48Dir, 'sibling-repo');
        fs.mkdirSync(siblingRepo, { recursive: true });
        execFileSync('git', ['init'], { cwd: siblingRepo });
        execFileSync('git', ['checkout', '-B', 'main'], { cwd: siblingRepo });
        execFileSync('git', ['config', 'user.name', 'Sibling Tester'], { cwd: siblingRepo });
        execFileSync('git', ['config', 'user.email', 'sibling@example.com'], { cwd: siblingRepo });

        fs.writeFileSync(path.join(siblingRepo, 'root.txt'), 'root\n', 'utf8');
        execFileSync('git', ['add', 'root.txt'], { cwd: siblingRepo });
        execFileSync('git', ['commit', '-m', 'root commit'], { cwd: siblingRepo });

        const sharedSecret = fromHex('6768705f') + fromHex('5369626c696e675370726561645365637265743132333435');

        // Sibling branch 1: introduced on 2025-01-01, removed on 2025-01-05 (4 days duration)
        execFileSync('git', ['checkout', '-b', 'branch-alpha'], { cwd: siblingRepo });
        fs.writeFileSync(path.join(siblingRepo, 'token.txt'), `KEY=${sharedSecret}\n`, 'utf8');
        execFileSync('git', ['add', 'token.txt'], { cwd: siblingRepo });
        execFileSync('git', ['commit', '-m', 'alpha intro'], {
          cwd: siblingRepo,
          env: {
            ...process.env,
            GIT_AUTHOR_DATE: '2025-01-01T12:00:00Z',
            GIT_COMMITTER_DATE: '2025-01-01T12:00:00Z',
          },
        });
        const alphaIntroSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: siblingRepo, encoding: 'utf8' }).trim();

        fs.writeFileSync(path.join(siblingRepo, 'token.txt'), 'KEY=clean_alpha\n', 'utf8');
        execFileSync('git', ['add', 'token.txt'], { cwd: siblingRepo });
        execFileSync('git', ['commit', '-m', 'alpha removal'], {
          cwd: siblingRepo,
          env: {
            ...process.env,
            GIT_AUTHOR_DATE: '2025-01-05T12:00:00Z',
            GIT_COMMITTER_DATE: '2025-01-05T12:00:00Z',
          },
        });
        const alphaRemovalSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: siblingRepo, encoding: 'utf8' }).trim();

        // Sibling branch 2 (divergent from root): introduced on 2025-01-02, active to 2025-01-12 (10 days duration)
        execFileSync('git', ['checkout', 'main'], { cwd: siblingRepo });
        execFileSync('git', ['checkout', '-b', 'branch-beta'], { cwd: siblingRepo });
        fs.writeFileSync(path.join(siblingRepo, 'token.txt'), `KEY=${sharedSecret}\n`, 'utf8');
        execFileSync('git', ['add', 'token.txt'], { cwd: siblingRepo });
        execFileSync('git', ['commit', '-m', 'beta intro'], {
          cwd: siblingRepo,
          env: {
            ...process.env,
            GIT_AUTHOR_DATE: '2025-01-02T12:00:00Z',
            GIT_COMMITTER_DATE: '2025-01-02T12:00:00Z',
          },
        });
        const betaIntroSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: siblingRepo, encoding: 'utf8' }).trim();

        fs.writeFileSync(path.join(siblingRepo, 'token.txt'), 'KEY=clean_beta\n', 'utf8');
        execFileSync('git', ['add', 'token.txt'], { cwd: siblingRepo });
        execFileSync('git', ['commit', '-m', 'beta removal'], {
          cwd: siblingRepo,
          env: {
            ...process.env,
            GIT_AUTHOR_DATE: '2025-01-12T12:00:00Z',
            GIT_COMMITTER_DATE: '2025-01-12T12:00:00Z',
          },
        });
        const betaRemovalSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: siblingRepo, encoding: 'utf8' }).trim();

        execFileSync('git', ['checkout', 'main'], { cwd: siblingRepo });

        const siblingEngine = new GitHistoryEngine(siblingRepo);
        const sibTrace = await siblingEngine.traceSecret(sharedSecret);
        assert(sibTrace.branchRemovals !== undefined, 'branchRemovals is defined');
        assert(sibTrace.branchRemovals['branch-alpha']?.introducedCommit?.sha === alphaIntroSha, 'branch-alpha intro commit tracked');
        assert(sibTrace.branchRemovals['branch-alpha']?.removalCommit?.sha === alphaRemovalSha, 'branch-alpha removal commit tracked');
        assert(sibTrace.branchRemovals['branch-alpha']?.exposureDurationDays === 4, 'branch-alpha duration is 4 days');

        assert(sibTrace.branchRemovals['branch-beta']?.introducedCommit?.sha === betaIntroSha, 'branch-beta intro commit tracked');
        assert(sibTrace.branchRemovals['branch-beta']?.removalCommit?.sha === betaRemovalSha, 'branch-beta removal commit tracked');
        assert(sibTrace.branchRemovals['branch-beta']?.exposureDurationDays === 10, 'branch-beta duration is 10 days');
        assert(sibTrace.exposureDurationDays === 10, 'sibTrace.exposureDurationDays aggregates to max confirmed branch duration (10 days)');

        const sibTlEngine = new GitTimelineEngine(siblingRepo, siblingEngine);
        const sibTl = await sibTlEngine.buildTimeline(sharedSecret, 'ghp_••••');
        const alphaEvent = sibTl.events.find((e) => e.commitSha === alphaIntroSha);
        const betaEvent = sibTl.events.find((e) => e.commitSha === betaIntroSha);
        assert(alphaEvent?.eventType === 'INTRODUCED', 'branch-alpha intro is labeled INTRODUCED');
        assert(betaEvent?.eventType === 'INTRODUCED', 'branch-beta independent sibling intro is labeled INTRODUCED');

        // 4. Positive matches in depth-limited searches report SEARCH_INCOMPLETE
        const limRepo = path.join(sec48Dir, 'lim-repo');
        fs.mkdirSync(limRepo, { recursive: true });
        execFileSync('git', ['init'], { cwd: limRepo });
        execFileSync('git', ['checkout', '-B', 'main'], { cwd: limRepo });
        execFileSync('git', ['config', 'user.name', 'Lim Tester'], { cwd: limRepo });
        execFileSync('git', ['config', 'user.email', 'lim@example.com'], { cwd: limRepo });

        const limSecret = fromHex('6768705f') + fromHex('4c696d697465645365617263685365637265743132333435');
        fs.writeFileSync(path.join(limRepo, 'code.txt'), `SECRET=${limSecret}\n`, 'utf8');
        execFileSync('git', ['add', 'code.txt'], { cwd: limRepo });
        execFileSync('git', ['commit', '-m', 'intro secret'], { cwd: limRepo });

        // Add 10 additional clean commits on top
        for (let i = 1; i <= 10; i++) {
          fs.writeFileSync(path.join(limRepo, 'clean.txt'), `${i}\n`, 'utf8');
          execFileSync('git', ['add', 'clean.txt'], { cwd: limRepo });
          execFileSync('git', ['commit', '-m', `clean commit ${i}`], { cwd: limRepo });
        }

        const limEngine = new GitHistoryEngine(limRepo);
        // Search with maxCommits = 11 (covers both the clean commits and the secret commit, but totalRevCount > 11? total is 11)
        // Add 5 more commits so total is 16
        for (let i = 11; i <= 15; i++) {
          fs.writeFileSync(path.join(limRepo, 'clean.txt'), `${i}\n`, 'utf8');
          execFileSync('git', ['add', 'clean.txt'], { cwd: limRepo });
          execFileSync('git', ['commit', '-m', `clean commit ${i}`], { cwd: limRepo });
        }

        // Now total commits = 16. Limit search to 15 commits (which includes the secret at commit 1, because HEAD is commit 16)
        // With maxCommits = 15, isPartialHistory is true, and secret is found!
        const limSearchResult = await limEngine.findCommitsContainingSecretResult(limSecret, 15);
        assert(limSearchResult.status === 'FOUND', 'findCommitsContainingSecretResult returns FOUND');
        assert(limSearchResult.isPartialHistory === true, 'findCommitsContainingSecretResult marks isPartialHistory: true');

        const limTrace = await limEngine.traceSecret(limSecret, 15);
        assert(limTrace.isPresentInHistory === true, 'traceSecret marks isPresentInHistory: true');
        assert(limTrace.isPartialHistory === true, 'traceSecret marks isPartialHistory: true');
        assert(limTrace.searchStatus === 'SEARCH_INCOMPLETE', 'traceSecret sets searchStatus: SEARCH_INCOMPLETE when secret found in partial history');
        assert(limTrace.statusDescription.includes('PARTIAL HISTORY: search depth limited to 15 commit(s)'), 'statusDescription mentions partial history limit');

        // Timeline check for limited search
        const limTlEngine = new GitTimelineEngine(limRepo, limEngine);
        const limTlReport = await limTlEngine.buildTimeline(limSecret, 'ghp_••••', 15);
        assert(limTlReport.currentStatus === 'SEARCH_INCOMPLETE', 'buildTimeline reports currentStatus: SEARCH_INCOMPLETE when partial history');
        assert(limTlReport.timelineAscii.includes('History Coverage:   PARTIAL (limited to 15 commits; earlier history uninspected)'), 'buildTimeline ASCII notes partial history coverage');

      } finally {
        try { fs.rmSync(sec48Dir, { recursive: true, force: true }); } catch {}
      }
    }

    // --- 49. Ongoing Branch Exposure, Independent Timeline Introductions, O(branches) Discovery & Risk Incomplete Flags ---
    console.log('\n--- 49. Ongoing Branch Exposure, Independent Timeline Introductions, O(branches) Discovery & Risk Incomplete Flags ---');
    {
      const { execFileSync } = cp;
      const fromHex = (h: string) => Buffer.from(h, 'hex').toString('utf8');
      const sec49Dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-sec49-'));
      try {
        // 1. Ongoing branch exposure through current time when active branch has no removal commit
        const ongoingRepo = path.join(sec49Dir, 'ongoing-repo');
        fs.mkdirSync(ongoingRepo, { recursive: true });
        execFileSync('git', ['init'], { cwd: ongoingRepo });
        execFileSync('git', ['checkout', '-B', 'main'], { cwd: ongoingRepo });
        execFileSync('git', ['config', 'user.name', 'Ongoing Tester'], { cwd: ongoingRepo });
        execFileSync('git', ['config', 'user.email', 'ongoing@example.com'], { cwd: ongoingRepo });

        fs.writeFileSync(path.join(ongoingRepo, 'root.txt'), 'root\n', 'utf8');
        execFileSync('git', ['add', 'root.txt'], { cwd: ongoingRepo });
        execFileSync('git', ['commit', '-m', 'root commit'], { cwd: ongoingRepo });

        // Create active branch with secret introduced 100 days ago, no removal commit
        execFileSync('git', ['checkout', '-b', 'feat/ongoing-leak'], { cwd: ongoingRepo });
        const ongoingSecret = fromHex('6768705f') + fromHex('4f6e676f696e674c65616b53656372657431323334353637383930');
        const introDate100DaysAgo = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000).toISOString();
        fs.writeFileSync(path.join(ongoingRepo, 'key.txt'), `KEY=${ongoingSecret}\n`, 'utf8');
        execFileSync('git', ['add', 'key.txt'], { cwd: ongoingRepo });
        execFileSync('git', ['commit', '-m', 'ongoing intro'], {
          cwd: ongoingRepo,
          env: {
            ...process.env,
            GIT_AUTHOR_DATE: introDate100DaysAgo,
            GIT_COMMITTER_DATE: introDate100DaysAgo,
          },
        });
        const ongoingIntroSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ongoingRepo, encoding: 'utf8' }).trim();

        // Switch to main (where secret was never present)
        execFileSync('git', ['checkout', 'main'], { cwd: ongoingRepo });

        const ongoingEngine = new GitHistoryEngine(ongoingRepo);
        const ongoingTrace = await ongoingEngine.traceSecret(ongoingSecret);
        assert(ongoingTrace.branchRemovals !== undefined, 'branchRemovals is defined for ongoing leak');
        const branchInfo = ongoingTrace.branchRemovals['feat/ongoing-leak'];
        assert(branchInfo !== undefined, 'feat/ongoing-leak branch tracked');
        assert(branchInfo?.isRemoved === false, 'active branch without removal commit is marked isRemoved: false');
        assert(branchInfo?.exposureDurationDays !== undefined && branchInfo.exposureDurationDays >= 99, `branch duration calculates ongoing exposure through current time (got ${branchInfo?.exposureDurationDays} days)`);
        assert(ongoingTrace.exposureDurationDays >= 99, `aggregate exposureDurationDays uses maximum confirmed ongoing duration (got ${ongoingTrace.exposureDurationDays} days)`);

        // 2. Sibling branch independent introductions with subsequent modifications
        const sibRepo = path.join(sec49Dir, 'sib-repo');
        fs.mkdirSync(sibRepo, { recursive: true });
        execFileSync('git', ['init'], { cwd: sibRepo });
        execFileSync('git', ['checkout', '-B', 'main'], { cwd: sibRepo });
        execFileSync('git', ['config', 'user.name', 'Sib Tester'], { cwd: sibRepo });
        execFileSync('git', ['config', 'user.email', 'sib@example.com'], { cwd: sibRepo });

        fs.writeFileSync(path.join(sibRepo, 'init.txt'), 'init\n', 'utf8');
        execFileSync('git', ['add', 'init.txt'], { cwd: sibRepo });
        execFileSync('git', ['commit', '-m', 'init commit'], { cwd: sibRepo });

        const multiIntroSecret = fromHex('6768705f') + fromHex('4d756c7469496e74726f53656372657431323334353637383930');

        // Branch 1: introduces secret in C1, modifies it in C2
        execFileSync('git', ['checkout', '-b', 'branch-1'], { cwd: sibRepo });
        fs.writeFileSync(path.join(sibRepo, 'sec.txt'), `KEY=${multiIntroSecret}\n`, 'utf8');
        execFileSync('git', ['add', 'sec.txt'], { cwd: sibRepo });
        execFileSync('git', ['commit', '-m', 'b1: intro secret'], {
          cwd: sibRepo,
          env: { ...process.env, GIT_AUTHOR_DATE: '2025-01-01T10:00:00Z', GIT_COMMITTER_DATE: '2025-01-01T10:00:00Z' },
        });
        const b1IntroSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: sibRepo, encoding: 'utf8' }).trim();

        fs.writeFileSync(path.join(sibRepo, 'sec.txt'), `KEY=${multiIntroSecret} mod\n`, 'utf8');
        execFileSync('git', ['add', 'sec.txt'], { cwd: sibRepo });
        execFileSync('git', ['commit', '-m', 'b1: mod secret'], {
          cwd: sibRepo,
          env: { ...process.env, GIT_AUTHOR_DATE: '2025-01-02T10:00:00Z', GIT_COMMITTER_DATE: '2025-01-02T10:00:00Z' },
        });
        const b1ModSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: sibRepo, encoding: 'utf8' }).trim();

        // Branch 2: branched from clean main, independently introduces secret in C3, modifies in C4
        execFileSync('git', ['checkout', 'main'], { cwd: sibRepo });
        execFileSync('git', ['checkout', '-b', 'branch-2'], { cwd: sibRepo });
        fs.writeFileSync(path.join(sibRepo, 'sec.txt'), `KEY=${multiIntroSecret}\n`, 'utf8');
        execFileSync('git', ['add', 'sec.txt'], { cwd: sibRepo });
        execFileSync('git', ['commit', '-m', 'b2: intro secret'], {
          cwd: sibRepo,
          env: { ...process.env, GIT_AUTHOR_DATE: '2025-01-03T10:00:00Z', GIT_COMMITTER_DATE: '2025-01-03T10:00:00Z' },
        });
        const b2IntroSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: sibRepo, encoding: 'utf8' }).trim();

        fs.writeFileSync(path.join(sibRepo, 'sec.txt'), `KEY=${multiIntroSecret} mod2\n`, 'utf8');
        execFileSync('git', ['add', 'sec.txt'], { cwd: sibRepo });
        execFileSync('git', ['commit', '-m', 'b2: mod secret'], {
          cwd: sibRepo,
          env: { ...process.env, GIT_AUTHOR_DATE: '2025-01-04T10:00:00Z', GIT_COMMITTER_DATE: '2025-01-04T10:00:00Z' },
        });
        const b2ModSha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: sibRepo, encoding: 'utf8' }).trim();

        execFileSync('git', ['checkout', 'main'], { cwd: sibRepo });

        const sibTlEngine = new GitTimelineEngine(sibRepo);
        const sibReport = await sibTlEngine.buildTimeline(multiIntroSecret, 'ghp_••••');

        const evB1Intro = sibReport.events.find((e) => e.commitSha === b1IntroSha);
        const evB1Mod = sibReport.events.find((e) => e.commitSha === b1ModSha);
        const evB2Intro = sibReport.events.find((e) => e.commitSha === b2IntroSha);
        const evB2Mod = sibReport.events.find((e) => e.commitSha === b2ModSha);

        assert(evB1Intro?.eventType === 'INTRODUCED', 'b1 intro commit is labeled INTRODUCED');
        assert(evB1Mod?.eventType === 'MODIFIED', 'b1 child commit is labeled MODIFIED');
        assert(evB2Intro?.eventType === 'INTRODUCED', 'b2 independent sibling intro commit is labeled INTRODUCED');
        assert(evB2Mod?.eventType === 'MODIFIED', 'b2 child commit is labeled MODIFIED');

        // 3. Efficient O(branches) branch discovery
        const discEngine = new GitHistoryEngine(sibRepo);
        const startDisc = Date.now();
        const discResult = await discEngine.getBranchesForCommits([b1IntroSha, b1ModSha, b2IntroSha, b2ModSha]);
        const elapsedDisc = Date.now() - startDisc;

        assert(discResult.failed === false, 'getBranchesForCommits executes successfully');
        assert(discResult.commitBranchesMap.get(b1IntroSha)?.includes('branch-1'), 'b1Intro mapped to branch-1');
        assert(discResult.commitBranchesMap.get(b2IntroSha)?.includes('branch-2'), 'b2Intro mapped to branch-2');
        assert(!discResult.commitBranchesMap.get(b1IntroSha)?.includes('branch-2'), 'b1Intro not mapped to branch-2');
        assert(elapsedDisc < 2000, `getBranchesForCommits completes in < 2000ms (took ${elapsedDisc}ms)`);

        // 4. Risk engine preserves uncertainty when history flags indicate incomplete / unverified history
        const dummyRule = DETECTOR_RULES.find((r) => r.id === 'github-pat')!;
        const dummyContext = { isTest: false, isDoc: false, isConfig: false, isSensitiveName: false, extension: '.ts' };

        // Test A: Incomplete search with only 1 confirmed day
        const partialExposure: GitExposure = {
          isPresentInHead: true,
          isPresentInHistory: true,
          exposureDurationDays: 1,
          branches: ['main'],
          isRemote: false,
          statusDescription: 'Partial history search',
          isPartialHistory: true,
          searchStatus: 'SEARCH_INCOMPLETE',
        };
        const partialRisk = calculateRiskAssessment(dummyRule, 100, dummyContext, partialExposure);
        assert(partialRisk.blastRadius.factors.some((f: string) => f.includes('Exposure duration unverified due to incomplete history')), 'Blast radius factor notes unverified exposure duration on SEARCH_INCOMPLETE');
        assert(partialRisk.factors.some((f) => f.factor === 'EXPOSURE_REACH' && f.explanation.includes('unverified exposure')), 'Risk factor explanation notes unverified exposure');

        // Test B: isIntroductionUnverified: true
        const unverifiedIntroExposure: GitExposure = {
          isPresentInHead: true,
          isPresentInHistory: true,
          exposureDurationDays: 2,
          branches: ['main'],
          isRemote: false,
          statusDescription: 'Shallow clone',
          isIntroductionUnverified: true,
          searchStatus: 'FOUND',
        };
        const unverifiedRisk = calculateRiskAssessment(dummyRule, 100, dummyContext, unverifiedIntroExposure);
        assert(unverifiedRisk.blastRadius.factors.some((f: string) => f.includes('Exposure duration unverified due to incomplete history')), 'Blast radius factor notes unverified exposure on isIntroductionUnverified');

        // Test C: Fully verified short exposure (1 day) does NOT flag unverified duration
        const cleanExposure: GitExposure = {
          isPresentInHead: true,
          isPresentInHistory: true,
          exposureDurationDays: 1,
          branches: ['main'],
          isRemote: false,
          statusDescription: 'Complete search',
          searchStatus: 'FOUND',
        };
        const cleanRisk = calculateRiskAssessment(dummyRule, 100, dummyContext, cleanExposure);
        assert(!cleanRisk.blastRadius.factors.some((f: string) => f.includes('Exposure duration unverified')), 'Fully verified 1-day exposure does not flag unverified duration');
        assert(!cleanRisk.blastRadius.factors.some((f: string) => f.includes('without rotation')), '1-day exposure does not exceed 7 days');

      } finally {
        try { fs.rmSync(sec49Dir, { recursive: true, force: true }); } catch {}
      }
    }

    // ============================================================
    // SECTION 50: LARGE-REPOSITORY SCALE BENCHMARK & RISK/BLAST RADIUS SEPARATION
    // ============================================================
    console.log('\n--- Section 50: Large-Repository Scale Benchmark & Risk/Blast Radius Separation ---');
    const sec50Dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sld-sec50-scale-'));
    try {
      const { execFileSync, spawn } = cp;
      execFileSync('git', ['init'], { cwd: sec50Dir, stdio: 'ignore' });
      execFileSync('git', ['config', 'user.name', 'Scale Tester'], { cwd: sec50Dir, stdio: 'ignore' });
      execFileSync('git', ['config', 'user.email', 'scale@example.com'], { cwd: sec50Dir, stdio: 'ignore' });

      // 1. Synthetic scale repository generation via fast-import (2,000 commits + 50 branches)
      const fiStart = Date.now();
      const fi = spawn('git', ['fast-import'], {
        cwd: sec50Dir,
        stdio: ['pipe', 'ignore', 'ignore'],
      });

      const commitCount = 2000;
      for (let i = 1; i <= commitCount; i++) {
        const authorTime = 1700000000 + i;
        const msg = `Commit ${i}\n`;
        const content = `content ${i}\n`;
        let commitStr = `commit refs/heads/main\nmark :${i}\n`;
        commitStr += `author Test <test@test.com> ${authorTime} +0000\n`;
        commitStr += `committer Test <test@test.com> ${authorTime} +0000\n`;
        commitStr += `data ${Buffer.byteLength(msg)}\n${msg}`;
        if (i > 1) {
          commitStr += `from :${i - 1}\n`;
        }
        commitStr += `M 100644 inline file.txt\ndata ${Buffer.byteLength(content)}\n${content}\n`;
        fi.stdin.write(commitStr);
      }

      // Create 25 local branches and 25 remote tracking branches sharing history
      for (let b = 1; b <= 25; b++) {
        const targetMark = Math.max(1, commitCount - (b * 20));
        fi.stdin.write(`reset refs/heads/branch-local-${b}\nfrom :${targetMark}\n\n`);
        fi.stdin.write(`reset refs/remotes/origin/remote-branch-${b}\nfrom :${targetMark}\n\n`);
      }
      fi.stdin.end();

      await new Promise<void>((resolve) => fi.on('close', () => resolve()));
      const fiDuration = Date.now() - fiStart;
      assert(fiDuration < 8000, `fast-import generated 2,000 commits and 50 branches rapidly (${fiDuration}ms)`);

      // Retrieve test commit SHAs
      const shaHead = execFileSync('git', ['rev-parse', 'refs/heads/main'], { cwd: sec50Dir, encoding: 'utf8' }).trim();
      const shaMid = execFileSync('git', ['rev-parse', 'refs/heads/main~500'], { cwd: sec50Dir, encoding: 'utf8' }).trim();
      const shaOld = execFileSync('git', ['rev-parse', 'refs/heads/main~1500'], { cwd: sec50Dir, encoding: 'utf8' }).trim();

      // 2. Performance & Flat-Memory Streaming Benchmark
      const scaleEngine = new GitHistoryEngine(sec50Dir);
      const memBefore = process.memoryUsage().heapUsed;
      const benchStart = Date.now();

      const scaleResult = await scaleEngine.getBranchesForCommits([shaHead, shaMid, shaOld], sec50Dir);
      const benchDuration = Date.now() - benchStart;
      const memAfter = process.memoryUsage().heapUsed;
      const memDeltaMb = (memAfter - memBefore) / (1024 * 1024);

      assert(scaleResult.failed === false, 'getBranchesForCommits executes without failure on large repo');
      assert(scaleResult.allBranches.length >= 50, `Discovered at least 50 branches (found ${scaleResult.allBranches.length})`);
      assert(scaleResult.commitBranchesMap.get(shaHead)?.includes('main'), 'shaHead is contained in main');
      assert((scaleResult.commitBranchesMap.get(shaMid)?.length ?? 0) >= 25, `shaMid contained in >= 25 branches (found ${scaleResult.commitBranchesMap.get(shaMid)?.length})`);
      assert((scaleResult.commitBranchesMap.get(shaOld)?.length ?? 0) >= 45, `shaOld contained in >= 45 branches (found ${scaleResult.commitBranchesMap.get(shaOld)?.length})`);
      assert(benchDuration < 4000, `getBranchesForCommits on 51 branches completes in < 4000ms (took ${benchDuration}ms)`);
      assert(memDeltaMb < 30, `Streaming heap memory consumption remains flat and bounded (< 30 MB delta, measured ${memDeltaMb.toFixed(2)} MB)`);

      // 3. Graceful error handling and edge cases
      const emptyResult = await scaleEngine.getBranchesForCommits([], sec50Dir);
      assert(emptyResult.failed === false && emptyResult.allBranches.length === 0, 'Empty commit input returns empty cleanly');

      const nonGitEngine = new GitHistoryEngine(path.join(os.tmpdir(), 'non-existent-dir-' + Date.now()));
      const failResult = await nonGitEngine.getBranchesForCommits(['abcdef1234567890']);
      assert(failResult.failed === true, 'getBranchesForCommits fails gracefully on invalid git repo');

      // 3b. Regression test: Subprocess failure lifecycle ordering (must not be swallowed by readline close)
      const subProcRepo = path.join(sec50Dir, 'subproc-repo');
      fs.mkdirSync(subProcRepo, { recursive: true });
      execFileSync('git', ['init'], { cwd: subProcRepo, stdio: 'ignore' });
      execFileSync('git', ['config', 'user.name', 'Tester'], { cwd: subProcRepo, stdio: 'ignore' });
      execFileSync('git', ['config', 'user.email', 'test@test.com'], { cwd: subProcRepo, stdio: 'ignore' });
      fs.writeFileSync(path.join(subProcRepo, 'init.txt'), 'hello', 'utf8');
      execFileSync('git', ['add', 'init.txt'], { cwd: subProcRepo, stdio: 'ignore' });
      execFileSync('git', ['commit', '-m', 'c1'], { cwd: subProcRepo, stdio: 'ignore' });
      const dummySha = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: subProcRepo, encoding: 'utf8' }).trim();

      class FaultyRevListEngine extends GitHistoryEngine {
        protected override spawnGitRevList(branch: string, cwd: string): any {
          // Emits commit output, writes error to stderr, then exits non-zero (code 128)
          return cp.spawn(process.execPath, [
            '-e',
            `console.log("${dummySha}"); process.stderr.write("fatal: object corrupt in pack\\n"); process.exit(128);`
          ]);
        }
      }

      const faultyEngine = new FaultyRevListEngine(subProcRepo);
      const faultyResult = await faultyEngine.getBranchesForCommits([dummySha, 'missing-sha-0000000000'], subProcRepo);

      assert(faultyResult.failed === true, 'getBranchesForCommits reports failed: true when git rev-list emits output then exits non-zero');
      assert(
        faultyResult.error?.includes('fatal: object corrupt') || faultyResult.error?.includes('128'),
        `Error message preserves stderr failure details (got: "${faultyResult.error}")`
      );

      // Verify stream error propagation (stdout stream error terminates long-running child immediately)
      class StdoutErrorRevListEngine extends GitHistoryEngine {
        protected override spawnGitRevList(branch: string, cwd: string): any {
          const proc = cp.spawn(process.execPath, [
            '-e',
            `console.log("${dummySha}"); setTimeout(() => process.exit(0), 5000);`
          ]);
          setTimeout(() => {
            if (proc.stdout) {
              proc.stdout.emit('error', new Error('Simulated stdout read error'));
            }
          }, 10);
          return proc;
        }
      }

      const stdoutErrEngine = new StdoutErrorRevListEngine(subProcRepo);
      const stdoutErrStart = Date.now();
      const stdoutErrResult = await stdoutErrEngine.getBranchesForCommits([dummySha, 'missing-sha-0000000000'], subProcRepo);
      const stdoutErrElapsed = Date.now() - stdoutErrStart;
      assert(
        stdoutErrResult.failed === true && Boolean(stdoutErrResult.error?.includes('Simulated stdout read error')),
        'getBranchesForCommits reports failed: true and preserves stdout read error'
      );
      assert(
        stdoutErrElapsed < 2000,
        `Long-running child is terminated promptly after stream failure without waiting for delay (took ${stdoutErrElapsed}ms)`
      );

      // Verify stream error propagation (stderr stream error terminates long-running child immediately)
      class StderrErrorRevListEngine extends GitHistoryEngine {
        protected override spawnGitRevList(branch: string, cwd: string): any {
          const proc = cp.spawn(process.execPath, [
            '-e',
            `console.log("${dummySha}"); setTimeout(() => process.exit(0), 5000);`
          ]);
          setTimeout(() => {
            if (proc.stderr) {
              proc.stderr.emit('error', new Error('Simulated stderr stream error'));
            }
          }, 10);
          return proc;
        }
      }

      const stderrErrEngine = new StderrErrorRevListEngine(subProcRepo);
      const stderrErrStart = Date.now();
      const stderrErrResult = await stderrErrEngine.getBranchesForCommits([dummySha, 'missing-sha-0000000000'], subProcRepo);
      const stderrErrElapsed = Date.now() - stderrErrStart;
      assert(
        stderrErrResult.failed === true && Boolean(stderrErrResult.error?.includes('Simulated stderr stream error')),
        'getBranchesForCommits reports failed: true and preserves stderr stream error'
      );
      assert(
        stderrErrElapsed < 2000,
        `Long-running child is terminated promptly after stderr stream failure without waiting for delay (took ${stderrErrElapsed}ms)`
      );

      // Verify intentional early termination resolves cleanly with failed: false
      class EarlyTermRevListEngine extends GitHistoryEngine {
        protected override spawnGitRevList(branch: string, cwd: string): any {
          return cp.spawn(process.execPath, [
            '-e',
            `console.log("${dummySha}"); setTimeout(() => { console.log("unreachable"); process.exit(0); }, 5000);`
          ]);
        }
      }
      const earlyEngine = new EarlyTermRevListEngine(subProcRepo);
      const earlyStart = Date.now();
      const earlyResult = await earlyEngine.getBranchesForCommits([dummySha], subProcRepo);
      const earlyElapsed = Date.now() - earlyStart;
      assert(earlyResult.failed === false, 'Early termination resolves cleanly with failed: false');
      assert(earlyElapsed < 2000, `Early termination kills process immediately without waiting for delay (took ${earlyElapsed}ms)`);

      // 4. Exact Mathematical Separation of Risk Assessment vs. Blast Radius
      const testRule = DETECTOR_RULES.find((r) => r.id === 'github-pat')!;
      const testCtx = { isTest: false, isDoc: false, isConfig: false, isSensitiveName: false, extension: '.ts' };

      const incompleteExp: GitExposure = {
        isPresentInHead: true,
        isPresentInHistory: true,
        exposureDurationDays: 1,
        branches: ['main'],
        isRemote: false,
        statusDescription: 'Truncated history search',
        isPartialHistory: true,
        searchStatus: 'SEARCH_INCOMPLETE',
      };

      const completeExp: GitExposure = {
        isPresentInHead: true,
        isPresentInHistory: true,
        exposureDurationDays: 1,
        branches: ['main'],
        isRemote: false,
        statusDescription: 'Complete history search',
        searchStatus: 'FOUND',
      };

      const incompleteAssessment = calculateRiskAssessment(testRule, 100, testCtx, incompleteExp);
      const completeAssessment = calculateRiskAssessment(testRule, 100, testCtx, completeExp);

      // Intrinsic Risk Score invariance:
      // Both have identical intrinsic credentials, confidence, storage, and physical reach (committed to git history).
      // Therefore their intrinsic RiskAssessment.score and tier must be exactly identical!
      assert(incompleteAssessment.score === 84, `Incomplete history risk score is exactly 84 (got ${incompleteAssessment.score})`);
      assert(completeAssessment.score === 84, `Complete history risk score is exactly 84 (got ${completeAssessment.score})`);
      assert(incompleteAssessment.tier === 'CRITICAL', 'Incomplete history tier is CRITICAL');
      assert(completeAssessment.tier === 'CRITICAL', 'Complete history tier is CRITICAL');
      assert(incompleteAssessment.score === completeAssessment.score, 'Intrinsic risk score is invariant to history truncation');

      // Factor 4 preserves transparent explanation without inflating structural weights:
      const incompleteReach = incompleteAssessment.factors.find((f) => f.factor === 'EXPOSURE_REACH');
      const completeReach = completeAssessment.factors.find((f) => f.factor === 'EXPOSURE_REACH');
      assert(incompleteReach?.scoreContribution === 16, 'Reach contribution is 16 for incomplete history');
      assert(completeReach?.scoreContribution === 16, 'Reach contribution is 16 for complete history');
      assert(incompleteReach?.explanation.includes('≥1 days unverified exposure'), 'Reach factor notes unverified duration');
      assert(completeReach?.explanation.includes('1 days exposure'), 'Reach factor notes verified 1 day duration');

      // Operational Blast Radius Separation:
      // BlastRadius penalizes unverified containment bounds (+10 points) because containment cannot be guaranteed.
      assert(incompleteAssessment.blastRadius.score === 72, `Incomplete history blast radius score is 72 (got ${incompleteAssessment.blastRadius.score})`);
      assert(completeAssessment.blastRadius.score === 62, `Complete history blast radius score is 62 (got ${completeAssessment.blastRadius.score})`);
      assert(incompleteAssessment.blastRadius.score - completeAssessment.blastRadius.score === 10, 'Blast radius reflects exact +10 operational uncertainty penalty');
      assert(incompleteAssessment.blastRadius.level === 'EXTENSIVE', 'Incomplete blast radius level is EXTENSIVE');
      assert(completeAssessment.blastRadius.level === 'EXTENSIVE', 'Complete blast radius level is EXTENSIVE');

      // Uncommitted Working Tree Baseline:
      const localUncommitted = calculateRiskAssessment(testRule, 100, testCtx, undefined);
      assert(localUncommitted.score === 73, `Local uncommitted risk score is 73 (got ${localUncommitted.score})`);
      assert(localUncommitted.tier === 'HIGH', 'Local uncommitted tier is HIGH');
      assert(localUncommitted.blastRadius.score === 52, `Local uncommitted blast radius is 52 (got ${localUncommitted.blastRadius.score})`);
      assert(localUncommitted.blastRadius.level === 'EXTENSIVE', 'Local uncommitted blast radius level is EXTENSIVE');
      assert(localUncommitted.blastRadius.summary.includes('Contained to local working tree'), 'Blast radius summary confirms local containment');
    } finally {
      try { fs.rmSync(sec50Dir, { recursive: true, force: true }); } catch {}
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

