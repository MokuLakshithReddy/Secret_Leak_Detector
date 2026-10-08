import { scanContent, scanFile, buildScanResult } from '../src/core/scanner/scanner';
import { calculateShannonEntropy, calculateNormalizedEntropy } from '../src/core/entropy/entropy';
import { redactSecret, generateFingerprint } from '../src/core/redactor/redactor';
import { BaselineEngine } from '../src/core/baseline/baselineEngine';
import { VerificationEngine } from '../src/core/verification/verificationEngine';
import { GitHistoryEngine } from '../src/core/history/gitHistoryEngine';
import { formatAsSarif } from '../src/core/sarif/sarifFormatter';
import * as path from 'path';
import * as fs from 'fs';

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

console.log('\n============================================================');
console.log(`🎉 TEST SUMMARY: ${passed} PASSED, ${failed} FAILED`);
console.log('============================================================\n');

if (failed > 0) {
  process.exit(1);
}
