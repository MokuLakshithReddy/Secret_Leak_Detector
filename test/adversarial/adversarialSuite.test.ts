import { scanContent } from '../../src/core/scanner/scanner';

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
console.log('⚔️ RUNNING ADVERSARIAL EVASION TEST SUITE');
console.log('============================================================\n');

const synth = (...parts: string[]) => parts.join('');
const synthStripe = synth('sk_', 'live_', '51M0XYZ982734bca81923456789');
const synthAws = synth('AKIA', '1234', '5678', '90AB', 'CDEF');

// 1. Split String Concatenation
console.log('--- 1. String Concatenation Evasion ---');
const splitPat = `const token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz";`;
const splitRes = scanContent(splitPat, 'auth.ts');
assert(splitRes.length > 0, 'Detects split GitHub PAT token concatenation');

// 2. Multiline Whitespace Stretching
console.log('\n--- 2. Multiline Whitespace Stretching ---');
const multilineCode = `
const
  STRIPE_SECRET_KEY
  =
  "${synthStripe}";
`;
const multilineRes = scanContent(multilineCode, 'services/payment.ts');
assert(multilineRes.length > 0, 'Detects credential with multiline whitespace stretching');

// 3. Inline Comment Disruption
console.log('\n--- 3. Inline Comment Disruption ---');
const commentCode = `const API_KEY /* authorization token */ = "${synthStripe}";`;
const commentRes = scanContent(commentCode, 'config.ts');
assert(commentRes.length > 0, 'Detects credential disguised with inline comments');

// 4. Environment Fallback Disguise
console.log('\n--- 4. Environment Fallback Disguise ---');
const envFallbackCode = `const key = process.env.AWS_KEY || "${synthAws}";`;
const envRes = scanContent(envFallbackCode, 'server.js');
assert(envRes.length > 0, 'Detects hardcoded fallback secret in process.env fallback');
if (envRes.length > 0) {
  assert(
    envRes[0].evidence.items.some((i) => i.signal === 'ENV_FALLBACK_ASSIGNMENT'),
    'AST engine identifies ENV_FALLBACK_ASSIGNMENT signal'
  );
}

// 5. Hierarchical Object Property Assignment
console.log('\n--- 5. Hierarchical Object Property Assignment ---');
const objectCode = `config.auth.providers.stripe.secretKey = "${synthStripe}";`;
const objectRes = scanContent(objectCode, 'config.ts');
assert(objectRes.length > 0, 'Detects credential in deeply nested object hierarchy');

console.log('\n============================================================');
console.log(`⚔️ ADVERSARIAL SUMMARY: ${passed} PASSED, ${failed} FAILED`);
console.log('============================================================\n');

if (failed > 0) process.exit(1);
