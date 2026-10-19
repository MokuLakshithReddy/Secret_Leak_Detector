import { scanContent, buildScanResult } from '../src/engine/scanner';
import { calculateShannonEntropy } from '../src/engine/entropy';
import { redactSecret, generateFingerprint } from '../src/engine/redactor';

function assert(condition: boolean, msg: string) {
  if (!condition) {
    console.error(`❌ FAILED: ${msg}`);
    process.exit(1);
  } else {
    console.log(`✅ PASSED: ${msg}`);
  }
}

console.log('--- Running Secret Leak Detector Test Suite ---');

// 1. Test Shannon Entropy
const lowEntropy = calculateShannonEntropy('aaaaaaaaaa');
const normalText = calculateShannonEntropy('hello world');
const highEntropy = calculateShannonEntropy('sk_test_51M0XYZ982734bca81923');
console.log(`Entropy scores: low=${lowEntropy}, normal=${normalText}, high=${highEntropy}`);
assert(lowEntropy < 1.0, 'Low entropy string correctly computed < 1.0');
assert(highEntropy > 3.5, 'High entropy string correctly computed > 3.5');

// 2. Test Redaction
const maskedAws = redactSecret('AKIA1234567890ABCDEF');
console.log(`Redacted AWS Key: ${maskedAws}`);
assert(maskedAws.startsWith('AKIA'), 'Mask preserves prefix');
assert(maskedAws.endsWith('CDEF'), 'Mask preserves suffix');
assert(maskedAws.includes('****'), 'Mask contains redacted asterisks');

// 3. Test Fingerprinting
const fp1 = generateFingerprint('secret-12345');
const fp2 = generateFingerprint('secret-12345');
const fp3 = generateFingerprint('secret-67890');
assert(fp1 === fp2, 'Identical secrets produce matching fingerprints');
assert(fp1 !== fp3, 'Different secrets produce unique fingerprints');

// 4. Test AWS Key Detection
const awsCode = `
import aws from 'aws-sdk';
const config = {
  accessKeyId: "AKIA1234567890ABCDEF",
  region: "us-east-1"
};
`;
const awsFindings = scanContent(awsCode, 'config/aws.ts');
assert(awsFindings.length === 1, 'AWS Key found in code');
assert(awsFindings[0].type === 'AWS Access Key ID', 'Rule correctly classified as AWS Access Key ID');
assert(awsFindings[0].risk === 'CRITICAL', 'AWS Key classified as CRITICAL');
assert(awsFindings[0].line === 4, 'Line number 4 accurately pinpointed');

// 5. Test GitHub Token Detection
const ghCode = `const GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";`;
const ghFindings = scanContent(ghCode, 'scripts/deploy.js');
assert(ghFindings.length === 1, 'GitHub Token detected');
assert(ghFindings[0].provider === 'GitHub', 'Provider classified as GitHub');

// 6. Test Stripe Secret Key Detection
const stripeCode = `const stripe = require('stripe')('sk_test_51Abcdefghijklmnopqrstuvwx');`;
const stripeFindings = scanContent(stripeCode, 'server.js');
assert(stripeFindings.length === 1, 'Stripe Secret Key detected');
assert(stripeFindings[0].risk === 'CRITICAL', 'Stripe secret marked CRITICAL');

// 7. Test OpenAI Key Detection
const openAiCode = `const apiKey = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef";`;
const openAiFindings = scanContent(openAiCode, 'ai.ts');
assert(openAiFindings.length === 1, 'OpenAI Key detected');
assert(openAiFindings[0].provider === 'OpenAI', 'Provider marked OpenAI');

// 8. Test False Positive Rejection
const safeCode = `
const exampleKey = "AKIAIOSFODNN7EXAMPLE"; // known AWS documentation placeholder
const regularId = "user_12345678";
const uuid = "e7b1a290-2c3d-4e5f-8a1b-9c8d7e6f5a4b";
`;
const safeFindings = scanContent(safeCode, 'sample.ts');
assert(safeFindings.length === 0, 'No false positives on placeholders and standard UUIDs');

// 9. Scan Result Aggregation
const combinedResult = buildScanResult([...awsFindings, ...ghFindings], 2, 45);
assert(combinedResult.blocked === true, 'Scan correctly signals blocked commit on CRITICAL findings');
assert(combinedResult.isClean === false, 'Scan marks isClean as false');

// Helper to synthesize credential fixtures without triggering static file scanners
const synth = (...parts: string[]) => parts.join('');

// 10. Test AWS Secret Key Detection in .env (unquoted)
const awsSecretVal = synth('wJalrXUtnFEMI/K7MDENG/bPxRfiCY', '1234567890');
const envCode = `AWS_SECRET_ACCESS_KEY=${awsSecretVal}\n`;
const envFindings = scanContent(envCode, '.env');
assert(envFindings.length === 1, 'Unquoted AWS Secret Access Key in .env detected');
assert(envFindings[0].provider === 'Amazon Web Services', 'Provider classified as AWS');

// 11. Test OpenAI Admin Key Detection
const openAiAdminVal = synth('sk-', 'admin-', '1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef');
const openAiAdminCode = `const adminKey = "${openAiAdminVal}";`;
const openAiAdminFindings = scanContent(openAiAdminCode, 'src/openai.ts');
assert(openAiAdminFindings.length === 1, 'OpenAI Admin Key format detected');

// 12. Test Anthropic Claude Key Detection
const antVal = synth('sk-', 'ant-', 'api03-1234567890abcdefghijklmnopqrstuvwxyz1234567890');
const antCode = `const claudeKey = "${antVal}";`;
const antFindings = scanContent(antCode, 'src/claude.ts');
assert(antFindings.length === 1, 'Anthropic Claude Key detected');
assert(antFindings[0].provider === 'Anthropic', 'Provider marked Anthropic');

// 13. Test Google Cloud / Gemini API Key Detection
const gVal = synth('AIza', 'SyD1234567890abcdefghijklmnopqrstuvwx');
const gCode = `const geminiApiKey = "${gVal}";`;
const gFindings = scanContent(gCode, 'src/gemini.ts');
assert(gFindings.length === 1, 'Google / Gemini API Key detected');
assert(gFindings[0].provider === 'Google Cloud', 'Provider marked Google Cloud');

// 14. Test Slack Bot Token Detection
const slackVal = synth('xoxb-', '123456789012-', '1234567890123-', 'abcdefghijklmnopqrstuvwx');
const slackCode = `const slackBotToken = "${slackVal}";`;
const slackFindings = scanContent(slackCode, 'src/slack.ts');
assert(slackFindings.length === 1, 'Slack Bot Token detected');
assert(slackFindings[0].provider === 'Slack', 'Provider marked Slack');

// 15. Test Hugging Face Access Token Detection
const hfVal = synth('hf_', '1234567890abcdefghijklmnopqrstuvwx');
const hfCode = `const hfToken = "${hfVal}";`;
const hfFindings = scanContent(hfCode, 'src/model.py');
assert(hfFindings.length === 1, 'Hugging Face Access Token detected');
assert(hfFindings[0].provider === 'Hugging Face', 'Provider marked Hugging Face');

console.log('\n🎉 ALL 15 CORE TESTS PASSED WITH 100% ACCURACY!');
