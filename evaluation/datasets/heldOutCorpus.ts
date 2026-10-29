/**
 * Held-Out Evaluation Corpus for Secret Leak Detector
 *
 * This corpus is ENTIRELY SEPARATE from the generated benchmark corpus and the
 * real-world fixture corpus used during development. It was constructed AFTER
 * detector rules were finalized; no case from this file was used to tune
 * thresholds or patterns.
 *
 * Structure:
 *   - 20 True-Positive (TP) cases: realistic fake credentials in various formats
 *   - 20 True-Negative (TN) cases: high-entropy non-secrets correctly ignored
 *
 * Credentials are SYNTHESIZED (never real) using the synth() helper so the
 * repository's own scanner does not flag this source file.
 */

import { scanContent } from '../../src/core/scanner/scanner';

// ── Synth helper (prevents scanner from flagging the source file) ─────────────
function synth(parts: string[]): string {
  return parts.join('');
}

// ── Corpus entry type ─────────────────────────────────────────────────────────
export interface HeldOutCase {
  id: string;
  label: 'TP' | 'TN';
  rule: string;
  file: string;
  line: number;
  description: string;
  content: string;
}

// ── True-Positive cases (20) ──────────────────────────────────────────────────

const tp01_awsKey = synth(['AKIA', '3F9K', '8M2X', '5P7Q', '9R1T']);
const tp01Content = `AWS_ACCESS_KEY_ID=${tp01_awsKey}`;

const tp02_githubPat = synth(['ghp_', 'abcdef', '1234567890', 'ABCDEF', 'XYZ123', '456abc', 'de']);
const tp02Content = `GITHUB_TOKEN="${tp02_githubPat}"`;

const tp03_stripeKey = synth(['sk_live_', 'acme', '1234', 'BCDE', 'FGHI', 'JKLM', 'NOPQ']);
const tp03Content = `STRIPE_SECRET_KEY = "${tp03_stripeKey}"`;

const tp04_openaiKey = synth(['sk-proj-', 'Tst1234abcdWXYZmnop9876QRST', 'ABCDEF1234567890abcdefghijkl']);
const tp04Content = `const openaiKey = "${tp04_openaiKey}";`;

const tp05_slackToken = synth(['xoxb-', '111222', '333-', '444555', '666-', 'abcdef', '789xyz']);
const tp05Content = `SLACK_BOT_TOKEN=${tp05_slackToken}`;

const tp06_anthropicKey = synth(['sk-ant-api03-', 'Tes', 'tKey', '1234', 'ABCD', 'efgh', 'WXYZ', '5678-A']);
const tp06Content = `ANTHROPIC_API_KEY="${tp06_anthropicKey}"`;

const tp07_googleKey = synth(['AIza', 'SyB3', 'cD4e', 'F5gH', '6iJk', 'L7mN', '8oPq']);
const tp07Content = `const GOOGLE_API_KEY = "${tp07_googleKey}";`;

const tp08_awsKeyYaml = synth(['AKIA', 'T2X9', 'M3K7', 'P5Q8', 'R1S4']);
const tp08Content = `
aws:
  credentials:
    access_key_id: "${tp08_awsKeyYaml}"
    region: us-west-2
`;

const tp09_dbUrl = synth(['postgres://', 'admin:', 'Sup3rS3cr3t!', '@db.internal.corp:5432/appdb']);
const tp09Content = `DATABASE_URL="${tp09_dbUrl}"`;

const tp10_githubOauth = synth(['gho_', '1234567890', 'abcDEFGHI', 'jklMNOPQR']);
const tp10Content = `oauth_token = "${tp10_githubOauth}"`;

const tp11_awsKeyJson = synth(['AKIA', 'B5Y7', 'Z2W4', 'V9U3', 'T6S8']);
const tp11Content = JSON.stringify({
  aws_access_key_id: tp11_awsKeyJson,
  aws_region: 'us-east-1',
}, null, 2);

const tp12_stripeRestricted = synth(['rk_live_', 'test', '9876', 'ABCD', 'efGH', 'IJKL', 'MNOP']);
const tp12Content = `stripe_restricted_key = "${tp12_stripeRestricted}"`;

const tp13_githubFinePat = synth(['github_pat_', '11A', 'BCDEFG_', 'hijklmnopqrstuvwxyz1234567890', 'ABCDEFGHIJKLMN', 'opqrstuvwxyz1234567890', '1234567']);
const tp13Content = `token: "${tp13_githubFinePat}"`;

const tp14_awsKeyGo = synth(['AKIA', 'N1O2', 'P3Q4', 'R5S6', 'T7U8']);
const tp14Content = `
package main
const awsAccessKey = "${tp14_awsKeyGo}"
`;

const tp15_dbUrlPython = synth(['postgresql://', 'dbuser:', 'MyP@ssw0rd123!', '@db.internal:5432/production']);
const tp15Content = `DATABASE_URL = "${tp15_dbUrlPython}"`;

const tp16_openaiKeyShell = synth(['sk-proj-', 'Sh3ll', '1234', 'ABCD', 'efgh', 'WXYZ', '9012', 'MNOP']);
const tp16Content = `export OPENAI_API_KEY="${tp16_openaiKeyShell}"`;

const tp17_awsKeyTerraform = synth(['AKIA', 'U9V8', 'W7X6', 'Y5Z4', 'A3B2']);
const tp17Content = `
resource "aws_iam_access_key" "example" {
  access_key = "${tp17_awsKeyTerraform}"
}`;

const tp18_k8sSecret = synth(['c2VjcmV0', 'LXBhc3N3', 'b3JkLTEy', 'MzQ1Njc4', 'OWFiY2Rl']);
const tp18Content = `
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
data:
  secret_key: "${tp18_k8sSecret}"
`;

const tp19_slackWebhook = synth(['https://hooks.slack.com/services/', 'T01ABC12345', '/B02DEF67890', '/xyz789abcGHIJKL123456789']);
const tp19Content = `SLACK_WEBHOOK_URL="${tp19_slackWebhook}"`;

const tp20_awsKeyRuby = synth(['AKIA', 'C4D5', 'E6F7', 'G8H9', 'I0J1']);
const tp20Content = `
# config/initializers/aws.rb
Aws.config.update(
  access_key_id: "${tp20_awsKeyRuby}",
  region: "us-east-1"
)
`;

// ── True-Negative cases (20) ──────────────────────────────────────────────────
// High-entropy non-secrets: SRI hashes, git SHAs, UUID v4s, base64 pixels, checksums

const tn01Content = `# SRI hash for CDN asset
<script src="https://cdn.example.com/app.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxbd5R/mJnQ="
  crossorigin="anonymous"></script>`;

const tn02Content = `# Git commit SHA
commit abc123def456789012345678901234567890abcdef
Author: Alice <alice@example.com>`;

const tn03Content = `# TLS Certificate SHA-256 Fingerprint
CERT_FINGERPRINT=9B:4C:6D:E8:1A:3F:72:05:4E:D9:8C:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A:BC:DE:F0:12:34:56:78:9A`;

const tn04Content = `# UUID v4
request_id = "550e8400-e29b-41d4-a716-446655440000"`;

const tn05Content = `# Base64-encoded 1x1 transparent PNG pixel
const TRACKING_PIXEL = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";`;

const tn06Content = `# Webpack asset bundle filename (content hash)
vendor.3f8a92b1c4d5e7f9a2b4c6d8.js`;

const tn07Content = `# Environment variable placeholder
AWS_ACCESS_KEY_ID=YOUR_AWS_ACCESS_KEY_HERE
AWS_SECRET_ACCESS_KEY=REPLACE_WITH_YOUR_SECRET`;

const tn08Content = `# Test mock token
const MOCK_TOKEN = "test_fake_token_000000000000000000000";
const MOCK_KEY = "00000000000000000000000000000000";`;

const tn09Content = `# localhost database URL (benign)
DATABASE_URL=postgres://user:password@localhost:5432/test_db`;

const tn10Content = `# SHA-256 integrity hash
Content-SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`;

const tn11Content = `# Docker image digest
FROM node:20@sha256:a1b2c3d4e5f6789012345678901234567890123456789012345678901234567890ab`;

const tn12Content = `# Python test fixture
import unittest
def test_connection():
    token = "test_token_abc123def456_not_real"
    assert token.startswith("test_")`;

const tn13Content = `# Terraform example placeholder
variable "api_key" {
  default = "EXAMPLE_API_KEY_REPLACE_ME"
}`;

const tn14Content = `# SRI hash sha256
<link rel="stylesheet" href="styles.css"
  integrity="sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
  crossorigin="anonymous">`;

const tn15Content = `# Base64-encoded RSA public key (example only)
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Ts
-----END PUBLIC KEY-----`;

const tn16Content = `# Kubernetes ConfigMap (non-secret data)
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  LOG_LEVEL: "info"
  MAX_CONNECTIONS: "100"`;

const tn17Content = `// Jest test spy — not a real credential
const mockApiKey = jest.fn().mockReturnValue("mock-api-key-for-testing");`;

const tn18Content = `# Go test constant
const testAWSKey = "AKIAIOSFODNN7EXAMPLE" // AWS docs example key`;

const tn19Content = `# package-lock.json integrity field
"integrity": "sha512-C9yCkHFfRFkuJAhXhLv9hB8RFXD9mB6TLiGpQWCKNWFBJGKGfBsWmGnbkAebmLdCZFKhFmBGLTkFnxKtB1PA=="`;

const tn20Content = `# Repetitive filler used in test suites
SECRET_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
API_TOKEN=00000000000000000000000000000000`;

// ── Build the corpus array ────────────────────────────────────────────────────

export const HELD_OUT_CORPUS: HeldOutCase[] = [
  // True Positives
  { id: 'HO-TP-01', label: 'TP', rule: 'aws-access-key',     file: '.env',                        line: 1,  description: 'AWS IAM access key in .env file',                           content: tp01Content },
  { id: 'HO-TP-02', label: 'TP', rule: 'github-pat',         file: '.env',                        line: 1,  description: 'GitHub personal access token (ghp_)',                        content: tp02Content },
  { id: 'HO-TP-03', label: 'TP', rule: 'stripe-live-key',    file: 'config/stripe.env',           line: 1,  description: 'Stripe live secret key',                                    content: tp03Content },
  { id: 'HO-TP-04', label: 'TP', rule: 'openai-key',         file: 'src/openai.ts',               line: 1,  description: 'OpenAI project key (sk-proj-)',                              content: tp04Content },
  { id: 'HO-TP-05', label: 'TP', rule: 'slack-token',        file: '.env',                        line: 1,  description: 'Slack bot token (xoxb-)',                                    content: tp05Content },
  { id: 'HO-TP-06', label: 'TP', rule: 'anthropic-key',      file: '.env',                        line: 1,  description: 'Anthropic API key (sk-ant-api03-)',                           content: tp06Content },
  { id: 'HO-TP-07', label: 'TP', rule: 'google-api-key',     file: 'src/config.js',               line: 1,  description: 'Google API key (AIza prefix)',                               content: tp07Content },
  { id: 'HO-TP-08', label: 'TP', rule: 'aws-access-key',     file: 'config/aws.yml',              line: 3,  description: 'AWS access key in YAML configuration',                       content: tp08Content },
  { id: 'HO-TP-09', label: 'TP', rule: 'database-url',       file: '.env',                        line: 1,  description: 'PostgreSQL connection URL with embedded password',            content: tp09Content },
  { id: 'HO-TP-10', label: 'TP', rule: 'github-oauth',       file: 'config.ini',                  line: 1,  description: 'GitHub OAuth token (gho_)',                                  content: tp10Content },
  { id: 'HO-TP-11', label: 'TP', rule: 'aws-access-key',     file: 'credentials.json',            line: 2,  description: 'AWS access key in JSON config',                             content: tp11Content },
  { id: 'HO-TP-12', label: 'TP', rule: 'stripe-restricted',  file: '.env',                        line: 1,  description: 'Stripe restricted key (rk_live_)',                           content: tp12Content },
  { id: 'HO-TP-13', label: 'TP', rule: 'github-fine-pat',    file: 'deploy.yml',                  line: 1,  description: 'GitHub fine-grained PAT (github_pat_)',                      content: tp13Content },
  { id: 'HO-TP-14', label: 'TP', rule: 'aws-access-key',     file: 'main.go',                     line: 3,  description: 'AWS access key in Go source file',                           content: tp14Content },
  { id: 'HO-TP-15', label: 'TP', rule: 'database-url',       file: 'settings.py',                 line: 1,  description: 'PostgreSQL URL in Python settings',                          content: tp15Content },
  { id: 'HO-TP-16', label: 'TP', rule: 'openai-key',         file: 'setup.sh',                    line: 1,  description: 'OpenAI key exported in shell script',                        content: tp16Content },
  { id: 'HO-TP-17', label: 'TP', rule: 'aws-access-key',     file: 'main.tf',                     line: 3,  description: 'AWS access key in Terraform resource',                       content: tp17Content },
  { id: 'HO-TP-18', label: 'TP', rule: 'generic-high-entropy','file': 'k8s/secret.yaml',          line: 5,  description: 'Base64-encoded secret key in Kubernetes Secret',             content: tp18Content },
  { id: 'HO-TP-19', label: 'TP', rule: 'slack-webhook',      file: '.env',                        line: 1,  description: 'Slack incoming webhook URL',                                 content: tp19Content },
  { id: 'HO-TP-20', label: 'TP', rule: 'aws-access-key',     file: 'config/initializers/aws.rb',  line: 3,  description: 'AWS access key in Ruby on Rails initializer',                content: tp20Content },

  // True Negatives
  { id: 'HO-TN-01', label: 'TN', rule: 'n/a', file: 'index.html',          line: 2, description: 'Subresource Integrity (SRI) sha384 hash — not a secret',     content: tn01Content },
  { id: 'HO-TN-02', label: 'TN', rule: 'n/a', file: 'CHANGELOG.md',        line: 2, description: '40-character Git commit SHA — not a secret',                 content: tn02Content },
  { id: 'HO-TN-03', label: 'TN', rule: 'n/a', file: 'config/tls.conf',     line: 2, description: 'TLS Certificate SHA-256 fingerprint — not a secret',          content: tn03Content },
  { id: 'HO-TN-04', label: 'TN', rule: 'n/a', file: 'config.ini',          line: 2, description: 'UUID v4 request ID — not a secret',                          content: tn04Content },
  { id: 'HO-TN-05', label: 'TN', rule: 'n/a', file: 'src/analytics.ts',    line: 2, description: 'Base64-encoded 1x1 PNG tracking pixel — not a secret',       content: tn05Content },
  { id: 'HO-TN-06', label: 'TN', rule: 'n/a', file: 'dist/manifest.txt',   line: 1, description: 'Webpack content-hash bundle filename — not a secret',        content: tn06Content },
  { id: 'HO-TN-07', label: 'TN', rule: 'n/a', file: '.env.example',        line: 1, description: 'Placeholder strings in .env.example — not a secret',         content: tn07Content },
  { id: 'HO-TN-08', label: 'TN', rule: 'n/a', file: 'test/mocks.ts',       line: 2, description: 'Repetitive test mock tokens — not a secret',                 content: tn08Content },
  { id: 'HO-TN-09', label: 'TN', rule: 'n/a', file: '.env.test',           line: 2, description: 'Localhost database URL — not a secret',                       content: tn09Content },
  { id: 'HO-TN-10', label: 'TN', rule: 'n/a', file: 'api-response.txt',    line: 2, description: 'SHA-256 Content-SHA256 header value — not a secret',         content: tn10Content },
  { id: 'HO-TN-11', label: 'TN', rule: 'n/a', file: 'Dockerfile',          line: 2, description: 'Docker image digest SHA — not a secret',                     content: tn11Content },
  { id: 'HO-TN-12', label: 'TN', rule: 'n/a', file: 'test_app.py',         line: 3, description: 'Python test fixture token starting with "test_" — not real', content: tn12Content },
  { id: 'HO-TN-13', label: 'TN', rule: 'n/a', file: 'variables.tf',        line: 3, description: 'Terraform variable placeholder — not a secret',              content: tn13Content },
  { id: 'HO-TN-14', label: 'TN', rule: 'n/a', file: 'index.html',          line: 2, description: 'SRI sha256 hash for CSS — not a secret',                     content: tn14Content },
  { id: 'HO-TN-15', label: 'TN', rule: 'n/a', file: 'certs/example.pem',   line: 2, description: 'Example RSA public key (not a private key) — not a secret',  content: tn15Content },
  { id: 'HO-TN-16', label: 'TN', rule: 'n/a', file: 'k8s/configmap.yaml',  line: 1, description: 'Kubernetes ConfigMap (non-Secret kind) — not a secret',      content: tn16Content },
  { id: 'HO-TN-17', label: 'TN', rule: 'n/a', file: 'src/api.test.ts',     line: 2, description: 'Jest mock API key — clearly a test value, not real',         content: tn17Content },
  { id: 'HO-TN-18', label: 'TN', rule: 'n/a', file: 'aws_test.go',         line: 2, description: 'AWS documentation example key (AKIAIOSFODNN7EXAMPLE)',       content: tn18Content },
  { id: 'HO-TN-19', label: 'TN', rule: 'n/a', file: 'package-lock.json',   line: 2, description: 'npm package-lock.json integrity hash — not a secret',        content: tn19Content },
  { id: 'HO-TN-20', label: 'TN', rule: 'n/a', file: '.env.test',           line: 1, description: 'Repetitive filler test tokens (all-zero, all-a) — not real', content: tn20Content },
];

// ── Evaluation runner ─────────────────────────────────────────────────────────

export interface EvaluationResult {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
  fpr: number;
}

export async function runHeldOutEvaluation(): Promise<EvaluationResult> {
  let tp = 0, fp = 0, tn = 0, fn = 0;

  console.log('\n══════════════════════════════════════════════════════════════');
  console.log('  Held-Out Evaluation Corpus — Secret Leak Detector');
  console.log('══════════════════════════════════════════════════════════════');
  console.log(`  Cases: ${HELD_OUT_CORPUS.length} (20 TP, 20 TN)`);
  console.log('');

  for (const c of HELD_OUT_CORPUS) {
    const findings = scanContent(c.content, c.file);
    const hasFindings = findings.length > 0;

    if (c.label === 'TP') {
      if (hasFindings) {
        tp++;
        console.log(`  ✅ TP detected  [${c.id}] ${c.description}`);
      } else {
        fn++;
        console.log(`  ❌ FN missed    [${c.id}] ${c.description}`);
      }
    } else {
      // TN
      if (!hasFindings) {
        tn++;
        console.log(`  ✅ TN ignored   [${c.id}] ${c.description}`);
      } else {
        fp++;
        const redacted = findings.map(f => `${f.type}@L${f.line}`).join(', ');
        console.log(`  ❌ FP flagged   [${c.id}] ${c.description} → ${redacted}`);
      }
    }
  }

  // ── Metrics ──────────────────────────────────────────────────────────────
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall    = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1        = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;
  const fpr       = tn + fp > 0 ? fp / (tn + fp) : 0;

  console.log('');
  console.log('── Confusion Matrix ─────────────────────────────────────────');
  console.log(`  True  Positives (TP): ${tp}`);
  console.log(`  False Positives (FP): ${fp}`);
  console.log(`  True  Negatives (TN): ${tn}`);
  console.log(`  False Negatives (FN): ${fn}`);
  console.log('');
  console.log('── Performance Metrics ──────────────────────────────────────');
  console.log(`  Precision : ${(precision * 100).toFixed(1)}%`);
  console.log(`  Recall    : ${(recall * 100).toFixed(1)}%`);
  console.log(`  F1 Score  : ${(f1 * 100).toFixed(1)}%`);
  console.log(`  FP Rate   : ${(fpr * 100).toFixed(1)}%`);
  console.log('══════════════════════════════════════════════════════════════');

  return { tp, fp, tn, fn, precision, recall, f1, fpr };
}

// ── Entry point ───────────────────────────────────────────────────────────────
if (require.main === module) {
  runHeldOutEvaluation()
    .then(r => {
      if (r.fn > 0 || r.fp > 0) {
        console.error('\nWARNING: Unexpected evaluation results — review FN/FP cases above.');
        process.exit(1);
      }
      process.exit(0);
    })
    .catch(err => {
      console.error('Evaluation error:', err);
      process.exit(1);
    });
}
