/**
 * Comprehensive Benchmark Corpus Generator (500+ Fixtures)
 * Generates an empirical, multi-language, multi-provider corpus on disk
 * for side-by-side evaluation of Secret Leak Detector, Gitleaks, TruffleHog, and detect-secrets.
 */

import * as fs from 'fs';
import * as path from 'path';

export interface CorpusItem {
  id: string;
  relativePath: string;
  category: 'true_positive' | 'false_positive' | 'adversarial';
  provider?: string;
  isSecret: boolean;
  expectedSecretPattern?: string;
}

// Runtime synthesizers so tokens never trigger static push protection scans
const synth = (...parts: string[]) => parts.join('');

function randomHex(length: number): string {
  const chars = '0123456789abcdef';
  let res = '';
  for (let i = 0; i < length; i++) res += chars[Math.floor(Math.random() * chars.length)];
  return res;
}

function randomAlpha(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let res = '';
  for (let i = 0; i < length; i++) res += chars[Math.floor(Math.random() * chars.length)];
  return res;
}

export function generateCorpus(targetDir: string): CorpusItem[] {
  if (fs.existsSync(targetDir)) {
    fs.rmSync(targetDir, { recursive: true, force: true });
  }
  fs.mkdirSync(targetDir, { recursive: true });

  const items: CorpusItem[] = [];

  // =========================================================================
  // 1. TRUE POSITIVES (260 Files across 10 credential families & 6 languages)
  // =========================================================================
  const providers = [
    {
      name: 'AWS',
      gen: () => ({
        key: synth('AKIA', randomAlpha(16).toUpperCase()),
        sec: synth(randomAlpha(40)),
      }),
      exts: ['ts', 'py', 'go', 'json', 'env', 'sh'],
      snippet: (k: string, s: string, ext: string) => {
        if (ext === 'ts') return `import AWS from 'aws-sdk';\nconst s3 = new AWS.S3({ accessKeyId: "${k}", secretAccessKey: "${s}" });`;
        if (ext === 'py') return `import boto3\nclient = boto3.client('s3', aws_access_key_id="${k}", aws_secret_access_key="${s}")`;
        if (ext === 'go') return `package main\nconst AwsKey = "${k}"\nconst AwsSecret = "${s}"`;
        if (ext === 'json') return `{\n  "AWS_ACCESS_KEY_ID": "${k}",\n  "AWS_SECRET_ACCESS_KEY": "${s}"\n}`;
        if (ext === 'env') return `AWS_ACCESS_KEY_ID=${k}\nAWS_SECRET_ACCESS_KEY=${s}`;
        return `export AWS_ACCESS_KEY_ID="${k}"\nexport AWS_SECRET_ACCESS_KEY="${s}"`;
      },
    },
    {
      name: 'Stripe',
      gen: () => ({
        key: synth('sk_live_', randomAlpha(24)),
        sec: '',
      }),
      exts: ['ts', 'js', 'py', 'json', 'env'],
      snippet: (k: string, _: string, ext: string) => {
        if (ext === 'ts') return `import Stripe from 'stripe';\nexport const stripe = new Stripe("${k}");`;
        if (ext === 'py') return `import stripe\nstripe.api_key = "${k}"`;
        if (ext === 'json') return `{\n  "stripe_secret": "${k}"\n}`;
        if (ext === 'env') return `STRIPE_SECRET_KEY=${k}`;
        return `const stripe = require('stripe')("${k}");`;
      },
    },
    {
      name: 'GitHub',
      gen: () => ({
        key: synth('ghp_', randomAlpha(36)),
        sec: '',
      }),
      exts: ['ts', 'py', 'sh', 'env', 'json'],
      snippet: (k: string, _: string, ext: string) => {
        if (ext === 'ts') return `const octokit = new Octokit({ auth: "${k}" });`;
        if (ext === 'py') return `import github\ng = github.Github("${k}")`;
        if (ext === 'sh') return `curl -H "Authorization: token ${k}" https://api.github.com/user`;
        if (ext === 'env') return `GITHUB_TOKEN=${k}`;
        return `{\n  "github_token": "${k}"\n}`;
      },
    },
    {
      name: 'Slack',
      gen: () => ({
        key: synth('xoxb-', '123456789012', '-', '123456789012', '-', randomAlpha(24)),
        sec: '',
      }),
      exts: ['ts', 'py', 'env', 'json'],
      snippet: (k: string, _: string, ext: string) => {
        if (ext === 'ts') return `import { WebClient } from '@slack/web-api';\nconst client = new WebClient("${k}");`;
        if (ext === 'py') return `from slack_sdk import WebClient\nclient = WebClient(token="${k}")`;
        if (ext === 'env') return `SLACK_BOT_TOKEN=${k}`;
        return `{\n  "slack_token": "${k}"\n}`;
      },
    },
    {
      name: 'OpenAI',
      gen: () => ({
        key: synth('sk-proj-', randomAlpha(48)),
        sec: '',
      }),
      exts: ['ts', 'py', 'env', 'json'],
      snippet: (k: string, _: string, ext: string) => {
        if (ext === 'ts') return `import OpenAI from 'openai';\nconst ai = new OpenAI({ apiKey: "${k}" });`;
        if (ext === 'py') return `import openai\nopenai.api_key = "${k}"`;
        if (ext === 'env') return `OPENAI_API_KEY=${k}`;
        return `{\n  "openai_key": "${k}"\n}`;
      },
    },
    {
      name: 'Anthropic',
      gen: () => ({
        key: synth('sk-ant-', randomAlpha(40)),
        sec: '',
      }),
      exts: ['ts', 'py', 'env', 'json'],
      snippet: (k: string, _: string, ext: string) => {
        if (ext === 'ts') return `import Anthropic from '@anthropic-ai/sdk';\nconst anthropic = new Anthropic({ apiKey: "${k}" });`;
        if (ext === 'py') return `import anthropic\nclient = anthropic.Anthropic(api_key="${k}")`;
        if (ext === 'env') return `ANTHROPIC_API_KEY=${k}`;
        return `{\n  "anthropic_key": "${k}"\n}`;
      },
    },
    {
      name: 'GoogleCloud',
      gen: () => ({
        key: synth('AIzaSy', randomAlpha(33)),
        sec: '',
      }),
      exts: ['ts', 'js', 'json', 'env'],
      snippet: (k: string, _: string, ext: string) => {
        if (ext === 'ts') return `const googleMapsUrl = "https://maps.googleapis.com/maps/api/js?key=${k}";`;
        if (ext === 'json') return `{\n  "google_api_key": "${k}"\n}`;
        if (ext === 'env') return `GOOGLE_API_KEY=${k}`;
        return `const apiKey = "${k}";`;
      },
    },
    {
      name: 'Database',
      gen: () => ({
        key: synth('postgres://dbuser:', randomAlpha(14), '@prod-db.corp.net:5432/customer_records'),
        sec: '',
      }),
      exts: ['ts', 'py', 'env', 'json'],
      snippet: (k: string, _: string, ext: string) => {
        if (ext === 'ts') return `import { Pool } from 'pg';\nexport const pool = new Pool({ connectionString: "${k}" });`;
        if (ext === 'py') return `import psycopg2\nconn = psycopg2.connect("${k}")`;
        if (ext === 'env') return `DATABASE_URL=${k}`;
        return `{\n  "database_uri": "${k}"\n}`;
      },
    },
    {
      name: 'PEM_PrivateKey',
      gen: () => ({
        key: `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0${randomAlpha(64)}\n${randomAlpha(64)}\n${randomAlpha(64)}\n-----END RSA PRIVATE KEY-----`,
        sec: '',
      }),
      exts: ['pem', 'key', 'ts'],
      snippet: (k: string, _: string, ext: string) => {
        if (ext === 'ts') return `export const privateKey = \`${k}\`;`;
        return k;
      },
    },
    {
      name: 'JWT',
      gen: () => ({
        key: synth(
          'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.',
          'eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwicm9sZSI6InN1cGVyYWRtaW4ifQ.',
          randomAlpha(32)
        ),
        sec: '',
      }),
      exts: ['ts', 'py', 'json', 'env'],
      snippet: (k: string, _: string, ext: string) => {
        if (ext === 'ts') return `const authHeader = "Bearer ${k}";`;
        if (ext === 'py') return `headers = {"Authorization": "Bearer ${k}"}`;
        if (ext === 'env') return `ADMIN_JWT=${k}`;
        return `{\n  "token": "${k}"\n}`;
      },
    },
  ];

  let tpCounter = 0;
  while (tpCounter < 260) {
    const prov = providers[tpCounter % providers.length];
    const ext = prov.exts[tpCounter % prov.exts.length];
    const { key, sec } = prov.gen();
    const content = prov.snippet(key, sec, ext);
    const relPath = `src/tp/tp_${prov.name.toLowerCase()}_${tpCounter}.${ext}`;
    const fullPath = path.join(targetDir, relPath);

    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content, 'utf8');

    items.push({
      id: `TP-${prov.name.toUpperCase()}-${tpCounter}`,
      relativePath: relPath,
      category: 'true_positive',
      provider: prov.name,
      isSecret: true,
      expectedSecretPattern: prov.name,
    });
    tpCounter++;
  }

  // =========================================================================
  // 2. FALSE POSITIVES (200 Files: docs, placeholders, UUIDs, hashes, configs)
  // =========================================================================
  const fpTemplates = [
    // 1. AWS official documentation placeholder
    {
      ext: 'md',
      dir: 'docs',
      name: 'aws_setup',
      content: `# AWS Guide\nSet up your credentials:\n\`\`\`bash\nexport AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"\nexport AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n\`\`\``,
    },
    // 2. Stripe documentation placeholder
    {
      ext: 'md',
      dir: 'docs',
      name: 'stripe_quickstart',
      content: `# Stripe Setup\nUse test keys:\n\`\`\`javascript\nconst stripe = require('stripe')('sk_test_placeholder_key_example');\n\`\`\``,
    },
    // 3. .env.example placeholder template
    {
      ext: 'example',
      dir: 'config',
      name: '.env',
      content: `API_KEY=your_api_key_here\nDATABASE_URL=postgres://user:password@localhost:5432/dbname\nSLACK_TOKEN=xoxb-your-token-here\nSECRET=insert_your_secret_key`,
    },
    // 4. Pure UUID v4 identifier
    {
      ext: 'ts',
      dir: 'src/utils',
      name: 'uuid',
      content: `export const traceId = "${randomHex(8)}-${randomHex(4)}-4${randomHex(3)}-a${randomHex(3)}-${randomHex(12)}";\nexport const requestId = "${randomHex(8)}-${randomHex(4)}-4${randomHex(3)}-b${randomHex(3)}-${randomHex(12)}";`,
    },
    // 5. Git Commit SHA1 hash
    {
      ext: 'ts',
      dir: 'src/version',
      name: 'commit_hash',
      content: `export const BUILD_COMMIT_SHA = "${randomHex(40)}";\nexport const PREV_COMMIT_SHA = "${randomHex(40)}";`,
    },
    // 6. SHA-256 integrity hash
    {
      ext: 'json',
      dir: 'src/security',
      name: 'integrity',
      content: `{\n  "sri_hash": "sha256-${randomAlpha(43)}=",\n  "file_hash": "${randomHex(64)}"\n}`,
    },
    // 7. Dummy test mock repeated filler
    {
      ext: 'ts',
      dir: 'test/mocks',
      name: 'test_mock',
      content: `export const DUMMY_KEY = "00000000000000000000000000000000";\nexport const FAKE_TOKEN = "test_fake_token_123456789";`,
    },
    // 8. Dummy database local connection
    {
      ext: 'py',
      dir: 'src/db',
      name: 'local_db',
      content: `DEV_DATABASE_URL = "postgres://user:password@localhost:5432/test_db"\nSQLITE_URL = "sqlite:///:memory:"`,
    },
    // 9. Webpack bundled chunk hash
    {
      ext: 'js',
      dir: 'dist/assets',
      name: 'chunk_manifest',
      content: `const manifest = {\n  vendor: "vendor.${randomHex(16)}.js",\n  app: "app.${randomHex(16)}.css"\n};`,
    },
    // 10. Base64 png image data URI
    {
      ext: 'ts',
      dir: 'src/assets',
      name: 'inline_icon',
      content: `export const ICON_DATA = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";`,
    },
  ];

  for (let i = 0; i < 200; i++) {
    const t = fpTemplates[i % fpTemplates.length];
    const relPath = `${t.dir}/fp_${t.name}_${i}.${t.ext}`;
    const fullPath = path.join(targetDir, relPath);

    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, t.content, 'utf8');

    items.push({
      id: `FP-${t.name.toUpperCase()}-${i}`,
      relativePath: relPath,
      category: 'false_positive',
      isSecret: false,
    });
  }

  // =========================================================================
  // 3. ADVERSARIAL EVASIONS (60 Files: split strings, whitespace, comments, AST)
  // =========================================================================
  for (let i = 0; i < 60; i++) {
    let content = '';
    const style = i % 4;
    let relPath = '';

    if (style === 0) {
      // Split string concatenation
      const p1 = synth('ghp_');
      const p2 = randomAlpha(36);
      content = `// Split Token Evasion #${i}\nconst token = "${p1}" + "${p2}";\nexport default token;`;
      relPath = `src/adv/adv_split_${i}.ts`;
    } else if (style === 1) {
      // Multiline whitespace stretching
      const key = synth('sk_live_', randomAlpha(24));
      content = `const\n  STRIPE_KEY\n  =\n  "${key}";\n`;
      relPath = `src/adv/adv_multiline_${i}.ts`;
    } else if (style === 2) {
      // Inline comment disruption
      const key = synth('sk-proj-', randomAlpha(48));
      content = `const OPENAI_SECRET /* authorization key */ = "${key}";`;
      relPath = `src/adv/adv_comment_${i}.ts`;
    } else {
      // AST environment fallback disguise
      const key = synth('AKIA', randomAlpha(16).toUpperCase());
      content = `const key = process.env.AWS_KEY || "${key}";\nmodule.exports = key;`;
      relPath = `src/adv/adv_fallback_${i}.js`;
    }

    const fullPath = path.join(targetDir, relPath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content, 'utf8');

    items.push({
      id: `ADV-${i}`,
      relativePath: relPath,
      category: 'adversarial',
      isSecret: true,
      expectedSecretPattern: 'Adversarial',
    });
  }

  return items;
}
