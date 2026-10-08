export interface BenchmarkTestCase {
  id: string;
  category: 'true_positive' | 'false_positive' | 'adversarial';
  provider?: string;
  description: string;
  codeSnippet: string;
  filePath: string;
  expectedDetection: boolean;
  expectedRuleId?: string;
  evasionType?: string;
}

// Runtime synthesizer to keep test tokens synthetic in source code
// without triggering remote push protection scanners
const synth = (parts: string[]) => parts.join('');

export const BENCHMARK_FIXTURES: BenchmarkTestCase[] = [
  // --- TRUE POSITIVES (Synthesized Valid Credentials) ---
  {
    id: 'tp-aws-01',
    category: 'true_positive',
    provider: 'AWS',
    description: 'AWS Access Key ID in production configuration',
    codeSnippet: `export AWS_ACCESS_KEY_ID="${synth(['AK', 'IA', 'IOSFODNN7ABCDEFG'])}"`,
    filePath: 'config/aws.ts',
    expectedDetection: true,
    expectedRuleId: 'AWS Access Key ID',
  },
  {
    id: 'tp-aws-02',
    category: 'true_positive',
    provider: 'AWS',
    description: 'AWS Secret Access Key paired assignment',
    codeSnippet: `const aws_secret_access_key = "${synth(['wJalrXUtnFEMI/K7MDENG/', 'bPxRfiCY781290ABCD'])}";`,
    filePath: 'services/cloud.js',
    expectedDetection: true,
    expectedRuleId: 'AWS Secret Access Key',
  },
  {
    id: 'tp-github-01',
    category: 'true_positive',
    provider: 'GitHub',
    description: 'GitHub Personal Access Token in deploy script',
    codeSnippet: `const GITHUB_TOKEN = "${synth(['gh', 'p_', '9876543210abcdefghijklmnopqrstuvwxyz'])}";`,
    filePath: 'scripts/release.js',
    expectedDetection: true,
    expectedRuleId: 'GitHub Personal Access Token',
  },
  {
    id: 'tp-stripe-01',
    category: 'true_positive',
    provider: 'Stripe',
    description: 'Stripe Live Secret Key in payments service',
    codeSnippet: `const stripe = Stripe("${synth(['sk', '_live_', '51M0XYZ982734bca81923456789'])}");`,
    filePath: 'src/payments/stripe.ts',
    expectedDetection: true,
    expectedRuleId: 'Stripe Secret Key',
  },
  {
    id: 'tp-openai-01',
    category: 'true_positive',
    provider: 'OpenAI',
    description: 'OpenAI API Project Key',
    codeSnippet: `const apiKey = "${synth(['sk', '-proj-', 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMn'])}";`,
    filePath: 'src/ai/agent.ts',
    expectedDetection: true,
    expectedRuleId: 'OpenAI API Key',
  },
  {
    id: 'tp-anthropic-01',
    category: 'true_positive',
    provider: 'Anthropic',
    description: 'Anthropic Claude API Key',
    codeSnippet: `client = Anthropic(api_key="${synth(['sk', '-ant-', 'api03-abcdefghijklmnopqrstuvwxyz0123456789'])}")`,
    filePath: 'llm_service.py',
    expectedDetection: true,
    expectedRuleId: 'Anthropic Claude API Key',
  },
  {
    id: 'tp-google-01',
    category: 'true_positive',
    provider: 'Google Cloud',
    description: 'Google AIza Gemini API Key',
    codeSnippet: `const GEMINI_KEY = "${synth(['AI', 'zaSyD-', '1234567890abcdefghijklmnopqrst'])}";`,
    filePath: 'config/gemini.ts',
    expectedDetection: true,
    expectedRuleId: 'Google Cloud / Gemini API Key',
  },
  {
    id: 'tp-slack-01',
    category: 'true_positive',
    provider: 'Slack',
    description: 'Slack Bot OAuth Token',
    codeSnippet: `SLACK_BOT_TOKEN="${synth(['xo', 'xb-', '1234567890-1234567890123-abcdefghijklmnopqrstuv'])}"`,
    filePath: '.env.production',
    expectedDetection: true,
    expectedRuleId: 'Slack OAuth / Bot Token',
  },
  {
    id: 'tp-db-01',
    category: 'true_positive',
    provider: 'Database',
    description: 'Postgres Connection String with Password',
    codeSnippet: `const dbUrl = "${synth(['post', 'gres://appuser:SuperStrongPass99!@db.prod.internal:5432/core_db'])}";`,
    filePath: 'config/database.ts',
    expectedDetection: true,
    expectedRuleId: 'Database Connection String with Credentials',
  },
  {
    id: 'tp-privatekey-01',
    category: 'true_positive',
    provider: 'Cryptography',
    description: 'Unencrypted RSA PEM Private Key block',
    codeSnippet: `${synth(['-----BEGIN ', 'RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y3K2...fakeKeyPayload...\n-----END RSA PRIVATE KEY-----'])}`,
    filePath: 'certs/server.key',
    expectedDetection: true,
    expectedRuleId: 'Cryptographic Private Key (PEM)',
  },

  // --- FALSE POSITIVES (Documentation, Placeholders, Tests, UUIDs) ---
  {
    id: 'fp-aws-placeholder',
    category: 'false_positive',
    description: 'Official AWS Example Key placeholder from public docs',
    codeSnippet: 'const accessKey = "AKIAIOSFODNN7EXAMPLE"; // example placeholder',
    filePath: 'docs/setup.md',
    expectedDetection: false,
  },
  {
    id: 'fp-generic-dummy',
    category: 'false_positive',
    description: 'Documentation placeholder instruction',
    codeSnippet: 'export API_KEY="your_api_key_here"',
    filePath: 'README.md',
    expectedDetection: false,
  },
  {
    id: 'fp-uuid-identifier',
    category: 'false_positive',
    description: 'Standard UUID v4 resource identifier',
    codeSnippet: 'const transactionId = "e7b1a290-2c3d-4e5f-8a1b-9c8d7e6f5a4b";',
    filePath: 'src/models/transaction.ts',
    expectedDetection: false,
  },
  {
    id: 'fp-filler-characters',
    category: 'false_positive',
    description: 'Repetitive filler dummy string',
    codeSnippet: 'const mockHash = "00000000000000000000000000000000";',
    filePath: 'tests/mocks.ts',
    expectedDetection: false,
  },
  {
    id: 'fp-sample-env',
    category: 'false_positive',
    description: 'Template sample environment configuration',
    codeSnippet: 'STRIPE_SECRET_KEY=insert_stripe_secret_key_here',
    filePath: '.env.example',
    expectedDetection: false,
  },
  {
    id: 'fp-words-identifier',
    category: 'false_positive',
    description: 'Normal English variable without secrets',
    codeSnippet: 'const username = "system_administrator";',
    filePath: 'src/auth/roles.ts',
    expectedDetection: false,
  },

  // --- ADVERSARIAL CASES (Evasion & Obfuscation Attempts) ---
  {
    id: 'adv-split-string',
    category: 'adversarial',
    description: 'Credential concatenated across split string literals',
    codeSnippet: `const token = "${synth(['gh', 'p_'])}" + "1234567890abcdefghijklmnopqrstuvwxyz";`,
    filePath: 'src/utils/auth.js',
    expectedDetection: true,
    evasionType: 'String concatenation',
  },
  {
    id: 'adv-inline-comment',
    category: 'adversarial',
    description: 'Sensitive assignment interrupted by inline comments',
    codeSnippet: `const API_KEY /* auth token */ = "${synth(['sk', '_live_', '51M0XYZ982734bca81923456789'])}";`,
    filePath: 'src/config.ts',
    expectedDetection: true,
    evasionType: 'Inline comment disruption',
  },
  {
    id: 'adv-multiline-assignment',
    category: 'adversarial',
    description: 'Credential assigned with unusual whitespace formatting',
    codeSnippet: `const\n  SECRET_KEY\n  =\n  "${synth(['sk', '-proj-', 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMn'])}";`,
    filePath: 'src/secrets.ts',
    expectedDetection: true,
    evasionType: 'Multiline whitespace stretching',
  },
];
