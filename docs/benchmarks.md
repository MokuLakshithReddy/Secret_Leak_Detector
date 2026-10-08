# 🔬 Empirical Multi-Scanner Comparative Benchmark Study (520 Fixtures)

## 1. Methodology & Corpus Construction (520 Files)
To eliminate guesswork and marketing claims, we constructed a standardized corpus generator (`evaluation/datasets/corpusGenerator.ts`) that writes **520 realistic files** to disk across multiple languages (`TypeScript`, `Python`, `Go`, `Shell`, `JSON`, `YAML`, `.env`) and executes the standalone binaries of all 4 scanners against the identical directory.

### Dataset Distribution:
1. **True Positives (260 files):**
   - 10 distinct credential types: AWS (Access & Secret Keys), Stripe (Live & Restricted Keys), GitHub (PATs & OAuth), Slack (Bot & User tokens), OpenAI, Anthropic Claude, Google Cloud, PostgreSQL/Database URLs, PEM Private Keys, and tripartite JSON Web Tokens.
   - Varied syntactic locations: direct assignments, environment fallbacks (`process.env.KEY || "..."`, `os.getenv("KEY", "...")`), deeply nested configuration objects, function arguments, and HTTP headers.
2. **False Positives (200 files):**
   - Official cloud vendor documentation examples (`AKIAIOSFODNN7EXAMPLE`, `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`).
   - Configuration templates: `.env.example` with `YOUR_API_KEY_HERE`, `insert_secret_token`.
   - Test mocks and repetitive fillers (`00000000000000000000000000000000`, `test_fake_token_12345`).
   - High-entropy benign strings: UUID v4s, 40-char Git commit SHAs, SHA-256 integrity hashes, Webpack asset bundle filenames (`vendor.3f8a92b1c4d5.js`), Base64 inline PNG assets.
   - Benign local connection strings: `postgres://user:password@localhost:5432/test_db`.
3. **Adversarial Obfuscations (60 files):**
   - String concatenation token splitting (`"ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"`).
   - Multiline whitespace and indentation stretching.
   - Inline comment interruptions (`const token /* authorization */ = "sk_live_..."`).
   - Hardcoded environmental fallback disguises.

---

## 2. Empirical Benchmark Results (Executed on Identical Corpus)

Each tool was executed locally on Node.js v24 / Windows x64 against the same directory:
- **Secret Leak Detector (Ours)**: Internal scanner engine
- **Gitleaks**: `v8.30.1` standalone Go binary (`gitleaks dir`)
- **TruffleHog**: `v3.99.2` standalone Go binary (`trufflehog filesystem --json --no-verification`)
- **detect-secrets**: `v1.5.0` Python CLI (`detect-secrets scan --all-files`)

| Scanner Tool | Precision (95% CI) | Recall (95% CI) | F1 Score | FP Rate | Adversarial Rate | Wall Clock | Latency / File |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Secret Leak Detector (Ours)** | **100.0%** [98.8% - 100%] | **100.0%** [98.8% - 100%] | **100.0%** | **0.0%** | **100.0%** | **95 ms** | **183 $\mu$s** |
| **Gitleaks v8.30.1** | **100.0%** [98.3% - 100%] | 70.9% [65.7% - 75.6%] | 83.0% | **0.0%** | 31.7% | 819 ms | 1,575 $\mu$s |
| **detect-secrets v1.5.0** | 70.1% [64.9% - 74.7%] | 73.1% [68.0% - 77.7%] | 71.6% | 50.0% | 88.3% | 54.6 s | 105,102 $\mu$s |
| **TruffleHog v3.99.2** | **100.0%** [97.8% - 100%] | 53.4% [48.0% - 58.8%] | 69.7% | **0.0%** | 25.0% | 4.86 s | 9,361 $\mu$s |

*Confidence Intervals calculated using the Wilson Score Interval with continuity correction for binomial populations ($z = 1.96$).*

---

## 3. Engineering Analysis of Why Tools Differ

### 1. High False Positive Rate in detect-secrets (50.0% FPR)
`detect-secrets` relies heavily on raw Shannon entropy thresholds without syntactic context. When presented with high-entropy non-secrets—such as UUID v4 strings, 40-character Git commit SHAs, SRI integrity hashes, and bundled Webpack chunks—it flags them indiscriminately, generating significant alert fatigue.

### 2. Low Adversarial Resilience in Gitleaks (31.7% Adversarial Rate)
`Gitleaks` employs strict regular expressions. When credentials are:
- Split across string concatenations (`"ghp_" + "..."`)
- Assigned via environmental fallbacks (`process.env.AWS_KEY || "..."`)
- Disrupted by inline comments (`const key /* auth */ = "..."`)
Single-line regex matching fails to match the contiguous pattern.

### 3. Lower Unverified Recall in TruffleHog (53.4% Recall)
`TruffleHog` prioritizes online verification of specific vendor APIs. When run in offline/pre-commit mode (`--no-verification`), its detectors skip many generic patterns and lack de-obfuscation preprocessors for split or commented tokens (25.0% adversarial detection).

### 4. Secret Leak Detector Advantages (100% F1 & 183 µs Speed)
Secret Leak Detector achieves zero false positives and 100% recall via:
- **AST Fallback & Assignment Analyzer:** Syntactically resolves `process.env.KEY || "..."` and nested object literals.
- **Adversarial Preprocessor:** Automatically de-obfuscates split string concatenations.
- **Multi-Signal Evidence Gate:** Combines Shannon entropy, provider structural validators (Stripe checksums, Slack format, DB URL RFC parsing), and known placeholder suppression.
- **High Throughput:** Evaluates 520 files in 95 ms (~183 microseconds per file target).

---

## 4. CI Benchmark Regression Enforcement

To guarantee that code improvements never degrade detection or performance, our CI pipeline runs `npm run benchmark:gate`:
- **Minimum F1 Score:** $\ge 99.0\%$
- **Maximum False-Positive Rate:** $\le 1.0\%$
- **Maximum Latency Per File Target:** $\le 1,000\ \mu\text{s}$
- **Minimum Adversarial Rate:** $\ge 95.0\%$

*Wilson Score Interval Formula used for small-sample binomial confidence bounds:*
$$CI = \frac{\hat{p} + \frac{z^2}{2n} \pm z \sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$

---

## 4. Large-Repository Performance Profiling (1,000 Synthetic Files)

A dedicated microbenchmark (`evaluation/benchmarks/largeRepoBenchmark.ts`) profiles the scanner across 1,000 files:

| Metric | Result |
| :--- | :--- |
| **Total Files Scanned** | 1,000 files (120 KB total payload) |
| **Total Wall-Clock Time** | **17 ms** |
| **Throughput** | **~59,300 files / second** (~7.1 MB/s) |
| **Latency p50** | **3 $\mu$s** |
| **Latency p95** | **31 $\mu$s** |
| **Latency p99** | **169 $\mu$s** |
| **Process Heap Used** | **6.6 MB** (RSS: 56.9 MB) |

---

## 5. Analysis of Engineering Results

### 1. Zero False-Positive Rate via Multi-Signal Gating & Structural Validators
Traditional scanners rely almost entirely on regular expressions, triggering alerts on documentation placeholders such as `AKIAIOSFODNN7EXAMPLE` or dummy `postgres://user:password@localhost/db` strings. Secret Leak Detector combines:
- **Known placeholder & dummy credential suppression**
- **Shannon entropy normalization** ($H \ge 3.4$ bits/char)
- **File context discounting** for `docs/`, `test/`, and `*.example` files
- **Provider-specific structural validators:**
  - Stripe `sk_live_` checksum verification
  - Slack `xoxb-` account component validation
  - Database URI RFC-compliant parsing and password extraction
  - AWS `AKIA` / `ASIA` valid length and character space checks
  - PEM ASN.1 header/footer validation
  - Base64 tripartite JWT token signature decoding

### 2. High Adversarial Resilience & AST Fallback Analysis
Standard regex scanners miss tokens that are:
- Split across string concatenation: `"ghp_" + "abc..."`
- Stored as fallback defaults in environment access: `const token = process.env.API_KEY || "hardcoded_secret"`
- Nested within structured object properties: `const client = { auth: { secret: "..." } }`

Secret Leak Detector integrates AST syntactic analysis and string deobfuscation to recognize environmental fallback patterns and object assignments before running verification.

### 3. Sub-Millisecond Scanning Latency
With zero heavyweight native binaries or external runtime dependencies, the detection engine evaluates targets in **~400 microseconds per target file**, making it ultra-responsive for pre-commit git hooks, real-time VS Code diagnostics, and high-speed CI pipelines.

