# 🔐 Secret Leak Detector

[![Visual Studio Code](https://img.shields.io/badge/VS%20Code-v1.85+-blue.svg?logo=visualstudiocode)](https://code.visualstudio.com/)
[![CI Status](https://img.shields.io/badge/CI-passing-brightgreen.svg)]()
[![Tests](https://img.shields.io/badge/tests-77%20passed%20%7C%20100%25-brightgreen.svg)]()
[![Benchmark F1](https://img.shields.io/badge/benchmark%20F1-100%25-brightgreen.svg)]()
[![Corpus](https://img.shields.io/badge/corpus-1%2C000%20cases-blueviolet.svg)]()
[![Precision](https://img.shields.io/badge/precision-100%25-00e5b0.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Secret Leak Detector** is a context-aware credential exposure detection and remediation system for Git repositories. It combines pattern detection, Shannon entropy analysis, contextual classification, Git exposure graph analysis, risk scoring, and verification to distinguish likely credentials from benign examples and track exposure beyond the current working tree.

---

## 📊 Multi-Scanner Empirical Benchmarks (Controlled & Real-World)

Secret Leak Detector was evaluated against **Gitleaks**, **TruffleHog**, and **detect-secrets** by executing each tool's standalone binary locally across two distinct benchmark suites:

### Suite A: 1,000-File Controlled Benchmark Corpus (95% Wilson CIs)
*500 True Positives, 400 False Positives, and 100 Adversarial Obfuscations generated deterministically with seeded PRNG (`0x5eec73`):*

| Scanner Tool | Precision (95% CI) | Recall (95% CI) | F1 Score | FP Rate | Adversarial | Latency / Target | Memory (RSS) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Secret Leak Detector (Ours) 1.0.0** | **100.0%** [99.4% - 100%] | **100.0%** [99.4% - 100%] | **100.0%** | **0.0%** | **100.0%** | **271 $\mu$s** | **84.1 MB** |
| **Gitleaks v8.30.1** | **100.0%** [99.1% - 100%] | 72.8% [69.1% - 76.2%] | 84.3% | **0.0%** | 37.0% | 1,028 $\mu$s | 84.7 MB |
| **TruffleHog v3.99.2** | **100.0%** [98.8% - 100%] | 54.2% [50.2% - 58.1%] | 70.3% | **0.0%** | 25.0% | 4,947 $\mu$s | 85.2 MB |
| **detect-secrets v1.5.0** | 68.7% [65.0% - 72.2%] | 73.2% [69.5% - 76.6%] | 70.9% | 50.0% | 92.0% | 88,987 $\mu$s | 85.2 MB |

### Suite B: 100-File Independently Labelled Real-World Corpus
*50 Real-World Leaks (GitHub Actions, Dockerfiles, Terraform tfvars, Django settings, Kubernetes manifests, Go APIs, and C# configs) vs 50 Real-World High-Entropy Noise cases (Subresource Integrity SHA digests, 40-char Git commit SHAs, UUIDs, PNG pixels, RFC 7519 JWT examples):*

| Scanner Tool | Precision (95% CI) | Recall (95% CI) | F1 Score | FP Rate | Latency / Target | Memory (RSS) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Secret Leak Detector (Ours) 1.0.0** | **97.5%** [87.1% - 99.6%] | **78.0%** [64.8% - 87.2%] | **86.7%** | **2.0%** | **310 $\mu$s** | **79.8 MB** |
| **Gitleaks v8.30.1** | 95.6% [85.2% - 98.8%] | 86.0% [73.8% - 93.0%] | 90.5% | 4.0% | 5,162 $\mu$s | 80.0 MB |
| **TruffleHog v3.99.2** | 100.0% [91.6% - 100%] | 84.0% [71.5% - 91.7%] | 91.3% | 0.0% | 29,387 $\mu$s | 80.4 MB |
| **detect-secrets v1.5.0** | 72.5% [57.2% - 83.9%] | 58.0% [44.2% - 70.6%] | 64.4% | 22.0% | 76,538 $\mu$s | 80.7 MB |

> **⚠️ Methodological Caution & Scope Limitations:**
> A 100-file curated corpus is valuable empirical initial evidence, but **is not enough to establish broad real-world superiority** across heterogeneous enterprise ecosystems.
> 
> We keep **controlled and real-world results strictly separate**:
> - **Controlled Suite (1,000 files):** Evaluates canonical provider signatures, synthetic variance, and adversarial evasion where SLD achieved 100% precision and recall.
> - **Real-World Suite (100 files):** Evaluates real incident patterns where SLD achieved **97.5% Precision and 78.0% Recall**. The 11 missed secrets stem from unescaped `@` symbols in PostgreSQL/MongoDB passwords disrupting URI bounds, and unquoted `AccountKey=...` parameters inside compound C# Azure connection strings.
> 
> Detailed root-cause post-mortem of all 11 false negatives and full reproduction scripts in [docs/benchmarks.md](docs/benchmarks.md).

---

## 🎯 The Philosophy: Beyond Simple Regex Scanning

A basic secret scanner answers:
> *“Does this file contain something that matches an API key regex?”*

**Secret Leak Detector answers:**
> *“Is this credential actually exposed, how confident are we, what is the explainable evidence, where did it come from in Git history, what is its blast radius, and has remediation proven that exposure is eliminated?”*

```text
                  SECRET LEAK DETECTOR PIPELINE
                                │
          ┌─────────────────────┴─────────────────────┐
          │                                           │
       DETECT                                       PROVE
          │                                           │
   Pattern Engine                              Evidence Model
   Entropy Engine                              Multi-Signal Score
   Compiler AST / Lexical                      False-Positive Gate
          │                                           │
          └─────────────────────┬─────────────────────┘
                                │
                              RISK
                                │
                    Dynamic 0-100 Score
                    Blast Radius Engine
                                │
          ┌─────────────────────┴─────────────────────┐
          │                                           │
        TRACE                                        FIX
          │                                           │
   Git Exposure Graph                          Controlled Patch Preview
   Author & Duration                           Approval Gate
   Branch Reachability                         .env & .gitignore Auto-Sync
          │                                           │
          └─────────────────────┬─────────────────────┘
                                │
                             RESCAN
                                │
                    Working-Tree Verification
                    History Purge Verification
                    Delta Reporting (Before vs After)
```

---

## ⚡ Core Capabilities

### 1. DETECT — Multi-Signal Candidate Engine
Never relies solely on regex patterns. Candidates pass through 5 discrete filters:
1. **Provider Signature:** 12+ cloud and identity provider patterns (AWS, GitHub, Google Cloud, OpenAI, Anthropic, Stripe, Slack, Microsoft Azure, Database URIs, Cryptographic PEM Keys, JWT).
2. **Shannon Entropy Engine:** Evaluates information entropy ($H = -\sum p_i \log_2 p_i$) and character set distribution (Base64, Hex, Alphanumeric).
3. **Compiler-Backed AST Analysis (TypeScript/TSX):** Employs the official TypeScript compiler parser (`ts.createSourceFile`) to inspect binary expressions (`process.env.KEY || "..."`, `??`), nested object property assignments (`config.auth.stripeKey`), and call expressions (`logger.info()`). For Python, Go, Shell, and other languages, high-performance structural lexical regex analyzers are used as fallbacks.
4. **File Environment Analysis:** Adjusts confidence based on file criticality (`.env`, `credentials.json` vs `docs/`, `tutorial.md`).
5. **Adversarial De-Concatenation:** Resolves split strings (`"ghp_" + "12345..."`) and comment-interrupted assignments before evaluation.

### 2. PROVE — Explainable Evidence Model
Every finding produces transparent, auditable evidence rather than a black-box alert:

```text
Finding #1: GitHub Personal Access Token (GitHub)
File:        src/config/auth.ts:17:14
Secret:      ghp_••••••••••••••••••••••••••••••••3a9b
Confidence:  99%
Risk Score:  83/100 [CRITICAL]
Blast Radius: SEVERE (Remote & history exposure)

Evidence:
  • [+0] Matched recognized credential signature for GitHub (GitHub Personal Access Token)
  • [+5] Cryptographic entropy: 4.81 bits/char (BASE64 set), indicates non-human randomness
  • [+10] Assigned to sensitive identifier: 'GITHUB_TOKEN'
  • [+8] Located in configuration or secret storage file (.ts)
  • [Passed] Not a documentation placeholder or test mock
```

### 3. RISK — Dynamic 0–100 Risk Engine & Model Consistency
Replaces static severity labels with a calibrated formula:

$$\text{Risk Score} = \text{Credential Severity Base} + \text{Confidence Alignment} + \text{Storage Environment} + \text{Exposure Reach}$$

- **0–25:** `LOW`
- **26–50:** `MEDIUM`
- **51–75:** `HIGH`
- **76–100:** `CRITICAL`

**Risk Model Consistency & Boundary Validation:**
Formally verified via automated test suite for mathematical calibration:
- Storage environment penalties: $\text{Score}_{\text{config}} > \text{Score}_{\text{src}} > \text{Score}_{\text{test}}$
- Reachability monotonicity: $\text{Score}_{\text{remote}} > \text{Score}_{\text{history}} > \text{Score}_{\text{uncommitted}}$
- Strict $[0, 100]$ boundary constraints across all 12 provider rules.
*(Note: Validates mathematical and behavioral consistency of the scoring model, rather than claiming statistical prediction of real-world security breaches).*

### 4. TRACE — Git Exposure Graph & Provenance Analysis
Even if a secret is deleted from the current file, Secret Leak Detector traces Git history to derive a **Git exposure graph** based on credential-related commits and reachable parent relationships:
- Distinguishes direct commit DAG parents (`DIRECT_PARENT`) from chronological event transitions (`EVENT_SEQUENCE`).
- Calculates exposure duration in days from introduction to removal.
- Checks contaminated branch reachability (`git branch -a --contains`) and remote tracking status (`origin/*`).

```bash
$ secret-leak-detector trace AKIA1234567890ABCDEF

============================================================
📊 GIT PROVENANCE & BLAST RADIUS TRACE
============================================================
Status:             ACTIVE IN HEAD & COMMITTED
In Active HEAD:     YES 🚨
In Git History:     YES ⚠️ (Rotation mandatory)
Exposure Duration:  18 days
Exposed Branches:   main, origin/main, feature/auth
Remote Pushed:      YES (External exposure risk!)
Introduced By:      Engineer Name <sha: 98d1fe4>
Commit Date:        2026-09-20 23:31:51 +0530
Commit Message:     "feat: implement auth credentials"
============================================================
```

### 5. FIX — Controlled Remediation Engine
- **Safe Masking:** Secrets are masked by default (`AKIA••••••••••••DEF`) with deterministic SHA-256 fingerprints to prevent secondary log leaks.
- **Controlled Patch Preview:** Unified diff preview before applying changes.
- **Safe `.env` Migration:** Automatically updates `.env`, generates blank `.env.example` templates, and secures `.gitignore`.
- **Git Purge Commands:** Generates exact `git-filter-repo` and BFG Repo-Cleaner commands for historical leaks.

### 6. RESCAN & BASELINE — Enterprise CI/CD Integration
- **Verification Engine:** Rescans target files to ensure hardcoded secrets are gone, variables resolve correctly, and alerts developers if historical commits still contain the key.
- **Baseline System (`.secretleak-baseline.json`):** Records existing known findings so legacy codebases can adopt security guardrails immediately. CI fails **only on newly introduced secrets**.
- **OASIS SARIF v2.1.0 Export:** Directly integrates with GitHub Code Scanning alerts.

---

## 💻 CLI Usage

```bash
# Scan current repository or directory
npx secret-leak-detector scan .

# Scan Git staged changes before commit
npx secret-leak-detector scan --staged

# Output OASIS SARIF v2.1.0 report for CI/CD
npx secret-leak-detector scan . --sarif > results.sarif

# Evaluate with baseline (ignores existing known findings, fails only on new)
npx secret-leak-detector scan . --baseline .secretleak-baseline.json

# Scan full Git commit log for historical secret leaks
npx secret-leak-detector history --max 100

# Trace provenance and blast radius of a credential
npx secret-leak-detector trace AKIAIOSFODNN7ABCDEFG

# Output exposure DAG timeline with reachability & merge awareness
npx secret-leak-detector timeline AKIAIOSFODNN7ABCDEFG

# Export formal Git DAG Exposure Graph (nodes, edges, branch reachability)
npx secret-leak-detector graph AKIAIOSFODNN7ABCDEFG --json

# Interactive controlled remediation (patch preview & .env extraction)
npx secret-leak-detector fix src/config/aws.ts

# Rescan and verify that credential exposure is resolved
npx secret-leak-detector verify src/config/aws.ts

# Install standalone Git pre-commit hook
npx secret-leak-detector hook install
```

---

## 🤖 GitHub Action Integration

Add Secret Leak Detector to `.github/workflows/security.yml`:

```yaml
name: Secret Security Gate
on: [push, pull_request]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Secret Leak Detector
        uses: MokuLakshithReddy/Secret_Leak_Detector@main
        with:
          path: '.'
          baseline: '.secretleak-baseline.json'
          sarif-output: 'results.sarif'
          fail-on-findings: 'true'

      - name: Upload SARIF to GitHub Security Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## 🖥️ VS Code Extension Usage

1. Open any workspace in VS Code.
2. In-editor real-time squiggly markers highlight credential exposures as you type or save.
3. Hover over findings to inspect confidence score, Shannon entropy, and evidence items.
4. Press `Alt+.` (Windows/Linux) or `Cmd+.` (Mac) to trigger **One-Click Quick Fix**:
   - Automatically migrates the credential to `.env`.
   - Adds `.env` to `.gitignore`.
   - Generates `.env.example`.
   - Replaces literal in code with `process.env.<VAR_NAME>`.
5. Open the **Secret Leak Detector Activity Bar Panel** to view active leaks categorized by risk score and jump directly to offending code.
6. Open the **Security Dashboard** for interactive blast radius and status visualization.

---

## 🛡️ Threat Model

Secret Leak Detector is engineered against 6 primary security threats:
- **T1: Accidental Working-Tree Commit:** Blocked via real-time editor underlines and pre-commit hook diff interception.
- **T2: Zombie Git History Exposure:** Captured via `history` commit log scanner, `timeline`, and `graph` DAG analysis.
- **T3: False Positive Alert Fatigue:** Mitigated via Shannon entropy thresholds and placeholder suppression.
- **T4: Adversarial Obfuscation Evasion:** Neutralized via string de-concatenation, comment stripping, and real compiler AST analysis.
- **T5: Secondary Secret Leakage by Scanner:** Eliminated through masked displays and SHA-256 fingerprinting.
- **T6: Destructive Remediation Regressions:** Prevented by diff previews, approval gates, and rescan verification.

*For complete threat trees and verification criteria, see [docs/threat-model.md](docs/threat-model.md).*

---

## 🧪 Testing & Verification

Run the comprehensive security engineering test suite (77 unit, integration, AST, risk, and regression tests):

```bash
npm test
```

Execute the 1,000-case comparative multi-scanner benchmark (SLD vs Gitleaks vs TruffleHog vs detect-secrets):

```bash
npm run benchmark:multi
```

Execute the 100-case independently labelled real-world benchmark suite:

```bash
npm run benchmark:realworld
```

Execute large-scale performance benchmarking across payloads up to 1GB:

```bash
npm run benchmark:scale
```

Run the automated CI regression gate (enforcing $F1 \ge 99\%$, $FPR \le 1\%$, $Latency \le 1,000\ \mu\text{s}$):

```bash
npm run benchmark:gate
```

Build the extension and standalone CLI:

```bash
npm run build
```

---

## 📜 License

MIT License. Developed for developer-first security engineering.
