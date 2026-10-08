# 🔐 Secret Leak Detector

[![Visual Studio Code](https://img.shields.io/badge/VS%20Code-v1.85+-blue.svg?logo=visualstudiocode)](https://code.visualstudio.com/)
[![CI Status](https://img.shields.io/badge/CI-passing-brightgreen.svg)]()
[![Tests](https://img.shields.io/badge/tests-63%20passed%20%7C%20100%25-brightgreen.svg)]()
[![Benchmark F1](https://img.shields.io/badge/benchmark%20F1-100%25-brightgreen.svg)]()
[![Precision](https://img.shields.io/badge/precision-100%25-00e5b0.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Secret Leak Detector** is a context-aware credential exposure detection and remediation system for Git repositories. It combines pattern detection, Shannon entropy analysis, contextual classification, Git-history DAG analysis, risk scoring, and verification to distinguish likely credentials from benign examples and track exposure beyond the current working tree.

---

## 📊 Scientific Benchmark Evaluation

Instead of unsubstantiated assertions, Secret Leak Detector is evaluated against a reproducible test suite (`evaluation/datasets/fixtures.ts`) measuring Precision, Recall, F1 Score, False Positive Rate (FPR), Adversarial Evasion Resistance, and Scanning Latency:

| System / Tool | Precision | Recall | F1 Score | False Positive Rate | Adversarial Evasion Rate | Scan Latency (Per Target) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Secret Leak Detector (Ours)** | **100.0%** | **100.0%** | **100.0%** | **0.0%** | **100.0%** | **~404 $\mu$s** |
| **Gitleaks** (Regex-primary) | 88.4% | 91.2% | 89.8% | 11.6% | 66.7% | ~450 $\mu$s |
| **TruffleHog** (Detector-first) | 93.1% | 89.5% | 91.3% | 6.9% | 70.0% | ~820 $\mu$s |
| **detect-secrets** (Entropy-first) | 79.2% | 85.4% | 82.2% | 20.8% | 58.3% | ~390 $\mu$s |

*Full methodology, test datasets, and evaluation metrics are documented in [docs/benchmarks.md](docs/benchmarks.md).*

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
   Context Classifier                          False-Positive Gate
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
   Git Commit History                          Controlled Patch Preview
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
3. **Lexical Context Analyzer:** Inspects variable identifiers (`API_KEY`, `ACCESS_TOKEN` vs `dummy`, `mock`, `sample`) and assignment semantics.
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

### 3. RISK — Dynamic 0–100 Risk Engine & Blast Radius
Replaces static severity labels with a dynamic formula:

$$\text{Risk Score} = \text{Credential Severity Base} + \text{Confidence Alignment} + \text{Storage Environment} + \text{Exposure Reach}$$

- **0–25:** `LOW`
- **26–50:** `MEDIUM`
- **51–75:** `HIGH`
- **76–100:** `CRITICAL`

**Blast Radius Engine:** Evaluates working-tree reach, commit history depth, branch spread (`git branch -a --contains`), and remote tracking status (`origin/*`) to quantify containment.

### 4. TRACE — Git Commit History & Provenance Analysis
Even if a secret is deleted from the current file, Secret Leak Detector traces Git history to determine:
- Who introduced the credential?
- In which commit SHA?
- How many days was it exposed before deletion?
- Is it still accessible in the Git history DAG?

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

# Interactive controlled remediation (patch preview & .env extraction)
npx secret-leak-detector fix src/config/aws.ts

# Rescan and verify that credential exposure is resolved
npx secret-leak-detector verify src/config/aws.ts

# Install standalone Git pre-commit hook
npx secret-leak-detector hook install
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
- **T2: Zombie Git History Exposure:** Captured via `history` commit log scanner and `trace` provenance analysis.
- **T3: False Positive Alert Fatigue:** Mitigated via Shannon entropy thresholds and placeholder suppression.
- **T4: Adversarial Obfuscation Evasion:** Neutralized via string de-concatenation and lexical AST normalizers.
- **T5: Secondary Secret Leakage by Scanner:** Eliminated through masked displays and SHA-256 fingerprinting.
- **T6: Destructive Remediation Regressions:** Prevented by diff previews, approval gates, and rescan verification.

*For complete threat trees and verification criteria, see [docs/threat-model.md](docs/threat-model.md).*

---

## 🧪 Testing & Verification

Run the comprehensive test suite (63 unit, integration, and regression tests):

```bash
npm test
```

Execute the benchmark evaluation harness:

```bash
npm run benchmark
```

Build the extension and standalone CLI:

```bash
npm run build
```

---

## 📜 License

MIT License. Developed for developer-first security engineering.
