# Validation Methodology — Secret Leak Detector

> **Version:** 1.0.3 | **Document date:** 2026-11

---

## 1. Purpose

This document provides a rigorous, independently reproducible validation
methodology for Secret Leak Detector (SLD). It is addressed to:

- **Security reviewers** assessing whether the tool actually blocks credentials.
- **Independent evaluators** who want to reproduce benchmark results without trusting author-reported numbers.
- **Project maintainers** who need a definitive test inventory.

The document makes four concrete, independently verifiable claims:

| Claim | Evidence |
|-------|----------|
| SLD detects realistic fake credentials | `demo/` — block-and-remediate fixture repo |
| SLD ignores high-entropy non-secrets (low FP rate) | `evaluation/datasets/heldOutCorpus.ts` |
| Core detector logic is covered by 399 automated tests | `test/runAllTests.ts` |
| Pre-commit hook *actually* blocks commits | `test/integration/gitHookScenarios.test.ts` |

---

## 2. Reproducible Block-and-Remediate Demonstration

### What it proves

The demo scripts create an isolated Git repository, populate it with five files
(three containing realistic fake credentials, two containing harmless
high-entropy strings), then invoke the SLD CLI directly to prove detection.
After credential remediation (replacing literals with `process.env.*`
references) the scan reruns and must exit 0.

### Commands

**Linux / macOS / Git Bash:**

```bash
npm run build
bash demo/setup-fixture-repo.sh
```

**Windows PowerShell:**

```powershell
npm run build
.\demo\setup-fixture-repo.ps1
```

### What to observe

1. **Initial scan output** — the CLI prints findings for:
   - `config/aws.env` — fake AWS IAM access key (`AKIAIOSFODNN7EXAMPLE`)
   - `db/connect.js` — fake PostgreSQL URL with password
   - `src/api.ts` — 40-character hex high-entropy string

2. **`crypto/hash.txt` is NOT flagged** — the 40-character Git SHA and the SRI
   sha384 hash are correctly identified as benign (true negatives). This proves
   the detector has provider-specific suppression, not raw entropy thresholding.

3. **Secrets are REDACTED in output** — the raw credential value is never
   printed; only a masked representation appears (e.g. `AKIA••••••••MPLE`).

4. **Post-remediation scan exits 0** — after replacing credential literals with
   `process.env.*` references the scanner finds nothing blocking.

5. **Exit codes are deterministic** — initial scan exits non-zero; post-remediation
   scan exits 0. Both are machine-checkable.

### Note on hook blocking

On projects with the SLD pre-commit hook installed, the `git commit` step would
be automatically blocked at the VCS layer — without requiring `--no-verify`.
The demo bypasses the hook (the isolated temp repo has no hook installed) and
instead runs the CLI directly to show the same detection engine. The dedicated
Git-hook integration test (`test/integration/gitHookScenarios.test.ts`) proves
actual commit blocking end-to-end.

---

## 3. Held-Out Evaluation Corpus

### Design

The file `evaluation/datasets/heldOutCorpus.ts` contains 40 labelled test
cases:

- **20 True-Positive (TP) cases** — realistic fake credentials in 8 file
  formats (`.env`, YAML, JSON, Go, Python, Shell, Terraform, Kubernetes Secret)
  and 9 credential types (AWS IAM, GitHub PAT/OAuth/fine-grained, Stripe
  live/restricted, OpenAI, Anthropic, Google API, Slack bot/webhook,
  PostgreSQL URL, Kubernetes Secret).

- **20 True-Negative (TN) cases** — high-entropy non-secrets: SRI hashes,
  40-char Git SHAs, RFC 7519 Appendix A.1 JWT example tokens, UUID v4s,
  base64-encoded PNG pixels, Webpack bundle filenames, localhost database URLs,
  `AKIAIOSFODNN7EXAMPLE` (AWS documentation example), repetitive fillers, and
  test mock tokens.

**Separation from development data:** This corpus was written after detector
rules were finalized. No case from this file influenced threshold tuning or
pattern selection. It is structurally analogous to a held-out test set in ML
evaluation.

**Synthesized credentials:** All credentials are built with the `synth()`
helper (`parts.join('')`) so the repository's own scanner does not flag this
source file. No real credentials appear anywhere.

### How to run

```bash
npm run build
npm run benchmark:heldout
```

### How to read the output

```
══════════════════════════════════════════════════════════════
  Held-Out Evaluation Corpus — Secret Leak Detector
══════════════════════════════════════════════════════════════
  Cases: 40 (20 TP, 20 TN)

  ✅ TP detected  [HO-TP-01] AWS IAM access key in .env file
  ✅ TP detected  [HO-TP-02] GitHub personal access token (ghp_)
  ...
  ✅ TN ignored   [HO-TN-01] Subresource Integrity (SRI) sha384 hash
  ...

── Confusion Matrix ─────────────────────────────────────────
  True  Positives (TP): 20
  False Positives (FP): 0
  True  Negatives (TN): 20
  False Negatives (FN): 0

── Performance Metrics ──────────────────────────────────────
  Precision : 100.0%
  Recall    : 100.0%
  F1 Score  : 100.0%
  FP Rate   : 0.0%
══════════════════════════════════════════════════════════════
```

- **TP detected** = correctly flagged as containing a credential
- **TN ignored** = correctly not flagged (benign high-entropy string)
- **FP flagged** = incorrectly flagged (false alarm — should be zero)
- **FN missed** = credential not detected (missed — should be zero)

### Actual results (run on clean checkout)

See `evaluation/reports/held_out_results.json` for the actual confusion matrix
counts recorded after running `npm run benchmark:heldout` on a clean checkout.
The `expectedResults` field in that file reflects the deterministic run output
and can be compared to your own reproduction.

### How to report discrepancies

If your reproduction produces different TP/FP/TN/FN counts, please open a
GitHub Issue at
https://github.com/MokuLakshithReddy/Secret_Leak_Detector/issues
with the output of `npm run benchmark:heldout` and your Node.js + OS version.

---

## 4. Development Test Suite

### Overview

`test/runAllTests.ts` contains **643 tests** across 45 sections. It is the
primary regression guard run on every CI push/PR.

### Run

```bash
npm test
# or equivalently:
npm run build && node dist/test-suite.js
```

### Section inventory

| Section | Description |
|---------|-------------|
| §01 | Core Scanner: AWS access keys, Stripe live/restricted keys, GitHub PATs, generic high-entropy secrets |
| §02 | Shannon Entropy Engine: correct bit calculations, normalized entropy, empty/short strings |
| §03 | Redactor: masking format, SHA-256 fingerprint generation, secret isolation |
| §04 | Baseline Engine: add/update/lookup/remove fingerprints, schema validation |
| §05 | SARIF Formatter: schema fields, result mapping, location URIs |
| §06 | Risk Engine: confidence-to-tier mapping, evidence weighting |
| §07 | File Context Analyzer: high-risk path detection, exclude glob matching |
| §08 | Remediation Engine: env file generation, gitignore update, code replacement diff |
| §09 | AST/Lexical Context Analyzer: concatenation unrolling, comment stripping |
| §10 | CLI Integration: scan command exits, --sarif flag, --baseline flag |
| §11 | Git History Engine: timeline extraction, commit graph traversal |
| §12 | Git Service: staged-blob scan interface |
| §13 | Evidence Engine: evidence item accumulation, weight aggregation |
| §14 | Multi-provider detection: OpenAI, Anthropic, Google Cloud, Slack, SendGrid |
| §15 | False-positive suppression: SRI hashes, Git SHAs, UUIDs, repetitive fillers |
| §16 | Pre-commit hook builder: script structure, fail-closed logic |
| §17 | Verification Engine: live-file re-scan, deleted file handling |
| §18 | Policy engine: tier ordering, threshold resolution, shouldBlock() |
| §19 | Dashboard model: toRedactedFindingView — rawSecret exclusion |
| §20 | Context-aware suppression: `.env.example`, placeholder strings |
| §21 | Scan boundary: node_modules exclusion, .git exclusion, binary file skipping |
| §22 | Policy CLI: fail-on flag propagation, threshold enforcement |
| §24 | Dashboard Panel: CSP nonce, no inline onclick, safe DOM creation |
| §25 | Verification Engine: deleted file Git history independence |
| §26 | Baseline schema validation edge cases |
| §27 | CLI Options & SARIF Schema Invariants |
| §28 | Lexical AST: Method Calls & Property Access Suppressions |
| §29 | Long Line Coordinate Mapping, Multi-Part Joins & Baseline Resolution |
| §30 | Staged Added-Line Filter, Ignore-Skipped & Verification Invariants |
| §31 | Verification Engine Integration & Git Staged Hook Invariants |
| §32 | Content-Based Inspection, Encodings (UTF-16BE/32/Gzip), NUL Byte & Base64 Resilience |
| §33 | Unicode/CRLF Normalization, Property Access & File Size Limits |
| §34 | Private Salt (.sld/salt), Auto-Recovery Hook Cleanup & NON_TEXT_EXTENSIONS |
| §35 | CI Trusted Base Ref, Staged Multiline PEM & Fail-On-Skipped Invariants |
| §36 | Compact JSON, Quoted Auth Header, Hyphenated Keys & Hook Fail-Closed Defaults |
| §37 | Cross-Platform Baseline Canonicalization, Deobfuscation Source Expressions, and Atomic Uninstaller |
| §38 | Uninstaller Lock Race Protection, Capture Group Isolation & Strict Defaults |
| §39 | History Scanning Multiline Invariants, Multi-Hunk Attributions, and Working-Tree State |
| §40 | History Correctness, Staged Index Verification & CI Baseline Invariants |
| §41 | Git History Deep Search, Metadata Incompleteness & Tri-State CLI Invariants |
| §42 | Lazy AST Parsing, Fail-Closed Node Version Guards & Engine Shims |
| §43 | Git Process Argument Confinement, Removal Error Handling & Electron Runtime Protection |
| §44 | Unmerged Branch Removal Lineage, Windows Explicit ACL Stripping & Hook-Gated Parser Copying |

> **Note:** Section §23 (GitHub Action: Shell Injection Prevention) was removed
> when `action.yml` was deleted from the repository. The section numbers above
> §22 were not renumbered; §24 follows §22 intentionally.

---

## 5. Git-Hook Integration Tests

### What they prove

`test/integration/gitHookScenarios.test.ts` proves that the pre-commit hook
generated by `buildPreCommitHook()` *actually rejects* a `git commit` containing
a fake credential and *actually allows* a clean commit after the credential is
removed.

This is the only test that executes a real `git commit` in a real Git
repository — all other tests call the scanner engine directly.

### Run

```bash
npm run build
npm run test:git-hook
```

### Test coverage

| Test | Expected outcome |
|------|-----------------|
| `buildPreCommitHook()` returns a non-empty sh script | Pass |
| Script starts with `#!/bin/sh` and contains `SLD_HOOK_MARKER` | Pass |
| Hook file written to `.git/hooks/pre-commit` | Pass |
| Commit with fake AWS key is rejected (exit ≠ 0) | Pass |
| Repository has 0 commits after blocked attempt | Pass |
| Clean commit (credential replaced with `process.env.*`) is allowed | Pass |
| Repository has exactly 1 commit after clean commit | Pass |
| Second credential commit is rejected again | Pass |
| Repository still has 1 commit after second block | Pass |

**Platform note:** On Windows without Git Bash, the sh-script hook cannot be
executed natively. The test detects this condition and skips the live commit
tests (groups 3–5), still passing the generation and installation tests (groups
1–2). Install Git for Windows (which bundles bash) to run the full suite.

---

## 6. Independent Benchmark Methodology

### Tool versions used for internal reporting

| Tool | Version | Platform |
|------|---------|----------|
| Node.js | v24 | Windows x64 |
| TypeScript (dev/optional) | 5.3.3 | Dynamic AST parsing when present; zero-dependency lexical fallback |
| Secret Leak Detector | 1.0.3 | — |

### Determinism

All corpus generators use a fixed PRNG seed (`0x5eec73`) so the 1,000-file
benchmark corpus is byte-identical across runs. The held-out corpus contains
fixed string literals — no randomness.

### Commands (in order)

```bash
git clone https://github.com/MokuLakshithReddy/Secret_Leak_Detector.git
cd Secret_Leak_Detector
npm ci
npm run build
npm test                     # 771 tests across 50 sections (828 tests total including git-hook and manifest suites)
npm run benchmark:heldout    # confusion matrix
npm run benchmark:gate       # 520-fixture regression gate
npm run test:git-hook        # 40 git-hook integration tests (commit blocking)
npm run test:manifest        # 17 VS Code manifest & architecture tests
npm run package              # .vsix packaging
```

### Held-out corpus actual results

See `evaluation/reports/held_out_results.json`. The `expectedResults` object
contains the confusion matrix recorded on the reference machine. An independent
evaluator should expect to match these counts exactly (the corpus is
deterministic).

---

## 7. Known Limitations

The following claims are **NOT** made by this validation document and are **NOT**
proven by the above tests:

- **IDE Extension Host display** — the tests do not exercise the VS Code
  Extension Host, WebviewPanel rendering, or diagnostic squiggly line display.
  These require a real VS Code instance.

- **macOS / Linux platform equivalence** — the benchmark results were recorded
  on Windows x64. Platform-specific path handling and shell differences have not
  been systematically tested across macOS and Linux.

- **Multi-user developer studies** — no human-subject study has been conducted.
  The false-positive and false-negative rates reported here are measured against
  a synthetic and a curated fixture corpus, not against real codebases scanned
  by real developers.

- **Novel credential types** — the detector covers the 14 provider-specific
  rules in `src/core/detectors/rules.ts` plus generic entropy detection. Novel
  credential formats not yet in the ruleset will not be detected.

- **Adversarial evasion at scale** — the adversarial corpus (100 obfuscated
  files) shows 100% detection in the internal benchmark. This does not imply
  that all possible obfuscation techniques are covered.

---

## 8. How to Verify Without Trusting Our Claims

Follow these steps on your own machine to produce independent verification:

1. **Clone a fresh copy of the repository**
   ```bash
   git clone https://github.com/MokuLakshithReddy/Secret_Leak_Detector.git sld-verify
   cd sld-verify
   ```

2. **Install dependencies (no `npm install` — use the lockfile)**
   ```bash
   npm ci
   ```

3. **Build the CLI and extension bundle**
   ```bash
   npm run build
   ```
   Expected: exits 0, produces `dist/cli.js` and `dist/extension.js`.

4. **Run the development test suite**
   ```bash
   npm test
   ```
   Expected: final line reads `TEST SUMMARY: 769 PASSED, 0 FAILED`.

5. **Run the held-out evaluation**
   ```bash
   npm run benchmark:heldout
   ```
   Expected: confusion matrix shows TP=20, FP=0, TN=20, FN=0 (or close to it
   depending on which TN cases the generic entropy detector catches).
   Compare raw counts to `evaluation/reports/held_out_results.json`.

6. **Run the block-and-remediate demo**
   ```bash
   bash demo/setup-fixture-repo.sh   # Linux/macOS/Git Bash
   # or: .\demo\setup-fixture-repo.ps1  (PowerShell)
   ```
   Expected: initial scan reports findings in `config/aws.env`, `db/connect.js`,
   `src/api.ts`; `crypto/hash.txt` is NOT flagged; post-remediation scan exits 0.

7. **Run the Git hook integration tests**
   ```bash
   npm run test:git-hook
   ```
   Expected: `TEST SUMMARY: X PASSED, 0 FAILED`. On Windows without Git Bash,
   groups 3–5 are skipped but groups 1–2 still pass.

8. **Package the VS Code extension**
   ```bash
   npm run package
   ```
   Expected: produces `secret-leak-detector-1.0.3.vsix` without errors.

9. **Scan the repository itself for accidental secrets**
   ```bash
   node dist/cli.js scan . --baseline .secretleak-baseline.json
   ```
   Expected: exits 0 (all findings known and baselined; no new credential leaks).

10. **Compare your results to the expected values in this document**
    If any step produces a different result, open a GitHub Issue with the
    complete output and your Node.js + OS version.
