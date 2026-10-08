# 🛡️ Threat Model: Secret Leak Detection & Remediation

## 1. System Scope & Objective
**Secret Leak Detector** protects source code repositories across local development environments, Git commit lifecycles, and CI/CD pipelines. This threat model identifies attack vectors, failure modes, security mitigations, and verification criteria for credential exposure.

---

## 2. Threat Matrix

| ID | Threat Name | Severity | Primary Attack Vector | Mitigation in Secret Leak Detector | Verification Criterion |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **T1** | Accidental Working-Tree Commit | `CRITICAL` | Developer pastes production API key into code and runs `git commit`. | Real-time diagnostic underline + pre-commit hook staged diff interception. | Commit rejected with exit code 1; remediation plan generated. |
| **T2** | Zombie Git History Exposure | `HIGH` | Secret deleted from HEAD in a subsequent commit, but remains readable in git log. | Full commit history scanner (`history`) + provenance tracer (`trace`). | Git log commit SHA identified; purge command generated; alert issued. |
| **T3** | False Positive Alert Fatigue | `MEDIUM` | Scanner triggers on docs, UUIDs, or mocks, causing developers to disable the tool. | Multi-signal evidence model + Shannon entropy + placeholder suppression + file discounting. | Precision reaches 100% on benchmark fixtures; 0% false positives. |
| **T4** | Adversarial Obfuscation Evasion | `HIGH` | Malicious actor or accident splits credentials across concatenated strings or inline comments. | Adversarial de-concatenation normalizer + whitespace-tolerant token parsing. | Adversarial detection rate achieves 100% on concatenation tests. |
| **T5** | Secondary Secret Leakage by Scanner | `HIGH` | Scanner prints or logs unredacted secret in terminal, logs, or SARIF output. | Strict redaction masks (`AKIA••••••••••••7F2`) + SHA-256 fingerprinting. | Plaintext secret never emitted to stdout or unencrypted reports. |
| **T6** | Destructive Remediation Regressions | `MEDIUM` | Automated fix damages application syntax or deletes legitimate code. | Controlled remediation workflow (diff preview + approval gate + .env isolation). | Tests and rescan verification validate syntax integrity before commit. |

---

## 3. Threat Deep-Dive & Countermeasures

### Threat T1: Accidental Working-Tree Commit
- **Attack Vector:** An engineer configures an SDK locally and hardcodes credentials (`AWS_ACCESS_KEY_ID = "AKIA..."`). Running `git commit -m "update"` stages and synchronizes the key to origin.
- **Countermeasures:**
  1. *Shift-Left Inline Detection:* VS Code diagnostics underline keys as soon as typed or saved.
  2. *Pre-Commit Guard:* `git diff --cached` runs through `GitHistoryEngine`. If any unredacted credential exceeds the risk threshold, the commit terminates before the Git tree object is written.
  3. *Zero-Config Hook Installer:* Standalone pre-commit hook runs `secret-leak-detector scan --staged`.

### Threat T2: Zombie Git History Exposure
- **Attack Vector:** A developer realizes they committed a key, removes the line in commit `C2`, and commits "Removed secret". The secret remains accessible to any clone in `git log -p C1`.
- **Countermeasures:**
  1. *Historical Exposure Trace:* Traces `-S <secret>` across all commit DAG paths.
  2. *Blast Radius Calculator:* Evaluates whether the secret was pushed to remote tracking branches (`origin/*`) and calculates exposure duration in days.
  3. *Purge Remediation:* Generates exact `git-filter-repo` and BFG Repo-Cleaner commands.

### Threat T3: Alert Fatigue & Suppression
- **Attack Vector:** Scanners that flag `AKIAIOSFODNN7EXAMPLE` or UUIDs (`e7b1a290...`) irritate developers into adding `--no-verify` to Git commits.
- **Countermeasures:**
  1. *Entropy Gating:* Non-random words (`username = "admin"`) filtered by Shannon entropy calculation.
  2. *Known Placeholders Database:* Recognizes official AWS, Stripe, and Google example templates.
  3. *Context Weighting:* Code in `docs/` or `README.md` receives confidence penalties unless unambiguous vendor prefixes are matched.

### Threat T4: Adversarial Obfuscation & Evasion
- **Attack Vector:** Splitting tokens (e.g. `"ghp_" + "12345..."`) or injecting inline comments (`API_KEY /* auth */ = "..."`) to break standard regex scanners.
- **Countermeasures:**
  1. *De-Concatenation Normalization:* Preprocessor inspects string concatenation patterns and reconstructs combined candidate tokens for secondary evaluation.
  2. *Structural Lexical Analysis:* Matches variable assignment semantics across multiline and comment-disrupted AST tokens.

### Threat T5: Secondary Leakage in Tooling Output
- **Attack Vector:** CI logs, terminal banners, or SARIF reports leak the plaintext secret into public build pipelines.
- **Countermeasures:**
  1. *Masking by Default:* Only initial prefixes and safe trailing characters are displayed (`sk_live_••••••••••••4567`).
  2. *Anonymous Fingerprinting:* Unique SHA-256 digests identify finding identity across scans and baselines without persisting the plaintext value.

### Threat T6: Remediation Integrity
- **Attack Vector:** Automatic code rewriting breaks syntax or overwrites crucial logic.
- **Countermeasures:**
  1. *Controlled Approval Gate:* Generates unified diff previews for developer inspection.
  2. *Safe `.env` Migration:* Moves values to local `.env`, creates blank `.env.example` templates, and ensures `.env` is written into `.gitignore`.
  3. *Rescan Verification:* Re-evaluates target files after modification to prove the vulnerability is closed without collateral damage.
