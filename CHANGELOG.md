# Changelog

All notable changes to **Secret Leak Detector** are documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.4] - 2026-11-07

### Reliability & Git History Hardening
- **Immediate Child Process Termination on Stream Failure:** In `getBranchesForCommits`, immediately terminated (`child.kill()`) affected Git child processes upon receiving stdout/stderr/readline stream errors, awaiting their `close` event to prevent hanging processes and returning `failed: true` with the original error.
- **Subprocess Lifecycle Ordering:** Ensured completion waits for child process `close` rather than resolving prematurely on readline EOF, ensuring non-zero exit codes (e.g. Git fatal errors) are reliably caught and reported.
- **Streaming Branch Discovery Scale Benchmark:** Scaled benchmark coverage to 2,000 commits and 50 branches, verifying flat heap memory delta and bounded concurrency.
- **Risk Score vs. Blast Radius Mathematical Separation:** Hardened the clear separation between intrinsic static credential risk and operational containment blast radius under incomplete history.
- **Comprehensive Verification:** Expanded test coverage to 828 tests across 50 sections with 100% cross-platform pass rate.

## [1.0.3] - 2026-11-01

### Critical Fixes & Resilience
- **Electron Stand-in & Node Resolution:** Exported `ELECTRON_RUN_AS_NODE=1` in pre-commit hook script to guarantee CLI executes as Node under VS Code Electron runtimes without fail-open exits. Preferred standard `node` on PATH before Electron binary.
- **Fail-Closed Staged Scanning & Git Config Resilience:** Rewrote staged change detection using NUL-delimited status parsing (`git diff --cached -z --name-status`) with explicit prefixes and disabled colors. Immune to `diff.noprefix`, `diff.mnemonicPrefix`, `color.diff=always`, and filenames containing quotes or backslashes.
- **Batch Git Object Streaming:** Converted staged scanning from hundreds of per-file spawns to single-process streaming via `git cat-file --batch-check` and `git cat-file --batch`, accelerating multi-hundred file scans by 20x.
- **Ignore Glob Engine Overhaul:** Implemented tokenizer-based glob compiler, restoring proper matching for `**/dist/**`, `**/node_modules/**`, `**/*.min.js`, `docs/**`, and lockfiles without regex corruption.
- **Anti-Tamper CI Guardrail:** Eliminated untrusted fallback to `HEAD` in CI for `.sldignore` and baseline files, preventing PR authors from silencing scan gates.
- **UTF-16 & Encoding Support:** Added transparent decoding for UTF-16LE (with or without BOM) and UTF-16BE files, ensuring credentials in UTF-16 files are scanned rather than dropped as binary.
- **Hook Lifecycle & Storage Cleanup:** Updated `uninstall.ts` to locate installed hooks across `globalStorage` and clean up persistent CLI copies, preventing orphaned scanners. Added dynamic hook re-pinning on configuration change.
- **Multi-Line Diagnostics & Multi-Root Support:** Calculated multi-line ranges for multi-line findings (PEM keys), enabled multi-root workspace iteration in `scanStaged`, and added human-readable unignore quickpick.
- **CI/CD Publishing:** Fixed GitHub Actions publishing conditionals and removed failure-masking echo statements.

## [1.0.2] - 2026-11-01

### Security & Hardening
- **Git Pre-Commit Hook Resilience:**
  - Pinned CLI copied to stable storage under `globalStorageUri`, preventing broken hooks on extension updates.
  - Added absolute Node.js path resolution with explicit actionable recovery guidance on exit code 127.
  - Added `vscode:uninstall` script to clean up managed hooks safely when the extension is removed.
  - Added fail-safe unblocking instructions (`rm .git/hooks/pre-commit`) when scanner binaries are absent.
- **Fail-Closed Gate Hardening:**
  - Separated operational errors (exit code 2) from findings (exit code 1) and clean scans (exit code 0).
  - In CI environments, `.sldignore` and `.secretleak-baseline.json` are loaded from remote Git base refs to prevent PR tamper bypasses.
  - Implemented HMAC-SHA256 salted baseline fingerprinting to defeat rainbow-table dictionary attacks on baseline files.
- **Secondary Leak Elimination:**
  - Secrets $\le 12$ characters are completely masked (`••••••••`).
  - Secrets $> 12$ characters reveal at most 20% of their length.
  - Scrubbed `surroundingCode` and raw expressions from JSON and SARIF exports.

### Detection & Performance
- **Extended Rule Coverage:**
  - Added detection rules for Discord Bot Tokens, Telegram Bot Tokens, PyPI API Tokens, Shopify Tokens, DigitalOcean PATs, Google OAuth Access Tokens, Mailgun API Keys, Square Access Tokens, Twilio Key SIDs, and Azure AD Secrets.
  - Supported unquoted keys in `.env` and YAML configurations.
  - Added multi-vector deobfuscation for split string concatenation, array joins, template literals, and Base64 payloads.
- **ReDoS Mitigation:**
  - Bounded PEM private key search to 8,192 characters and eliminated unbounded lazy backtracking, reducing 4MB scans from 22.7s to 7.8ms.
  - Long lines $> 4,000$ characters are chunked prior to regex evaluation.
- **Fast Staged Scanning:**
  - Single `git diff --cached -U0` batch execution across index, replacing hundreds of individual child process forks.
  - Added automatic binary and oversized file skipping ($> 5\text{MB}$) with visible skipped file accounting.

### VS Code Extension & Hygiene
- **Workspace Scan Overhaul:**
  - Batch file scanning via direct file system reading, eliminating duplicate document open events and UI re-renders.
  - Added cancellation support (`CancellationToken`) and real-time progress reporting.
  - Aligned editor entropy filtering with single-policy CLI standards.
- **Crash-Safe Remediation:**
  - Reused transactional remediation engine in quick-fix code actions, writing `.env` with `0o600` permissions and verifying `.gitignore` before updating source code.
- **Packaging & Manifest Cleanups:**
  - Removed inaccurate SCM Provider category, declared `virtualWorkspaces: false`, and cleaned palette command titles.
  - Converted `media/icon.png` to a true 256x256 PNG asset, removing image LFS tracking rules.

## [1.0.1] - 2026-10-15

### Added
- Staged Git commit scanning with fail-closed security enforcement.
- OASIS SARIF v2.1.0 output formatting for GitHub Code Scanning integration.
- AST and lexical syntax analysis for environment fallback assignments (`process.env.KEY || "..."`).

## [1.0.0] - 2026-09-01

### Initial Release
- Multi-provider pattern detection for AWS, GitHub, Google Cloud, OpenAI, Anthropic, Stripe, Slack, and Database URIs.
- Shannon entropy evaluation with base-64, hex, and alphanumeric alphabet normalization.
- Git commit history scanning and blast radius risk assessment.
- VS Code extension with real-time diagnostics, sidebar views, and security dashboard.

