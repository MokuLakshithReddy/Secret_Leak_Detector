# Changelog

All notable changes to **Secret Leak Detector** are documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
