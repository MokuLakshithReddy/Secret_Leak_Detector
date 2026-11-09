# Security Policy

## Reporting Security Vulnerabilities

The Secret Leak Detector team takes the security of our software and our users' codebases extremely seriously. If you discover a vulnerability or security flaw in Secret Leak Detector, please report it privately and responsibly so we can resolve it before public disclosure.

### How to Report

Please **do not** report security vulnerabilities through public GitHub issues or discussions.

Instead, please send an encrypted or private report to:
- **Email:** `security@secretleakdetector.dev` (or open a GitHub Security Advisory at [github.com/MokuLakshithReddy/Secret_Leak_Detector/security/advisories/new](https://github.com/MokuLakshithReddy/Secret_Leak_Detector/security/advisories/new))

### What to Include

To help us triage and resolve the issue quickly, please provide:
1. A description of the vulnerability, including attack vector, impact, and affected components.
2. Minimal steps to reproduce the issue (proof of concept, repository structure, or sample payload).
3. The environment in which the issue was discovered (Node.js version, OS, VS Code version, extension version).
4. Any proposed remediations or patches if available.

### Response Time & Policy

- **Initial Response:** Within 48 hours of receipt.
- **Triage & Reproduction:** Within 5 business days.
- **Patch & Advisory:** High-severity issues are prioritized with a patched release and coordinated disclosure window.

---

## Security Architecture & Guarantees

Secret Leak Detector operates under strict security engineering constraints:
1. **Local-Only Execution:** Secret detection, entropy calculation, and structural validation are performed strictly on local files. No outbound network requests are made to third-party endpoints or LLMs.
2. **Fail-Closed Commit Enforcement:** Pre-commit hooks and CI gates block execution when the scanner encounters operational errors or missing dependencies, preventing unverified commits from leaving the local machine.
3. **Secondary Leak Prevention:** Raw secret values are never printed to terminal scrollbacks, serialized in SARIF exports, or forwarded to webview DOMs. All credentials are masked with strict length-bounded redaction ($\le 20\%$ revealed characters).
4. **Crash-Safe Transactional Remediation:** Moving secrets to `.env` enforces atomic backups, file permissions (`0o600`), and `.gitignore` index verification before any disk write.
5. **Private Baseline Fingerprints:** New fingerprints use HMAC-SHA-256 with a randomly generated 256-bit repository key stored in `.sld/salt` (ignored by Git). The file is owner-only on POSIX and has inherited Windows ACLs removed. Run `secret-leak-detector salt init` to initialize it explicitly. For shared baselines, distribute the same key through an approved secret manager and set `SLD_SALT` in every authorized developer environment and as a GitHub Actions repository/environment secret. Do not commit the key or paste it into issues, PRs, logs, or chat. Baselines record a non-secret key identifier so a mismatched key fails clearly instead of making known findings appear new. Pre-metadata v1 baselines are recognized through a legacy-only public-salt compatibility path; `baseline update` migrates still-present known findings to the private scheme and does not whitelist new leaks. Rotate old credentials and remove resolved legacy entries from baselines because their historical fingerprints remain susceptible to offline guessing.


6. **Safe Extension Lifecycle & Hook Hygiene:** On extension uninstallation, `vscode:uninstall` cleans up pre-commit hooks marked with `# [SLD_HOOK_MANAGED]` across registered repositories (`~/.sld/installed-hooks.json`), global storage history, and standard local workspace roots. Custom unmanaged user hooks are strictly preserved and restored from backups. Pre-commit hooks strictly fail closed by default if the scanner CLI is missing, blocking unverified commits and providing actionable recovery commands. When opted in via `--allow-self-heal`, `SLD_ALLOW_SELF_HEAL=1`, or git config `secret-leak-detector.allow-self-heal true`, hooks safely self-heal by restoring original user backups or removing stranded hooks.
