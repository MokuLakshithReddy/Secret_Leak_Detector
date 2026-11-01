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
5. **Deterministic Baseline Fingerprints:** Baseline fingerprints use deterministic HMAC-SHA-256 to enable cross-machine and CI deduplication. Because baseline files are tracked in version control with a standardized domain salt, low-entropy credentials could theoretically be dictionary-tested by an adversary with repository access. Repositories requiring private fingerprint domains may supply a custom salt via the `SLD_SALT` environment variable or place a private repository salt in `.sld/salt` in the repository root.


6. **Safe Extension Lifecycle & Hook Hygiene:** On extension uninstallation, `vscode:uninstall` cleans up pre-commit hooks marked with `# [SLD_HOOK_MANAGED]` across registered repositories (`~/.sld/installed-hooks.json`), global storage history, and standard local workspace roots. Custom unmanaged user hooks are strictly preserved and restored from backups. Hooks also self-detect missing scanner binaries and auto-remove themselves upon commit if the extension has been uninstalled.
