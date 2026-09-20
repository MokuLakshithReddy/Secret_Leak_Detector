# 🔐 Secret Leak Detector - VS Code Extension

A developer-first credential protection system that detects, proves, traces, blocks, and fixes leaked secrets before they ever leave your local machine.

---

## 🚀 Features

1. **Inline Real-Time Diagnostics**:
   - Automatically scans open files as you type or save.
   - Highlights exposed credentials with red squiggly lines.
   - Computes Shannon entropy and confidence percentages for every finding.
2. **One-Click Quick Fixes (`Alt+.` / `Cmd+.`)**:
   - **Move to `.env`**: Automatically moves the hardcoded credential to your local `.env` file, replaces the code with `process.env.VARIABLE_NAME`, and ensures `.env` is safely protected in `.gitignore`.
   - **Ignore Finding**: Allows marking false positives.
3. **Git Commit Interception & Pre-Commit Guard**:
   - Scans staged changes (`git diff --cached`) before commits are finalized.
   - Blocks the commit if unredacted credentials are detected.
   - Emits terminal-first explanations with actionable remediation steps and redacted previews.
   - 1-Click installation of automated `.git/hooks/pre-commit` hook.
4. **Interactive Security Dashboard & Activity Bar Panel**:
   - Dedicated Activity Bar shield icon displaying Active Leaks grouped by risk (`CRITICAL`, `HIGH`, `MEDIUM`).
   - Rich interactive Webview dashboard with live metrics, blast radius analysis, and workflow status.

---

## 🛠️ Supported Credential Providers

- **AWS**: Access Key ID (`AKIA...`, `ASIA...`, `ABIA...`, `ACCA...`), Secret Access Key
- **GitHub**: Classic PATs (`ghp_`), Fine-Grained PATs (`github_pat_`), OAuth tokens
- **OpenAI & Anthropic**: `sk-proj-...`, `sk-ant-...`
- **Stripe**: Live & Test Secret Keys (`sk_live_...`, `rk_live_...`)
- **Slack**: Bot/User tokens (`xoxb-`, `xoxp-`), Incoming Webhooks
- **Private Keys**: RSA, DSA, EC, OPENSSH, PGP private key blocks
- **Database Connection Strings**: PostgreSQL, MySQL, MongoDB, Redis URIs containing embedded passwords
- **Generic High-Entropy Secrets**: Shannon entropy > 3.4 in assignment context

---

## 🏃 How to Run & Test Locally

### Option 1: Run in VS Code (F5)
1. Open this folder in VS Code:
   ```bash
   code C:\Users\nsrfl\.gemini\antigravity-ide\scratch\secret-leak-detector-extension
   ```
2. Press **F5** (or go to `Run and Debug` > `Run Extension`).
3. A new **Extension Development Host** VS Code window will open with the extension running live!
4. Open `samples/sample-vulnerable-file.js` to see real-time red squiggly diagnostics and try `Alt+.` Quick Fixes.
5. Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) and run:
   - `Secret Leak Detector: Open Security Dashboard`
   - `Secret Leak Detector: Scan Workspace for Secrets`
   - `Secret Leak Detector: Scan Git Staged Changes`

### Option 2: Package as a `.vsix` Extension
To package and install into any VS Code or Cursor instance:
```bash
npx @vscode/vsce package
```
This generates `secret-leak-detector-1.0.0.vsix`, which you can install via:
```bash
code --install-extension secret-leak-detector-1.0.0.vsix
```

---

## 🧪 Automated Tests

Run the test suite:
```bash
node esbuild.js --test
node dist/test-suite.js
```
