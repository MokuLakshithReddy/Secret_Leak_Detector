# 🔐 Secret Leak Detector for VS Code

[![Visual Studio Code](https://img.shields.io/badge/VS%20Code-v1.85+-blue.svg?logo=visualstudiocode)](https://code.visualstudio.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()
[![Tests](https://img.shields.io/badge/tests-100%25%20passing-brightgreen.svg)]()
[![Security](https://img.shields.io/badge/security-developer--first-00e5b0.svg)]()

> **Stop credentials from leaving your machine.**  
> A developer-first security extension that detects, proves, traces, blocks, and fixes secret leaks directly inside VS Code before they are committed or pushed to Git.

---

## 🎯 The Philosophy: Shift-Left Secret Protection

Traditional secret scanners alert you **after** code has already reached remote repositories or CI/CD pipelines—when revocation, rotation, and incident reports are already required.

```
Traditional Workflow (Reactive):
Developer ➔ git commit ➔ git push ➔ Remote Repo ➔ CI/CD Scanner ➔ Incident / Leak Alert 🚨
```

**Secret Leak Detector shifts protection directly to the editor & commit boundary:**

```
Secret Leak Detector Workflow (Preventative):
Developer ➔ Writes Code ➔ [Real-Time Inline Underline] ➔ git commit ➔ [BLOCKED with Fix Guide] ➔ Safe! 🛡️
```

```
DETECT ➔ PROVE ➔ TRACE ➔ BLOCK ➔ FIX ➔ RESCAN ➔ ALLOW
```

---

## ✨ Key Features

### 1. ⚡ Real-Time In-Editor Diagnostics
- Continuously scans active editors as you type or save.
- Credential leaks are underlined with precise squiggly error markers.
- Hovering over a finding reveals secret type, provider, confidence score, Shannon entropy, and remediation guidance.

### 2. 🪄 One-Click Quick Fixes (`Alt+.` / `Cmd+.`)
- **Move to `.env`**: Automatically extracts the exposed secret into a local `.env` file, updates the source code to `process.env.VARIABLE_NAME`, and ensures `.env` is protected in `.gitignore`.
- **Ignore False Positive**: Quickly dismisses intended mock values.

### 3. 🛑 Git Commit Interception & Pre-Commit Hook
- Inspects staged changes (`git diff --cached`) when attempting commits.
- If unredacted credentials are staged, the commit is **blocked** immediately.
- Emits an actionable terminal report detailing:
  - Exact file & line number
  - Redacted credential preview (`AKIA************CDEF`)
  - Provider and risk assessment
  - Step-by-step resolution commands
- **1-Click Hook Installer**: Run `Secret Leak Detector: Install Git Pre-Commit Hook` to enforce CLI-level commit blocking in any terminal.

### 4. 📊 Native Webview Dashboard & Activity Bar Panel
- Dedicated **Activity Bar Shield Icon** displaying all active leaks categorized by risk (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- Click any finding to jump directly to the offending line of code.
- Full-page interactive **Security Dashboard** featuring:
  - Live metric counters & commit guardrail status
  - Provider distribution & blast-radius analysis
  - Quick triggers for workspace-wide scans and hook management

### 5. 🧮 Multi-Signal Detection & Shannon Entropy Engine
- Evaluates string randomness using **Shannon entropy** ($H = -\sum p_i \log_2 p_i$) to distinguish real cryptographic keys from variable identifiers or UUIDs.
- Contextual heuristics inspect surrounding variable names (e.g. `api_key`, `secret`, `token`, `password`).
- Built-in placeholder recognition skips documentation examples (e.g. `AKIAIOSFODNN7EXAMPLE`, `your-api-key-here`).

### 6. 🔒 Automatic Redaction
- Never exposes plain-text secrets in logs, notifications, or terminal messages.
- Generates anonymous SHA-256 fingerprints to trace credential blast radius without storing plaintext.

---

## 🔍 Supported Credential Providers

| Credential Type | Provider | Pattern / Format | Risk |
| :--- | :--- | :--- | :--- |
| **AWS Access Key ID** | Amazon Web Services | `(AKIA\|ASIA\|ABIA\|ACCA)[0-9A-Z]{16}` | `CRITICAL` |
| **AWS Secret Access Key** | Amazon Web Services | 40-char high-entropy base64 in AWS context | `CRITICAL` |
| **GitHub Token** | GitHub | `ghp_`, `gho_`, `ghu_`, `github_pat_` | `CRITICAL` |
| **OpenAI API Key** | OpenAI | `sk-proj-[a-zA-Z0-9_-]{48,}`, `sk-...` | `CRITICAL` |
| **Anthropic API Key** | Anthropic | `sk-ant-[a-zA-Z0-9_-]{40,}` | `CRITICAL` |
| **Stripe Secret Key** | Stripe | `sk_live_...`, `rk_live_...`, `sk_test_...` | `CRITICAL` |
| **Slack Bot / Webhook** | Slack | `xox[baprs]-...`, `hooks.slack.com/services/...` | `HIGH` |
| **Private Keys** | Cryptography | `-----BEGIN (RSA\|EC\|DSA\|OPENSSH\|PGP) PRIVATE KEY-----` | `CRITICAL` |
| **Database Connection Strings** | Databases | `(postgres\|mysql\|mongodb\|redis)://user:pass@host/db` | `HIGH` |
| **JSON Web Tokens** | Auth / Identity | `eyJ... . eyJ... . ...` (valid JWT triples) | `HIGH` |
| **Generic High-Entropy Keys** | Any API | Key assignment (`apiKey = "..."`) with entropy > 3.4 | `MEDIUM` |

---

## 🚀 Installation

### Option 1: Install from VSIX (Direct)

1. Download or locate `secret-leak-detector-1.0.0.vsix`.
2. Open VS Code.
3. Press `Ctrl+Shift+X` (or `Cmd+Shift+X`) to open the **Extensions View**.
4. Click the **`...`** (Views and More Actions) menu in the top right corner.
5. Select **Install from VSIX...** and choose `secret-leak-detector-1.0.0.vsix`.

Alternatively, install via terminal:
```bash
code --install-extension secret-leak-detector-1.0.0.vsix
```

---

### Option 2: Run in Extension Development Host (From Source)

1. Clone or open the repository in VS Code:
   ```bash
   git clone https://github.com/MokuLakshithReddy/Secret_Leak_Detector.git
   cd Secret_Leak_Detector
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Press **`F5`** (or go to `Run and Debug` ➔ `Run Extension`).
4. A new VS Code window will launch with Secret Leak Detector running live.
5. Open `samples/sample-vulnerable-file.js` to see real-time detection in action!

---

## ⌨️ Commands

| Command | Title | Description |
| :--- | :--- | :--- |
| `secret-leak-detector.openDashboard` | **Open Security Dashboard** | Opens the interactive Webview dashboard |
| `secret-leak-detector.scanWorkspace` | **Scan Workspace for Secrets** | Scans all workspace files and aggregates findings |
| `secret-leak-detector.scanStaged` | **Scan Git Staged Changes** | Inspects staged diff for credentials before commit |
| `secret-leak-detector.installGitHook` | **Install Pre-Commit Hook** | Installs standalone `.git/hooks/pre-commit` script |
| `secret-leak-detector.clearFindings` | **Clear Findings** | Clears active findings and squiggly lines |

---

## ⚙️ Configuration Settings

Customize behavior under `Settings` (`Ctrl+,`) ➔ `Extensions` ➔ `Secret Leak Detector`:

| Setting | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `secretLeakDetector.enableRealtimeScanning` | `boolean` | `true` | Automatically scan open files as you type/save |
| `secretLeakDetector.blockGitCommits` | `boolean` | `true` | Intercept and block commits with staged secrets |
| `secretLeakDetector.minEntropy` | `number` | `3.4` | Shannon entropy threshold for generic secrets |
| `secretLeakDetector.redactSecrets` | `boolean` | `true` | Mask credentials in UI and terminal messages |
| `secretLeakDetector.excludeGlobs` | `array` | `node_modules, .git, dist, ...` | Paths ignored during full scans |

---

## 🧪 Testing & Verification

The extension comes with an automated test suite verifying pattern matching, entropy scoring, redaction, and false-positive prevention:

```bash
# Run tests
npm test
# or
node esbuild.js --test && node dist/test-suite.js
```

### Live Demonstration Simulation
To run a complete CLI simulation of the `DETECT ➔ BLOCK ➔ FIX ➔ RESCAN ➔ ALLOW` lifecycle:
```bash
node esbuild.js --demo && node dist/demo-cli.js
```

---

## 📦 Building & Packaging

```bash
# Compile and bundle with esbuild
npm run build

# Package into .vsix file
npx @vscode/vsce package
```

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

Developed with ❤️ by **[Moku Lakshith Reddy](https://github.com/MokuLakshithReddy)**.
