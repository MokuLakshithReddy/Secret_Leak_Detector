🔐 Secret Leak Detector

A cybersecurity dashboard prototype for detecting, investigating, tracing, and remediating accidentally exposed secrets in software repositories.

🌐 Live Demo

Live Application:
https://secret-leak-detector-three.vercel.app/


GitHub Repository:
MokuLakshithReddy/Secret_Leak_Detector

⸻

📌 Overview

Secret Leak Detector is a web-based cybersecurity prototype designed to demonstrate how accidentally exposed secrets can be detected and managed throughout their security lifecycle.

Instead of treating secret detection as simply:

"Potential secret found"

the prototype focuses on a complete investigation workflow:

DETECT
   ↓
PROVE
   ↓
TRACE
   ↓
FIX
   ↓
RESCAN
   ↓
SECURE

The dashboard allows users to investigate security findings, understand their risk, review verification status, examine repository exposure and Git history, view blast radius, apply remediation guidance, and rescan after remediation.

⸻

🎯 Project Goal

The goal of this project is to demonstrate a security workflow that helps answer:

WHAT was detected?
        ↓
WHY is it suspicious?
        ↓
WHERE does it exist?
        ↓
HOW serious is it?
        ↓
WHERE else did it appear?
        ↓
HOW should it be fixed?
        ↓
IS it actually resolved?

This makes the prototype more than a simple detection interface. It demonstrates the investigation and remediation experience around a potential secret leak.

⸻

✨ Features

🔎 Secret Findings

The dashboard presents security findings with information such as:

* Secret type
* Provider
* Status
* Verification result
* Signal score
* Confidence
* File location
* Line number
* Evidence
* Blast radius
* Remediation guidance

Sensitive values are represented in redacted form rather than exposing the complete credential.

Example:

Value: [REDACTED]

⸻

📈 Risk & Signal Score

The prototype presents a signal score to communicate the potential risk associated with a finding.

Example:

Signal Score: XX / 100

This helps users prioritize findings during investigation.

⸻

🟢 Verification Status

The prototype supports different verification states:

LIVE
INVALID
UNKNOWN
NOT_SUPPORTED

It also represents provider-specific verification concepts such as:

* GitHub Verifier
* AWS Verifier
* Generic / Unknown Verifier

The purpose is to distinguish between a value that looks like a secret and a finding that has additional evidence indicating its potential validity.

⸻

🌐 Provider Information

Findings can contain provider information.

Examples represented in the prototype include:

GitHub
AWS

Provider information helps provide context around the detected credential and its potential remediation path.

⸻

💥 Blast Radius

The prototype includes a blast-radius concept for understanding how widely a potential secret may have been exposed.

The interface can represent exposure across:

Current Repository Files
        ↓
Staged Files
        ↓
Git History
        ↓
Deleted / Previous Versions

This helps answer:

Has the secret only appeared in the current file, or has it existed elsewhere in the repository?

⸻

🗂️ Git History

The prototype includes a history-oriented investigation workflow.

It represents different scanning scopes:

Current Repository Files

Files currently present in the repository.

Staged Files

Files that are about to be committed.

Full Git History

Previous commits and historical repository states.

Deleted / Previous Versions

Files or content that may have contained a secret in an earlier version of the repository.

⸻

🛑 Pre-commit Protection

The application includes a dedicated Pre-commit Hook interface.

The intended workflow is:

Developer
    ↓
git commit
    ↓
Secret Scan
    ↓
Secret Found?
   ↙      ↘
 YES       NO
  ↓         ↓
BLOCK     ALLOW
COMMIT    COMMIT

Prototype limitation

The current application demonstrates the pre-commit security workflow through the frontend.

It does not currently install or execute a real Git pre-commit hook.

⸻

🔧 Remediation

The prototype includes a remediation workflow for detected secrets.

The general approach is to replace hard-coded credentials with environment variables.

Before

API_KEY = "actual-secret-value";

After

API_KEY = process.env.API_KEY;

The interface can also provide .env.example-style guidance:

# Secret Scanner — generated .env.example
# Do NOT commit real values

The objective is to encourage safer credential management.

⸻

🔄 Rescan Workflow

After a finding has been remediated, the repository should be scanned again.

The prototype represents this workflow as:

Finding Detected
      ↓
Review Finding
      ↓
Review Evidence
      ↓
Review Risk
      ↓
Review Blast Radius
      ↓
Apply Remediation
      ↓
Rescan
      ↓
Verify Resolution

This closes the loop between detection and remediation.

⸻

📊 Security Dashboard

The main application is presented as an Exposure Dashboard.

The dashboard provides an overview of the repository’s security state, including concepts such as:

* Confirmed live findings
* Blocked commits
* Total findings
* Signal scores
* Verification status
* Current files
* Historical commits
* Finding distribution
* Repository exposure

The dashboard is designed with both developers and security teams in mind.

⸻

📋 Finding Investigation

The finding detail workflow is designed to provide context around why a finding was identified.

A typical investigation follows:

Finding
   ↓
Signal Score
   ↓
Confidence
   ↓
Verification
   ↓
File + Line
   ↓
Historical Exposure
   ↓
Blast Radius
   ↓
Remediation
   ↓
Rescan

This provides more context than simply showing a raw secret-scanning alert.

⸻

📊 Compliance View

The dashboard also includes a compliance-oriented perspective.

The intended relationship is:

Repository Security
        ↓
     Findings
        ↓
       Risk
        ↓
   Remediation
        ↓
    Verification
        ↓
    Compliance

This provides a higher-level view of repository security.

⸻

⚙️ Settings

The application contains a dedicated Settings section.

This provides a place for future scanner configuration and security controls.

The current implementation primarily demonstrates the interface and navigation for this functionality.

⸻

🏗️ Architecture

The current version is a frontend application.

                    ┌─────────────────────┐
                    │        USER         │
                    │                     │
                    │ Developer / Security│
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │   React Frontend    │
                    │                     │
                    │      App.tsx        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Prototype Findings  │
                    │                     │
                    │ • Secret Type       │
                    │ • Risk              │
                    │ • Confidence        │
                    │ • Provider          │
                    │ • Verification      │
                    │ • Blast Radius      │
                    │ • History           │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Security Dashboard  │
                    │                     │
                    │ • Dashboard         │
                    │ • Pre-commit Hook   │
                    │ • History           │
                    │ • Settings         │
                    └─────────────────────┘

⸻

🛠️ Tech Stack

The repository currently uses:

Technology	Purpose
React 19	Frontend UI
React DOM 19	React rendering
TypeScript	Type-safe development
Vite	Development and build tooling
Tailwind CSS 4	Styling
CSS	Custom styling
pnpm	Package management
Oxfmt	Code formatting

The current package.json confirms React 19, Vite, TypeScript, Tailwind CSS 4, Oxfmt, and the available npm scripts. (GitHub)

⸻

📁 Project Structure

The repository currently contains a lightweight frontend structure:

Secret_Leak_Detector/
│
├── .figma/
│   └── make/
│
├── src/
│
├── .gitattributes
├── .gitignore
├── .mise.toml
├── AGENTS.md
├── CLAUDE.md
├── index.html
├── package.json
├── pnpm-lock.yaml
├── tsconfig.json
└── vite.config.ts

The repository is currently organized as a Vite-based frontend project. (GitHub)

⸻

🚀 How to Run the Application

Follow these steps to run Secret Leak Detector locally.

1. Clone the Repository

Open a terminal and run:

git clone https://github.com/MokuLakshithReddy/Secret_Leak_Detector.git

Then move into the project directory:

cd Secret_Leak_Detector

⸻

2. Install Node.js

Make sure Node.js is installed on your system.

Check your installation:

node --version

You should receive a Node.js version number.

⸻

3. Install pnpm

This project uses pnpm as its package manager.

Check whether pnpm is already installed:

pnpm --version

If pnpm is not installed, you can enable it through Corepack:

corepack enable

Then check again:

pnpm --version

⸻

4. Install Dependencies

From the project directory, run:

pnpm install

This installs all dependencies defined in package.json.

⸻

5. Start the Development Server

Run:

pnpm dev

Vite will start the development server.

You should see output similar to:

VITE v8.x.x  ready in xxx ms
➜  Local:   http://localhost:5173/

Open the displayed local URL in your browser:

http://localhost:5173/

You should now see the Secret Leak Detector dashboard.

⸻

🏭 Build for Production

To create a production build, run:

pnpm build

This generates the optimized production files.

⸻

👀 Preview the Production Build

After building the project, run:

pnpm preview

Vite will start a local server for the production build.

Open the URL displayed in the terminal.

⸻

🧹 Format the Code

The project includes an Oxfmt formatting script.

Run:

pnpm format

⸻

📜 Available Commands

Command	Description
pnpm install	Install project dependencies
pnpm dev	Start development server
pnpm build	Create production build
pnpm preview	Preview production build
pnpm format	Format project files

These commands correspond to the scripts currently defined in the repository’s package.json. (GitHub)

⸻

⚠️ Current Prototype Scope

This project is currently a frontend proof of concept.

✅ Currently Demonstrated

* Security dashboard
* Finding management interface
* Finding details
* Risk / signal score presentation
* Confidence presentation
* Provider information
* Verification states
* Blast-radius presentation
* Git history workflow
* Pre-commit protection interface
* Remediation workflow
* .env.example-style guidance
* Rescan workflow
* Compliance-oriented interface
* Security-focused navigation

🚧 Not Currently Implemented

The current repository does not yet contain a production backend scanning engine.

The following capabilities are future development areas:

* Real secret scanning engine
* Regex-based secret detection engine
* Entropy analysis
* Real Git pre-commit executable hook
* Real Git pre-push hook
* Backend API
* Persistent database
* Real-time repository scanning
* Actual Git history scanning engine
* Live provider API verification
* External credential validation
* Automatic credential rotation
* Persistent scan-history storage

Therefore, the current project should be considered a functional UI prototype, not a production-ready secret scanning platform.

⸻

🔐 Security Considerations

Never commit real secrets into this repository.

Do not commit:

.env
.env.local
API keys
Access tokens
Private keys
Passwords
Cloud credentials
Database credentials
OAuth secrets

For real applications, use environment variables or a dedicated secret-management system.

The prototype uses redacted representations such as:

[REDACTED]

instead of displaying complete credentials.

⸻

🧠 Core Concept

The project is built around five core stages:

1. DETECT

Identify a potentially exposed credential.

2. PROVE

Gather evidence and determine whether the finding is likely to be a real secret.

3. TRACE

Understand where the secret exists and whether it appeared in repository history.

4. FIX

Remove the exposed credential and move it to a safer configuration mechanism.

5. RESCAN

Check the repository again and verify that the finding has been resolved.

DETECT → PROVE → TRACE → FIX → RESCAN

⸻

🔮 Future Development

The frontend prototype can eventually be connected to a complete security backend.

A potential future architecture could include:

Developer
    │
    ▼
Git Repository
    │
    ├───────────────┐
    ▼               ▼
Pre-commit       CI/CD
Scanner          Scanner
    │               │
    └───────┬───────┘
            ▼
     Secret Detection
          Engine
            │
      ┌─────┼─────┐
      ▼     ▼     ▼
   Pattern Entropy Context
   Analysis Analysis Analysis
      │     │     │
      └─────┼─────┘
            ▼
      Risk & Confidence
            │
            ▼
       Verification
            │
            ▼
       Git History
            │
            ▼
        Blast Radius
            │
            ▼
        Remediation
            │
            ▼
          Rescan
            │
            ▼
        Dashboard

⸻

📌 Project Status

                    STATUS
Frontend                    ✅
Security Dashboard          ✅
Finding Workflow            ✅
Risk Presentation           ✅
Confidence UI               ✅
Verification UI             ✅
Blast Radius UI             ✅
History Workflow            ✅
Remediation UI              ✅
Rescan Workflow             ✅
Compliance UI               ✅
Real Scanner Engine         🚧
Backend API                 🚧
Database                    🚧
Git Hooks                   🚧
Live Verification           🚧
Automatic Rotation           🚧
Production Deployment       🚧

⸻

🏆 Summary

Secret Leak Detector is a cybersecurity dashboard prototype that explores a complete workflow for managing accidentally exposed credentials.

Instead of stopping at detection, the prototype focuses on:

DETECT
   ↓
PROVE
   ↓
TRACE
   ↓
FIX
   ↓
RESCAN
   ↓
SECURE

It demonstrates how developers and security teams could investigate a finding, understand its risk and exposure, trace it through repository history, remediate it, and verify the result.

⸻

🔐 Secret Leak Detector

Don’t just detect secrets. Understand the exposure. Fix it. Verify it.
