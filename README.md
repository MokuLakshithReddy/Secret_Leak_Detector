🔐 Secret Leak Detector

A developer-first secret protection system designed to detect accidentally exposed credentials before they are committed or pushed to a Git repository.

Secret Leak Detector is a cybersecurity project focused on preventing one of the most common developer security mistakes:

A developer accidentally puts a secret inside the source code
                         ↓
                 git commit / push
                         ↓
              Secret reaches repository
                         ↓
                 Security incident

The idea behind this project is to move secret detection closer to the developer and earlier into the development workflow.

Instead of waiting for a repository, CI/CD pipeline, or security team to discover the exposed credential, Secret Leak Detector is designed as a VS Code extension that can identify the problem while the developer is committing or pushing code.

⸻

🎯 The Core Idea

The main idea is simple:

Don’t wait until a secret reaches the repository. Stop it before it leaves the developer’s machine.

The intended workflow is:

Developer writes code
        ↓
Developer accidentally adds a secret
        ↓
Developer runs git commit / git push
        ↓
Secret Leak Detector checks the changes
        ↓
Secret detected?
     ↙        ↘
   YES         NO
    ↓           ↓
BLOCK          ALLOW
    ↓
Explain the problem
    ↓
Show where it was detected
    ↓
Tell developer how to fix it
    ↓
Developer fixes the secret
    ↓
Retry commit / push

The system is therefore designed around:

DETECT
   ↓
PROVE
   ↓
TRACE
   ↓
BLOCK
   ↓
FIX
   ↓
RESCAN
   ↓
ALLOW

⸻

💡 What Makes This Approach Different?

Traditional secret detection often happens after code has already reached a remote repository or CI/CD environment.

The approach proposed by Secret Leak Detector is developer-workflow-first.

Instead of:

Developer
    ↓
Commit
    ↓
Push
    ↓
Remote Repository
    ↓
CI/CD
    ↓
Security Scanner
    ↓
Alert

the intended approach is:

Developer
    ↓
VS Code
    ↓
Commit / Push
    ↓
Secret Leak Detector
    ↓
Scan Before Code Leaves
    ↓
┌───────────────────┐
│ Secret detected?  │
└─────────┬─────────┘
          │
     ┌────┴────┐
     ↓         ↓
    YES        NO
     ↓         ↓
   BLOCK      ALLOW
     ↓
 Explain + Remediate

The key principle

Security should happen where the developer is already working.

The developer should not have to leave VS Code and open another security dashboard just to understand why a commit failed.

⸻

🧩 VS Code Extension Concept

The final product is intended to operate as a VS Code extension.

Once installed, the extension would integrate with the developer’s existing Git workflow.

┌─────────────────────────────────────────┐
│              VS CODE                    │
│                                         │
│  Source Code                            │
│      │                                  │
│      ▼                                  │
│  Developer writes code                  │
│      │                                  │
│      ▼                                  │
│  Git Commit / Git Push                  │
│      │                                  │
│      ▼                                  │
│  Secret Leak Detector Extension         │
│      │                                  │
│      ▼                                  │
│  Secret Detection Engine                │
│      │                                  │
│      ├───────────────┐                  │
│      │               │                  │
│      ▼               ▼                  │
│   Secret?          Safe?                │
│      │               │                  │
│      ▼               ▼                  │
│    BLOCK            ALLOW               │
│      │                                  │
│      ▼                                  │
│  Terminal Message                      │
│  + Finding Details                     │
│  + Fix Guidance                        │
│                                         │
└─────────────────────────────────────────┘

⸻

🏗️ Proposed Architecture

The intended architecture consists of several components.

                         ┌───────────────────────┐
                         │       Developer       │
                         └───────────┬───────────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │       VS Code         │
                         │                       │
                         │  Source Code Editor   │
                         └───────────┬───────────┘
                                     │
                              git commit / push
                                     │
                                     ▼
                    ┌────────────────────────────────┐
                    │     Secret Leak Detector        │
                    │       VS Code Extension         │
                    └───────────────┬────────────────┘
                                    │
                                    ▼
                    ┌────────────────────────────────┐
                    │       Detection Engine          │
                    │                                │
                    │  • Pattern Detection            │
                    │  • Secret Classification        │
                    │  • Context Analysis             │
                    │  • Entropy / Randomness         │
                    │  • Risk Scoring                 │
                    └───────────────┬────────────────┘
                                    │
                                    ▼
                    ┌────────────────────────────────┐
                    │       Verification Layer        │
                    │                                │
                    │  • Provider Identification      │
                    │  • Verification Status           │
                    │  • Confidence                   │
                    └───────────────┬────────────────┘
                                    │
                                    ▼
                    ┌────────────────────────────────┐
                    │       Exposure Analysis         │
                    │                                │
                    │  • Current Changes              │
                    │  • Staged Files                 │
                    │  • Git History                  │
                    │  • Blast Radius                 │
                    └───────────────┬────────────────┘
                                    │
                                    ▼
                    ┌────────────────────────────────┐
                    │       Decision Engine           │
                    │                                │
                    │     Secret Found?              │
                    └───────────────┬────────────────┘
                                    │
                         ┌──────────┴──────────┐
                         ▼                     ▼
                       BLOCK                 ALLOW
                         │                     │
                         ▼                     ▼
                  Terminal Message        Git continues
                         │
                         ▼
                    Remediation
                         │
                         ▼
                       Rescan
                         │
                         ▼
                      Commit

⸻

🔎 How Detection Works

When the developer attempts to commit or push code, the extension is intended to inspect the relevant changes.

For example, a developer might accidentally write:

const AWS_ACCESS_KEY = "AKIAxxxxxxxxxxxxxxxx";

or:

const API_KEY = "sk-xxxxxxxxxxxxxxxx";

The extension should identify that the value may represent a credential.

The detection pipeline can consider multiple signals:

Potential Secret
       │
       ├── Pattern Match
       │
       ├── Secret Type
       │
       ├── Provider
       │
       ├── Context
       │
       ├── Entropy
       │
       └── Location
              │
              ▼
        Risk / Confidence

The objective is not simply to search for one fixed string pattern.

The system should combine multiple signals to determine whether something is likely to be a real secret.

⸻

🎯 Detection Scope

The intended scanner can inspect:

1. Current Changes

Code that the developer has modified.

2. Staged Changes

Files currently staged for commit.

3. Commit Content

The changes that are about to become part of a Git commit.

4. Push Content

Changes that are about to be pushed to a remote repository.

5. Git History

Previous commits can also be inspected when investigating the exposure of an already detected secret.

⸻

🛑 Blocking the Commit

One of the most important parts of the idea is that the extension should actively prevent the accidental commit.

For example:

$ git commit -m "Add API integration"
🔐 Secret Leak Detector
Scanning staged changes...
✖ SECRET DETECTED
Type:        API Key
Provider:    Example Provider
File:        src/config.js
Line:        14
Confidence:  96%
Risk:        HIGH
The detected credential appears to be hard-coded
inside the source code.
Commit blocked.
Please remove the secret and use an environment
variable or secure secret manager.
Example:
    API_KEY = process.env.API_KEY
After fixing the issue, try committing again.

The important part is:

SECRET DETECTED
       ↓
COMMIT BLOCKED
       ↓
EXPLAIN WHY
       ↓
SHOW WHERE
       ↓
SHOW HOW TO FIX

⸻

🖥️ Terminal-First Communication

A key part of the proposed experience is communicating directly through the terminal.

The developer should not simply receive:

ERROR: Commit failed

Instead, the extension should provide actionable information:

❌ Commit blocked by Secret Leak Detector
Reason:
A potential AWS credential was detected.
File:
src/config/aws.ts
Line:
18
Risk:
HIGH
Confidence:
94%
Why:
The value matches a known credential pattern and
appears to be hard-coded in source code.
Recommended fix:
Move the credential into an environment variable.
Example:
AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID
After fixing:
1. Save the file
2. Stage the changes
3. Run the commit again

This makes the security system developer-friendly rather than simply restrictive.

⸻

🔐 Secret Redaction

The extension should never unnecessarily print the complete secret into the terminal.

Instead of:

Secret:
sk-1234567890abcdef...

it should display:

Secret:
[REDACTED]

The user should receive enough information to locate and fix the issue without exposing the credential again.

⸻

📊 Risk & Confidence

Each finding can have two important characteristics:

Risk

How dangerous the exposure could be.

LOW
MEDIUM
HIGH
CRITICAL

Confidence

How confident the detection system is that the value represents a real secret.

Example:

Confidence: 96%
Risk: HIGH

This allows the system to distinguish between:

High-confidence secret

and:

Possible false positive

⸻

🟢 Verification

Where possible, the system can determine whether a detected credential appears to be valid.

Possible states include:

LIVE
INVALID
UNKNOWN
NOT_SUPPORTED

The verification layer can identify the provider where possible.

For example:

Provider: GitHub
Verifier: GitHub Verifier
Status: LIVE

or:

Provider: AWS
Verifier: AWS Verifier
Status: UNKNOWN

Verification should be handled carefully because credentials are sensitive and external validation may have security implications.

⸻

💥 Blast Radius

Finding a secret is only one part of the problem.

The next question is:

Where else has this secret appeared?

The system can investigate:

Current File
     ↓
Other Current Files
     ↓
Staged Changes
     ↓
Previous Commits
     ↓
Deleted Files
     ↓
Git History

This creates a blast-radius view of the potential exposure.

For example:

Secret Exposure
Current files:       1
Historical commits:  4
Deleted versions:    2
Total exposure:      7 locations

⸻

🔧 Remediation

Once a secret is detected, the extension should help the developer fix it.

Unsafe

const API_KEY = "my-secret-key";

Recommended

const API_KEY = process.env.API_KEY;

The extension can also suggest:

.env
.env.example
Environment Variables
Secret Manager

depending on the project’s requirements.

⸻

🔄 Rescan

After the developer fixes the issue, the system should scan again.

SECRET DETECTED
       ↓
COMMIT BLOCKED
       ↓
DEVELOPER FIXES CODE
       ↓
RESCAN
       ↓
┌──────────────────┐
│ Secret still     │
│ present?         │
└────────┬─────────┘
         │
     ┌───┴───┐
     ▼       ▼
    YES      NO
     │        │
     ▼        ▼
  BLOCK     ALLOW
             │
             ▼
           COMMIT

This prevents a developer from simply being told that something is wrong without confirming that it has actually been fixed.

⸻

🖥️ Prototype Dashboard

The current repository contains the web-based prototype/dashboard used to demonstrate this security workflow.

The repository is currently implemented as a React + Vite frontend rather than as the final VS Code extension. The GitHub repository contains the frontend source and Vite configuration, and its current package.json defines the development, build, preview, and formatting commands.

The dashboard represents concepts such as:

* Security findings
* Risk
* Confidence
* Verification
* Provider
* Git history
* Blast radius
* Blocked commits
* Remediation
* Rescanning
* Compliance

The dashboard therefore acts as a prototype representation of the security system and investigation workflow.

⸻

🧪 How the Current Prototype Works

The current repository is a frontend proof of concept.

The current architecture is:

React
  ↓
TypeScript
  ↓
Vite
  ↓
Prototype Finding Data
  ↓
Security Dashboard

The dashboard presents predefined security findings and allows the user to explore the intended workflow.

The current prototype demonstrates the user experience and security logic concept rather than executing a production Git scanning engine.

⸻

🚧 Prototype vs Intended Product

It is important to distinguish between the current prototype and the final product vision.

Capability	Current Prototype	Intended Product
Security dashboard	✅	✅
Finding investigation	✅	✅
Risk presentation	✅	✅
Confidence	✅	✅
Verification UI	✅	✅
Git history concept	✅	✅
Blast-radius concept	✅	✅
Remediation workflow	✅	✅
Rescan workflow	✅	✅
VS Code extension	🚧	✅
Real Git integration	🚧	✅
Commit interception	🚧	✅
Push protection	🚧	✅
Real scanning engine	🚧	✅
Terminal security messages	🚧	✅
Persistent scan history	🚧	Future
Provider verification	🚧	Future

The current repository is therefore a prototype of the intended security experience, while the VS Code extension represents the planned product implementation.

⸻

🏗️ Final Product Architecture

The intended final system would look like:

                         DEVELOPER
                             │
                             ▼
                       ┌───────────┐
                       │  VS Code  │
                       └─────┬─────┘
                             │
                             ▼
                 ┌──────────────────────┐
                 │ Secret Leak Detector │
                 │    VS Code Extension │
                 └──────────┬───────────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
              ▼             ▼             ▼
         Git Events      Scanner       UI/Terminal
              │             │             │
              │             ▼             │
              │       Detection Engine    │
              │             │             │
              │       ┌─────┼─────┐       │
              │       ▼     ▼     ▼       │
              │    Pattern Context Entropy│
              │       │     │     │       │
              │       └─────┼─────┘       │
              │             ▼             │
              │      Risk + Confidence    │
              │             │             │
              └─────────────┼─────────────┘
                            ▼
                     Decision Engine
                            │
                 ┌──────────┴──────────┐
                 ▼                     ▼
              BLOCK                   ALLOW
                 │                     │
                 ▼                     ▼
          Terminal Error          Git Continues
                 │
                 ▼
            Remediation
                 │
                 ▼
              Rescan
                 │
                 ▼
              ALLOW

⸻

🔄 Complete User Flow

1. Developer opens a project in VS Code
                ↓
2. Secret Leak Detector extension is installed
                ↓
3. Developer writes code
                ↓
4. Developer accidentally hard-codes a credential
                ↓
5. Developer runs git add / git commit
                ↓
6. Secret Leak Detector scans the relevant changes
                ↓
7. Potential secret detected
                ↓
8. Risk + confidence calculated
                ↓
9. Finding is presented
                ↓
10. Commit is blocked
                ↓
11. Terminal explains the problem
                ↓
12. Developer fixes the secret
                ↓
13. Developer attempts commit again
                ↓
14. Extension rescans
                ↓
15. No secret detected
                ↓
16. Commit succeeds
                ↓
17. Developer pushes safely

⸻

🧠 Why VS Code?

The VS Code extension approach is important because VS Code is already where the developer:

* Writes code
* Reviews files
* Uses the integrated terminal
* Stages changes
* Commits code
* Pushes code
* Fixes errors

Instead of introducing another security workflow, Secret Leak Detector aims to embed security into the developer’s existing workflow.

The security system becomes:

Developer Workflow
        +
Security Protection
        =
Secure Development Workflow

⸻

🚀 Running the Current Prototype

Prerequisites

Install:

* Node.js
* pnpm

Check Node.js:

node --version

Check pnpm:

pnpm --version

⸻

1. Clone the Repository

git clone https://github.com/MokuLakshithReddy/Secret_Leak_Detector.git

Move into the project:

cd Secret_Leak_Detector

⸻

2. Install Dependencies

pnpm install

⸻

3. Start the Prototype

pnpm dev

Vite will start the development server.

You should see a local address similar to:

http://localhost:5173/

Open that address in your browser.

⸻

4. Build the Prototype

To create a production build:

pnpm build

⸻

5. Preview the Production Build

pnpm preview

⸻

6. Format the Project

pnpm format

These commands correspond to the scripts currently defined in the repository’s package.json.

⸻

🛠️ Technology Stack

Current Prototype

React 19
TypeScript
Vite
Tailwind CSS 4
CSS
pnpm

Intended Extension

The final VS Code implementation is expected to introduce:

VS Code Extension API
        +
Git Integration
        +
Secret Detection Engine
        +
Risk / Confidence Engine
        +
Terminal Communication
        +
Remediation Workflow

⸻

🔮 Future Development

The next major development stage is converting the prototype into a real VS Code extension.

Phase 1 — Extension Foundation

Create VS Code Extension
        ↓
Register Commands
        ↓
Detect Workspace
        ↓
Access Git Repository

Phase 2 — Secret Detection

Changed Files
      ↓
Secret Scanner
      ↓
Pattern Detection
      ↓
Context Analysis
      ↓
Risk Score
      ↓
Confidence

Phase 3 — Git Protection

git commit
     ↓
Secret Scan
     ↓
Secret?
  ↙     ↘
YES      NO
 ↓        ↓
BLOCK    ALLOW

Phase 4 — Terminal Communication

Commit Blocked
      ↓
Terminal Output
      ↓
Finding
      ↓
File + Line
      ↓
Risk
      ↓
Recommended Fix

Phase 5 — Rescan

Fix
 ↓
Retry
 ↓
Rescan
 ↓
Safe
 ↓
Allow Commit

Phase 6 — Advanced Protection

Future versions could include:

* Push protection
* Git history scanning
* Provider-specific verification
* Secret rotation guidance
* Repository-wide scanning
* CI/CD integration
* Team dashboards
* Persistent finding history
* Security policies
* Organization-level configuration

⸻

🔐 Security Philosophy

Secret Leak Detector is based on a simple security principle:

Prevent the secret from becoming an incident in the first place.

Instead of:

LEAK
 ↓
DISCOVER
 ↓
ALERT
 ↓
INVESTIGATE
 ↓
FIX

the intended workflow is:

DETECT
 ↓
BLOCK
 ↓
EXPLAIN
 ↓
FIX
 ↓
RESCAN
 ↓
ALLOW

This shifts secret security from post-exposure detection toward prevention during development.

⸻

📌 Current Project Status

                    PROJECT STATUS
Web Prototype              ✅
Security Dashboard         ✅
Finding UI                 ✅
Risk / Confidence UI       ✅
Verification UI            ✅
Blast Radius UI            ✅
History Concept             ✅
Remediation UI             ✅
Rescan Workflow             ✅
VS Code Extension           🚧
Git Integration             🚧
Commit Blocking             🚧
Push Blocking               🚧
Real Secret Scanner         🚧
Terminal Integration        🚧
Live Verification           🚧
Production Backend          🚧

⸻

🏆 Final Concept

Secret Leak Detector is not intended to be just another dashboard that tells a developer:

“You leaked a secret.”

The intended experience is:

Developer writes code
        ↓
Developer tries to commit
        ↓
Secret Leak Detector intercepts the workflow
        ↓
Secret detected
        ↓
Commit blocked
        ↓
Developer receives a clear terminal explanation
        ↓
Developer fixes the issue
        ↓
Extension rescans
        ↓
Problem resolved
        ↓
Commit allowed

In one sentence:

Secret Leak Detector is a VS Code-centered security layer that detects and blocks accidentally exposed secrets during the Git commit/push workflow, explains the problem directly to the developer, guides remediation, and allows the operation only after the issue is resolved.

⸻



Prototype live demo link 

https://secret-leak-detector-three.vercel.app/
🔐 DETECT → PROVE → TRACE → BLOCK → FIX → RESCAN → ALLOW

Stop secrets before they become security incidents.
