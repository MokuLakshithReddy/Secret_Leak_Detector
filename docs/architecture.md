# 🏛️ Architecture: Secret Leak Detector

Secret Leak Detector transforms credential scanning into an evidence-based security engineering pipeline:

```text
                  SECRET LEAK DETECTOR PIPELINE
                                │
          ┌─────────────────────┴─────────────────────┐
          │                                           │
       DETECT                                       PROVE
          │                                           │
   Pattern Engine                              Evidence Model
   Entropy Engine                              Multi-Signal Score
   Context Classifier                          False-Positive Gate
          │                                           │
          └─────────────────────┬─────────────────────┘
                                │
                              RISK
                                │
                    Dynamic 0-100 Score
                    Blast Radius Engine
                                │
          ┌─────────────────────┴─────────────────────┐
          │                                           │
        TRACE                                        FIX
          │                                           │
   Git Commit History                          Controlled Patch Preview
   Author & Duration                           Approval Gate
   Branch Reachability                         .env & .gitignore Auto-Sync
          │                                           │
          └─────────────────────┬─────────────────────┘
                                │
                             RESCAN
                                │
                    Working-Tree Verification
                    History Purge Verification
                    Delta Reporting (Before vs After)
```

---

## 1. Pipeline Stages

### Stage 1: DETECT (Multi-Signal Candidate Generation)
Candidate strings undergo sequential evaluations rather than binary regex checks:
1. **Provider Signature Match:** 12+ cloud and identity provider patterns (AWS, GitHub, Google, OpenAI, Anthropic, Stripe, Slack, Azure, DB URIs, PEM Private Keys, JWT).
2. **Shannon Entropy Filter:** Evaluates information entropy ($H = -\sum p_i \log_2 p_i$) and normalizes against the detected character set (Base64, Hex, Alphanumeric).
3. **Lexical Context Analysis:** Evaluates variable assignment names, identifier semantics, and syntax positioning.
4. **Adversarial De-Concatenation:** Detects and reassembles split strings and concatenated token fragments.

### Stage 2: PROVE (Explainable Evidence Model)
Rather than asserting "Secret Detected", every finding produces an explainable **Evidence Model**:
- Specific pattern matched with provider attribution
- Calculated Shannon entropy with character distribution
- Contextual signals (sensitive identifier name, production configuration file)
- Disproven false-positive factors (known documentation example, placeholder check)
- Resulting in a composite **Confidence Score (0 - 100%)**.

### Stage 3: RISK (Multi-Factor Risk Scoring & Blast Radius)
Static mappings (`AWS = CRITICAL`) are replaced with a dual-engine dynamic evaluation distinguishing intrinsic finding severity from operational containment:

$$\text{Risk Score} = w_{\text{type}} \cdot S_{\text{type}} + w_{\text{conf}} \cdot C + w_{\text{env}} \cdot E_{\text{env}} + w_{\text{git}} \cdot G_{\text{git}}$$

- **Intrinsic Risk Score (0 - 100):**
  - Evaluates inherent exploit capability based on four calibrated structural weights:
    - `CREDENTIAL_SEVERITY` ($w=40$): Privilege capability of the credential type.
    - `CONFIDENCE_LEVEL` ($w=25$): Multi-signal verification certainty.
    - `STORAGE_ENVIRONMENT` ($w=15$): Sensitivity of file location (.env/config vs. code vs. test).
    - `EXPOSURE_REACH` ($w=20$): Physical containment (working tree vs. HEAD vs. history vs. remote).
  - **Score Tiers:** `0 - 25`: LOW | `26 - 50`: MEDIUM | `51 - 75`: HIGH | `76 - 100`: CRITICAL.
  - When history is incomplete, `EXPOSURE_REACH` notes unverified duration in its factor explanation while strictly preserving the calibrated 4-factor sum.

- **Operational Blast Radius Score (0 - 100):**
  - Evaluates operational containment, incident response blast radius, and attack surface breadth.
  - Derives from a baseline of $0.5 \times \text{Risk Score}$ and stacks operational containment penalties:
    - Active working-tree presence: $+15$
    - Local Git commit history presence: $+20$
    - Remote tracking branch synchronization (`origin/*`): $+25$
    - Unrotated exposure (>7 days) OR incomplete/unverified history bounds (`isPartialHistory`, `isIntroductionUnverified`, `searchStatus === 'SEARCH_INCOMPLETE'`): $+10$
  - Operational uncertainty (+10) is deliberately applied here: when historical commit bounds cannot be fully verified (e.g. shallow clone or search truncated), security responders must treat containment as compromised.
  - **Containment Levels:** `0 - 24`: CONTAINED | `25 - 49`: MODERATE | `50 - 74`: EXTENSIVE | `75 - 100`: SEVERE.

### Stage 4: TRACE (Git History & Provenance Analysis)
Integrates Git DAG analysis to trace credential lifecycle:
- When was the secret introduced? (Commit SHA, author name, timestamp)
- Is the secret present in HEAD?
- If removed from HEAD, is it still present in historical commits?
- Which branches contain the commit?
- Has the commit been pushed to remote tracking branches?

### Stage 5: FIX (Controlled Remediation)
- Never prints or transmits plaintext secrets (automated masking: `AKIA••••••••••••7F2`).
- Previews unified diffs before modifying source code.
- Migrates raw secrets into local `.env` files.
- Generates template `.env.example` placeholders with blank values.
- Adds `.env` to `.gitignore` to prevent recursive leaks.
- Emits Git history purge commands (`git-filter-repo` / BFG) when secrets exist in history.

### Stage 6: RESCAN & VERIFY (Audit Verification)
- Rescans target files to ensure hardcoded secrets are completely eliminated.
- Confirms syntax validity and environment variable substitutions.
- Alerts developers if historical commits still contain the purged credential.
- Produces a Before vs After verification delta report.

---

## 2. Directory Layout

```text
Secret_Leak_Detector/
├── src/
│   ├── core/
│   │   ├── types.ts              # System types, Evidence, Risk, and Blast Radius schemas
│   │   ├── scanner/              # Orchestrated scanner pipeline
│   │   ├── detectors/            # Provider rule definitions
│   │   ├── entropy/              # Shannon and normalized entropy engine
│   │   ├── context/              # File and lexical AST analyzer
│   │   ├── classifier/           # False positive and placeholder suppression
│   │   ├── evidence/             # Evidence model and confidence calculator
│   │   ├── risk/                 # Dynamic risk scoring and blast radius
│   │   ├── history/              # Git history scanner and trace engine
│   │   ├── remediation/          # Controlled patch preview and env migration
│   │   ├── verification/         # Rescan verification and delta comparison
│   │   ├── baseline/             # CI baseline management (.secretleak-baseline.json)
│   │   ├── sarif/                # OASIS SARIF v2.1.0 generator for CI/CD
│   │   └── redactor/             # Masking and cryptographic SHA-256 fingerprinting
│   ├── cli/                      # Standalone CLI entrypoint
│   ├── diagnostics/              # VS Code diagnostics and QuickFix providers
│   ├── sidebar/                  # VS Code Activity Bar Tree views
│   ├── webview/                  # Interactive security dashboard panel
│   └── extension.ts              # VS Code extension lifecycle
├── evaluation/
│   ├── datasets/                 # True positive, false positive, and adversarial fixtures
│   └── benchmarks/               # Comparative evaluation harness
├── test/
│   └── runAllTests.ts            # Comprehensive unit, integration, and regression tests
├── docs/
│   ├── threat-model.md           # Security threat model and mitigations
│   ├── architecture.md           # Architecture design specification
│   └── benchmarks.md             # Benchmark methodology and results
└── README.md                     # Technical README
```
