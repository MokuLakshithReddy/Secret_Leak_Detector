# Independent review packet workflow

This directory provides a generator for an external, process-based blind review
of the 40-case held-out evaluation corpus.

## Status of Issue #46

> **POLICY NOTICE:** Issue #46 tracking third-party accuracy and security review
> **MUST REMAIN OPEN** until genuine external, un-blinded verification has been
> conducted, recorded, and signed off by an independent reviewer. No maintainer,
> automated test, or AI agent may close Issue #46.

## Generate a reviewer packet

From the repository root:

```bash
npm ci
npm run review:packet
```

The command creates two files in a private temporary directory outside the
repository:

- `blind-review-packet.json`: 40 shuffled cases with neutral IDs, file/line
  context, and fixture content only.
- `review-worksheet-<packet-id>.csv`: blank classification and rationale
  fields for the reviewer.

The generated packet excludes the maintainer's expected labels, detector rule
names, source case IDs, descriptions, and scanner outcomes. Each run uses a
fresh random order and packet ID. To choose a specific output path, use:

```bash
npm run review:packet -- --output /absolute/path/blind-review-packet.json
```

The worksheet is written alongside the packet. Keep both generated files out
of Git; the fixture strings are synthetic test values and some intentionally
match credential detectors.

## Reviewer eligibility and independence

Ask a reviewer who:
1. Is not the project maintainer or contributor.
2. Has not contributed to the detector rules, test suites, or held-out labels.
3. Can disclose relevant security-engineering or code-auditing experience and confirm absence of conflicts of interest.
4. Reviews the supplied blinded packet before inspecting the repository's labelled source or benchmark outputs.

## Classification rubric

For every blinded test case, the reviewer must assign exactly one classification:

| Classification | Definition & Criteria |
|---|---|
| `positive` | The candidate token or fixture represents an active, validly formed, or actionable credential/token that should block a commit in production. Includes valid provider formats (AWS, GitHub, Stripe, Slack, OpenAI, Anthropic, Google, Azure, JWT, Private Keys, etc.) across standard and obfuscated contexts. |
| `negative` | The candidate token or fixture represents safe code, public identifier, placeholder, documentation example, synthetic test mock (`dummy`, `example`, `test`, `mock`), high-entropy non-secret (UUID, git commit hash, sha256 checksum, base64 image chunk), or non-credential configuration. |
| `ambiguous` | The candidate exhibits high entropy or credential-like format but context cannot conclusively determine intent (e.g. unannotated binary blob, ambiguous base64 string, variable named `key` holding random non-credential data). Requires reviewer rationale. |

### Domain & boundary coverage requirements

Reviewers evaluate across 5 explicit security categories:
- **Provider-specific structural validity:** Checksums, length, prefixes (e.g., `AKIA...`, `ghp_...`, `sk-proj-...`, `xoxb-...`).
- **Obfuscation & concatenation:** String concatenation (`"AKIA" + "..."`), template literals, multiline private keys, hex escapes, base64 data URIs.
- **Lexical & semantic context:** Variable assignments (`api_key = ...` vs `const id = ...`), function calls (`setToken(...)`), comment suppression (`// sld-ignore`).
- **Boundary & false positive resistance:** High-entropy non-secrets (SHA-256 digests, GUIDs/UUIDs, package lock hashes, base64 image data).
- **Adversarial permutations:** Transposed characters, truncated tokens, non-printable characters, encoded payloads.

## Disagreement adjudication protocol

When reviewer classifications differ from the author's internal baseline labels:
1. **Initial Submission:** The reviewer submits their completed worksheet with all 40 classifications and rationales.
2. **Comparison & Discrepancy Log:** The maintainer runs automated discrepancy diff against `evaluation/datasets/heldOutCorpus.ts`.
3. **Formal Adjudication Conference:**
   - Any case where the reviewer marked `ambiguous` is reviewed jointly. If consensus cannot be reached, the case is marked as a contested edge case and excluded from perfect precision/recall calculations.
   - If the reviewer identifies a genuine false positive or false negative in the author's ground truth, the author updates `evaluation/datasets/heldOutCorpus.ts` and documents the correction in `CHANGELOG.md`.
4. **Statistical Bounds (Wilson Score Intervals):**
   - Point estimates (e.g. 100% precision on 20 cases) must be paired with two-sided 95% Wilson score confidence intervals ($z = 1.96$):
   $$\hat{p} \pm \frac{z \sqrt{\frac{\hat{p}(1-\hat{p})}{n} + \frac{z^2}{4n^2}}}{1 + \frac{z^2}{n}}$$
   - Point metrics must never be claimed as absolute production guarantees without the corresponding confidence intervals.

## Blinding limitation

The repository is public, and the author's original labels remain visible in
`evaluation/datasets/heldOutCorpus.ts`. The packet hides those labels from the
review worksheet but cannot technically prevent a reviewer from discovering
the source labels. This is therefore a process-based blind review, not a
controlled or access-isolated blinded study. Send the packet separately and
ask the reviewer not to inspect the labelled source or benchmark output before
submitting the initial worksheet.
