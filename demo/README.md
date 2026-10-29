# Demo: End-to-End Block-and-Remediate Fixture Repository

This demo proves that Secret Leak Detector detects realistic fake credentials
and clears findings after remediation — using only the open-source CLI, with no
proprietary infrastructure.

## What the Demo Proves

| Step | What happens | Evidence |
|------|-------------|----------|
| 1 | Fixture repo created with 5 files | temp directory on disk |
| 2 | `config/aws.env` contains a fake AWS key | detected by SLD as HIGH/CRITICAL |
| 3 | `db/connect.js` contains a fake database URL | detected by SLD |
| 4 | `src/api.ts` contains a high-entropy hex string | detected by SLD |
| 5 | `crypto/hash.txt` contains a git SHA + SRI hash | **not** flagged (true negative) |
| 6 | Credentials replaced with `process.env.*` references | post-remediation scan is CLEAN |

> **All credentials in the fixture files are synthesized / fake.**  
> The AWS key (`AKIAIOSFODNN7EXAMPLE`) is the official AWS documentation example key,
> universally recognized as non-secret. No real credentials appear anywhere in this repo.

## How to Run

### Linux / macOS / Git Bash

```bash
# 1. Build the CLI (one-time)
npm run build

# 2. Run the demo
bash demo/setup-fixture-repo.sh
```

### Windows (PowerShell)

```powershell
# 1. Build the CLI (one-time)
npm run build

# 2. Run the demo
.\demo\setup-fixture-repo.ps1
```

## What a Reviewer Should Observe

1. **Initial scan output** — the CLI reports findings in `config/aws.env`,
   `db/connect.js`, and `src/api.ts`. Each finding shows:
   - File path and line number
   - Redacted secret (masked with bullet characters — the raw value is never printed)
   - Risk tier (HIGH or CRITICAL)
   - Rule ID that triggered

2. **`crypto/hash.txt` is NOT flagged** — the git SHA and SRI hash are correctly
   identified as benign high-entropy strings (true negatives).

3. **Post-remediation scan is CLEAN** — after replacing literal credentials with
   `process.env.*` references, the CLI exits 0 with no blocking findings.

4. **Exit codes** — the initial scan exits non-zero (findings present); the
   post-remediation scan exits 0 (clean). Both are deterministic.

## Note on Git Hook Blocking

On a project with the SLD pre-commit hook installed, the `git commit` at step 4
would be **automatically rejected** before the changes leave the developer's
machine — without requiring `--no-verify`. This demo uses an isolated temp
repository without the hook installed, and instead runs the CLI directly to
demonstrate the same detection logic.

To see actual hook blocking, run:
```bash
npx secret-leak-detector hook install   # in a real project
git add config/aws.env
git commit -m "oops"                    # → blocked by pre-commit hook
```

See `test/integration/gitHookScenarios.test.ts` for the automated proof of
commit blocking.
