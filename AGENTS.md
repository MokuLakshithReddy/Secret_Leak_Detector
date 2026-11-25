# Secret Leak Detector

VS Code extension and CLI for detecting, tracing, blocking, and remediating credential leaks in Git repositories.

## Main deliverables

1. **VS Code extension** — editor diagnostics, findings tree, security dashboard, Git commit protection, and guarded remediation.
2. **CLI** — workspace and staged scans, SARIF export, Git history tracing, baselines, remediation, verification, and hook lifecycle management.

## Repository layout

- `src/extension.ts` — VS Code extension entry point.
- `src/core/` — scanner, detectors, entropy, context analysis, evidence, risk, baseline, history, SARIF, remediation, and verification.
- `src/cli/index.ts` — CLI entry point.
- `src/diagnostics/`, `src/sidebar/`, `src/webview/` — editor diagnostics and UI.
- `src/git/` — Git integration, staged-blob scanning, and pre-commit hook generation.
- `src/engine/` and `src/types.ts` — compatibility re-exports; keep new implementation in `src/core/`.
- `test/` — core, adversarial, Git-hook, manifest, and VS Code integration tests.
- `evaluation/` — reproducible benchmarks, generated/held-out corpora, reports, and external-review protocol.
- `scripts/` — packaging, SBOM, demo, and CI helper scripts.
- `.secretleak-baseline.json` — repository-owned finding baseline. Its private fingerprint key must never be committed.

## Development and validation

Run from the repository root with Node.js 22 and npm:

```bash
npm ci
npm run lint
npm run build
npm test
npm run test:changed-scan
npm run test:git-hook
npm run test:manifest
npm run test:vscode
npm run benchmark:gate
npm run benchmark:heldout
npm run verify:package
npm run verify:sbom
```

Test totals are emitted by the checked-out test runner. Do not copy fixed historical counts into documentation; the suite evolves as tests are added.

## Security rules for contributors

- Keep the scanner core independent of VS Code imports so the CLI can reuse it.
- Use `execFile` / `execFileSync` with argument arrays for child processes. Do not interpolate untrusted input into shell commands.
- Test credentials must be synthesized at runtime (for example, by joining string fragments), never committed as realistic literals.
- Never print or serialize `rawSecret`. Use redacted representations in CLI output, logs, SARIF, telemetry, and UI.
- Never commit `.sld/salt`, `SLD_SALT`, baseline signing material, or other private credentials.
- Dependabot and fork PRs do not receive the private baseline key. Their CI path scans only changed files and must fail closed on scanner errors.
- Do not claim independent accuracy validation until an eligible external reviewer has completed and signed the protocol in `evaluation/REVIEW_GUIDE.md`. Internal tests and benchmarks are not third-party validation.
- Generated runtime bundles under `dist/` are build outputs and must not be committed.
