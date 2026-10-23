# Secret Leak Detector

VS Code extension and CLI tool for detecting, tracing, and remediating credential leaks in Git repositories.

## Deliverables

1. **VS Code Extension** — real-time in-editor secret scanning, diagnostics, sidebar tree, Git commit protection, and one-click remediation.
2. **CLI** — terminal-based scanning, SARIF export, history tracing, and baseline management.

## Project Structure

```
src/
  extension.ts          VS Code extension entry point
  core/                 Scanner engine, detectors, entropy, risk, baseline, SARIF, remediation, verification
  cli/                  CLI entry point (src/cli/index.ts)
  diagnostics/          VS Code DiagnosticsCollection integration
  git/                  GitService (staged-blob scan), pre-commit hook builder
  sidebar/              Activity bar tree view provider
  webview/              In-editor Security Dashboard (WebviewPanel, nonce-based CSP)
  engine/               Re-export shims for core modules
  types.ts              Re-export of core/types
test/                   Comprehensive security engineering test suite (231 tests)
evaluation/             Multi-scanner benchmarks and real-world corpus
  benchmarks/           Reproducible benchmark runners
  datasets/             Corpus generators and ground-truth labels
scripts/                Development and diagnostic helper scripts
docs/                   Threat model, benchmarks, and architecture documentation
samples/                Example files for manual testing
action.yml              GitHub Action composite action (pass inputs via env vars)
esbuild.js              Build script — produces dist/cli.js and dist/extension.js
package.json            Extension manifest, CLI bin, scripts, and devDependencies
tsconfig.json           TypeScript compiler settings (strict, node target)
.vscodeignore           Controls what is packaged in the .vsix
.secretleak-baseline.json  Baseline of known findings in the repository itself
```

## Build

```bash
npm run build       # production build of cli + extension
npm run watch       # watch mode for extension development
npm test            # build + run all 231 unit/integration tests
npm run package     # produce secret-leak-detector-x.y.z.vsix
```

## Technology

- Language: TypeScript 5, compiled with esbuild (not tsc) for extension and CLI bundles
- Extension host: VS Code API ^1.85.0 (CommonJS, external: vscode)
- CLI: Node.js 18+, platform: node, no external runtime dependencies
- Dev: `@vscode/vsce` for packaging, TypeScript for type checking

## Coding Conventions

- All source lives under `src/` or `test/` or `evaluation/`.
- The scanner engine is in `src/core/` — keep it free of VS Code imports so the CLI can use it directly.
- Use `execFileSync`/`execFile` (argument arrays) for all child process invocations. Never interpolate user-controlled data into shell strings.
- Test credentials in test files must be synthesised at runtime using the `synth(parts)` helper (array join), never written as plain literals, so the repository's own scanner does not flag them.
