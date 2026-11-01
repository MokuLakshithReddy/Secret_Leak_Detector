# Contributing to Secret Leak Detector

Thank you for your interest in contributing to **Secret Leak Detector**! We welcome contributions from the community to improve credential detection accuracy, performance, and developer experience.

## Getting Started

### Prerequisites

- **Node.js**: Version 18.x or 20.x or higher
- **npm**: Version 9.x or higher
- **Git**: Version 2.25+

### Installation & Build

```bash
git clone https://github.com/MokuLakshithReddy/Secret_Leak_Detector.git
cd Secret_Leak_Detector
npm ci
npm run build
```

## Running Tests & Verification

Before submitting a pull request, ensure all tests, lints, and benchmark gates pass cleanly:

```bash
# 1. Type checking and linting
npm run lint

# 2. Comprehensive security engineering test suite
npm test

# 3. Git pre-commit hook integration scenarios
npm run test:git-hook

# 4. CI benchmark regression gate
npm run benchmark:gate

# 5. Package extension (.vsix)
npm run package
```

## Security & Ethics Guidelines

When adding tests or benchmarks:
- **NEVER use live, production, or real credentials.** Always use synthesized, fake test vectors (`synth(['fake', 'token'])` or standard dummy formats).
- Maintain fail-closed security properties for all gate decisions.
- All detection rules must include explainable evidence and appropriate Shannon entropy bounds.

## Pull Request Process

1. Fork the repository and create your branch from `main`.
2. Ensure your changes have corresponding test coverage in `test/runAllTests.ts` or integration tests.
3. Keep pull requests focused on a single feature or bugfix.
4. Update `CHANGELOG.md` with a summary of your changes.
