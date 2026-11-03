/**
 * @file Legacy compatibility shim for core scanner APIs.
 * Preserves backward compatibility with legacy consumers (e.g. scripts/demo-cli.ts and test/suite.ts).
 * Canonical implementation lives at src/core/scanner/scanner.
 */
export * from '../core/scanner/scanner';
