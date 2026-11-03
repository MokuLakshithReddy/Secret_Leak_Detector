/**
 * @file Legacy compatibility shim for detection rules and patterns.
 * Adapts canonical CORE_RULES to the legacy SECRET_RULES interface with exampleFix and remediation.
 * Preserves backward compatibility with legacy consumers and test runners.
 * Canonical implementation lives at src/core/detectors/rules.
 */
import { CORE_RULES } from '../core/detectors/rules';

export const SECRET_RULES = CORE_RULES.map((rule) => ({
  ...rule,
  remediation: rule.remediationInstructions ? rule.remediationInstructions.join(' ') : '',
  exampleFix: (v: string) => `process.env.${rule.suggestedEnvName(v)}`,
}));

export * from '../core/detectors/rules';
