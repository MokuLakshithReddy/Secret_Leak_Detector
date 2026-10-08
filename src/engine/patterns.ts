import { CORE_RULES } from '../core/detectors/rules';

export const SECRET_RULES = CORE_RULES.map((rule) => ({
  ...rule,
  remediation: rule.remediationInstructions ? rule.remediationInstructions.join(' ') : '',
  exampleFix: (v: string) => `process.env.${rule.suggestedEnvName(v)}`,
}));

export * from '../core/detectors/rules';
