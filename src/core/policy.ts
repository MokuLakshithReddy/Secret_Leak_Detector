import { Risk } from './types';

/**
 * ============================================================================
 *  SECRET LEAK DETECTOR — SINGLE COMMIT-BLOCKING POLICY
 * ============================================================================
 *
 * This module is the *one* place the project's blocking threshold is defined.
 * The CLI default, the generated pre-commit hook and the VS Code extension all
 * resolve their threshold from `DEFAULT_FAIL_ON` below, so the "policy" can no
 * longer drift between surfaces (previously the hook blocked at HIGH while the
 * CLI defaulted to CRITICAL).
 *
 * Documented policy
 * -----------------
 *   BLOCK  : HIGH and CRITICAL findings (live credentials with account-takeover
 *            blast radius — cloud keys, PATs, private keys, DB URLs with creds).
 *   REPORT : MEDIUM and LOW findings are reported in the UI / terminal but do
 *            not block a commit or fail a scan by default.
 *
 *   `--fail-on <tier>` overrides the threshold for a single invocation. The
 *   tiers are ordered LOW < MEDIUM < HIGH < CRITICAL; a scan fails when any
 *   finding's tier is at or above the configured `fail-on` tier.
 *
 *   "Fail closed": when the scanner cannot run at all (crash, unreadable staged
 *   blob, missing runtime), the gate BLOCKS rather than allowing the change.
 */

export const RISK_LEVELS: readonly Risk[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;

/** Numeric severity, used for threshold comparisons. Higher == more severe. */
export const RISK_SEVERITY: Record<Risk, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

/** The single, documented commit-blocking threshold for the whole project. */
export const DEFAULT_FAIL_ON: Risk = 'HIGH';

export interface BlockingPolicy {
  failOn: Risk;
  rationale: string;
}

export const BLOCKING_POLICY: BlockingPolicy = {
  failOn: DEFAULT_FAIL_ON,
  rationale:
    'HIGH/CRITICAL findings are live credentials with account-takeover blast radius and must block a commit; ' +
    'MEDIUM/LOW findings are reported but do not block by default.',
};

/** True when `value` is a recognised risk tier name. */
export function isRiskTier(value: unknown): value is Risk {
  return typeof value === 'string' && (RISK_LEVELS as readonly string[]).includes(value.toUpperCase());
}

/**
 * Resolve a `--fail-on` style value against the project policy.
 * Invalid/absent values fall back to the documented policy threshold.
 */
export function resolveFailOn(value: string | undefined | null, fallback: Risk = DEFAULT_FAIL_ON): Risk {
  if (isRiskTier(value)) return value.toUpperCase() as Risk;
  return fallback;
}

/** True when a finding's tier is at or above the threshold. */
export function meetsThreshold(risk: Risk, failOn: Risk = DEFAULT_FAIL_ON): boolean {
  return (RISK_SEVERITY[risk] || 0) >= (RISK_SEVERITY[failOn] || RISK_SEVERITY.CRITICAL);
}

/** True when any finding's tier is at or above the threshold (i.e. block). */
export function shouldBlock(
  findings: Array<{ risk: Risk }>,
  failOn: Risk = DEFAULT_FAIL_ON
): boolean {
  return findings.some((f) => meetsThreshold(f.risk, failOn));
}
