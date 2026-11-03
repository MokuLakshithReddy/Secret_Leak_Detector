import {
  Risk,
  RiskAssessment,
  RiskFactor,
  BlastRadius,
  RuleDefinition,
  GitExposure,
} from '../types';
import { FileContext } from '../context/contextAnalyzer';

/**
 * Calculates the multi-factor risk assessment for a secret finding.
 *
 * Architectural Distinction — Risk Score vs. Blast Radius Score:
 * 1. Intrinsic Finding Severity (RiskAssessment.score: 0–100, Tier: LOW/MEDIUM/HIGH/CRITICAL):
 *    Measures the intrinsic exploit likelihood and severity based on four strictly calibrated,
 *    mathematically independent structural weights summing to 100:
 *      - CREDENTIAL_SEVERITY (0–40): Privilege level of the credential type (e.g. AWS root, Stripe private).
 *      - CONFIDENCE_LEVEL (0–25): Multi-signal verification certainty (entropy, pattern, checksum, AST).
 *      - STORAGE_ENVIRONMENT (0–15): Contextual sensitivity of the location (.env/config vs. src vs. test).
 *      - EXPOSURE_REACH (0–20): Physical reach of the artifact (working tree vs. head vs. history vs. remote).
 *    When Git history is incomplete or shallow, the reach factor records the conservative rating
 *    and unverified duration explicitly in its explanation without distorting the calibrated 4-factor sum.
 *
 * 2. Operational Containment Breadth (BlastRadius.score: 0–100, Level: CONTAINED/MODERATE/EXTENSIVE/SEVERE):
 *    Evaluates operational containment and incident response attack surface breadth. Unlike the intrinsic
 *    risk score, BlastRadius penalizes unverified history bounds (+10 points) because uncontained or
 *    unverifiable exposure history forces security teams to treat containment as compromised.
 */
export function calculateRiskAssessment(
  rule: RuleDefinition,
  confidence: number,
  fileContext: FileContext,
  gitExposure?: GitExposure
): RiskAssessment {
  const factors: RiskFactor[] = [];
  let score = 0;

  // Factor 1: Credential Severity Base (0 - 40 points)
  // High-impact credentials (Cloud root, Private keys, Stripe financial)
  const baseWeight = Math.min(40, Math.round((rule.baseRiskWeight / 100) * 40));
  score += baseWeight;
  factors.push({
    factor: 'CREDENTIAL_SEVERITY',
    weight: 40,
    scoreContribution: baseWeight,
    explanation: `${rule.provider} ${rule.name} has high inherent privilege capability`,
  });

  // Factor 2: Confidence Alignment (0 - 25 points)
  const confidenceScore = Math.round((confidence / 100) * 25);
  score += confidenceScore;
  factors.push({
    factor: 'CONFIDENCE_LEVEL',
    weight: 25,
    scoreContribution: confidenceScore,
    explanation: `Multi-signal verification confidence is ${confidence}%`,
  });

  // Factor 3: File & Storage Environment (0 - 15 points)
  let envScore = 5;
  let envDesc = 'Standard source code file';
  if (fileContext.isConfig || fileContext.isSensitiveName) {
    envScore = 15;
    envDesc = 'Located in sensitive deployment / environment configuration';
  } else if (fileContext.isTest) {
    envScore = 0;
    envDesc = 'Located in test / fixture codebase with reduced operational blast radius';
  } else if (fileContext.isDoc) {
    envScore = 0;
    envDesc = 'Located in documentation context';
  }
  score += envScore;
  factors.push({
    factor: 'STORAGE_ENVIRONMENT',
    weight: 15,
    scoreContribution: envScore,
    explanation: envDesc,
  });

  // Factor 4: Git Exposure & Blast Radius (0 - 20 points)
  let gitScore = 5;
  let gitDesc = 'Found in local uncommitted working tree';

  if (gitExposure) {
    if (gitExposure.isRemote === true) {
      gitScore = 20;
      gitDesc = 'Pushed to remote repository branch (external exposure risk)';
    } else if (gitExposure.isPresentInHistory === true) {
      gitScore = 16;
      const isUnverifiedDuration = gitExposure.isIntroductionUnverified === true ||
        gitExposure.isPartialHistory === true ||
        gitExposure.searchStatus === 'SEARCH_INCOMPLETE' ||
        gitExposure.searchStatus === 'PARTIAL_HISTORY';
      const durationText = isUnverifiedDuration
        ? `≥${gitExposure.exposureDurationDays} days unverified exposure (history search incomplete/truncated)`
        : `${gitExposure.exposureDurationDays} days exposure`;
      gitDesc = `Committed to Git history across ${gitExposure.branches.length || 1} branch(es) (${durationText})`;
    } else if (gitExposure.isPresentInHistory === 'UNKNOWN') {
      gitScore = 16;
      gitDesc = 'Git history exposure could not be fully verified (conservative risk rating applied)';
    } else if (gitExposure.isPresentInHead === true) {
      gitScore = 12;
      gitDesc = 'Committed in current HEAD commit';
    } else if (gitExposure.isPresentInHead === 'UNKNOWN') {
      gitScore = 12;
      gitDesc = 'Current HEAD commit exposure could not be fully verified (conservative risk rating applied)';
    }
  }
  score += gitScore;
  factors.push({
    factor: 'EXPOSURE_REACH',
    weight: 20,
    scoreContribution: gitScore,
    explanation: gitDesc,
  });

  const finalScore = Math.max(0, Math.min(100, Math.round(score)));

  let tier: Risk = 'LOW';
  if (finalScore >= 76) tier = 'CRITICAL';
  else if (finalScore >= 51) tier = 'HIGH';
  else if (finalScore >= 26) tier = 'MEDIUM';
  else tier = 'LOW';

  // Blast Radius evaluation
  const blastRadius = computeBlastRadius(finalScore, gitExposure);

  const summary = `${tier} Risk (${finalScore}/100) — ${rule.name}. ${blastRadius.summary}`;

  return {
    score: finalScore,
    tier,
    factors,
    blastRadius,
    summary,
  };
}

/**
 * Computes the operational Blast Radius (containment breadth and attack surface) of an exposed secret.
 *
 * Operational Scoring Architecture:
 * - Baseline: 50% of the intrinsic riskScore (providing initial coupling to credential severity).
 * - Working Tree Containment (+15): Active local uncommitted working tree exposure.
 * - History Containment (+20): Propagation into local Git commits across repository branches.
 * - Remote Sync Reach (+25): Exposure synchronized to remote tracking branches (`origin/*`).
 * - Exposure Duration / Uncertainty Penalty (+10):
 *     - If exposure exceeds 7 days without rotation, +10 points are added.
 *     - If history is partial/shallow/incomplete (`isPartialHistory`, `isIntroductionUnverified`,
 *       `searchStatus === 'SEARCH_INCOMPLETE'`), +10 points are applied immediately as a conservative
 *       operational uncertainty penalty. Because older commits are missing or truncated, incident
 *       responders cannot guarantee containment, elevating the operational blast radius score while
 *       keeping the 4-factor intrinsic risk score calibrated.
 */
export function computeBlastRadius(riskScore: number, gitExposure?: GitExposure): BlastRadius {
  const factors: string[] = [];
  let score = Math.round(riskScore * 0.5);

  const workingTreeExposed: boolean | 'UNKNOWN' = gitExposure
    ? (gitExposure.isSecretInWorkingTree === 'UNKNOWN' || gitExposure.isPresentInWorkingTree === 'UNKNOWN'
        ? 'UNKNOWN'
        : (gitExposure.isSecretInWorkingTree === true || gitExposure.isPresentInWorkingTree === true))
    : true;
  const gitHistoryExposed: boolean | 'UNKNOWN' = gitExposure
    ? (gitExposure.isPresentInHistory === 'UNKNOWN' ? 'UNKNOWN' : gitExposure.isPresentInHistory === true)
    : false;
  const commitCount = gitExposure?.commitCount ?? (gitHistoryExposed ? 1 : 0);
  const branches = gitExposure?.branches || ['main'];
  const branchCount = branches.length;
  const remoteExposed: boolean | 'UNKNOWN' = gitExposure
    ? (gitExposure.isRemote === 'UNKNOWN' ? 'UNKNOWN' : gitExposure.isRemote === true)
    : false;
  const exposureDurationDays = gitExposure?.exposureDurationDays || 0;

  if (workingTreeExposed === 'UNKNOWN') {
    factors.push('Working tree status unverified (conservative exposure assumed)');
    score += 15;
  } else if (workingTreeExposed) {
    factors.push('Active working tree contains exposed secret');
    score += 15;
  }
  if (gitHistoryExposed === 'UNKNOWN') {
    factors.push('Git history status unverified (conservative exposure assumed)');
    score += 20;
  } else if (gitHistoryExposed) {
    factors.push(`Git history contains commit records across ${branchCount} branch(es)`);
    score += 20;
  }
  if (remoteExposed === 'UNKNOWN') {
    factors.push('Remote tracking branch status unverified (conservative exposure assumed)');
    score += 20;
  } else if (remoteExposed) {
    factors.push('Secret has been synchronized to remote tracking branches');
    score += 25;
  }
  const isUnverifiedDuration = gitExposure
    ? (gitExposure.isIntroductionUnverified === true ||
       gitExposure.isPartialHistory === true ||
       gitExposure.searchStatus === 'SEARCH_INCOMPLETE' ||
       gitExposure.searchStatus === 'PARTIAL_HISTORY')
    : false;

  if (isUnverifiedDuration) {
    factors.push(`Exposure duration unverified due to incomplete history (minimum confirmed ${exposureDurationDays} day(s); conservative exposure risk applied)`);
    score += 10;
  } else if (exposureDurationDays > 7) {
    factors.push(`Exposure duration exceeds ${exposureDurationDays} days without rotation`);
    score += 10;
  }

  score = Math.max(0, Math.min(100, score));

  let level: BlastRadius['level'] = 'CONTAINED';
  if (score >= 75) level = 'SEVERE';
  else if (score >= 50) level = 'EXTENSIVE';
  else if (score >= 25) level = 'MODERATE';
  else level = 'CONTAINED';

  const summary = `Blast Radius: ${level} (${score}/100) — ${
    remoteExposed === true
      ? 'Remote & history exposure'
      : remoteExposed === 'UNKNOWN'
      ? 'Unverified remote tracking risk'
      : gitHistoryExposed === true || gitHistoryExposed === 'UNKNOWN'
      ? 'Historical commit exposure'
      : 'Contained to local working tree'
  }`;

  return {
    level,
    score,
    workingTreeExposed,
    gitHistoryExposed,
    commitCount,
    branchCount,
    branches,
    remoteExposed,
    exposureDurationDays,
    summary,
    factors,
  };
}
