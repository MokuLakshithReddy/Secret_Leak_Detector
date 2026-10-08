import {
  Risk,
  RiskAssessment,
  RiskFactor,
  BlastRadius,
  RuleDefinition,
  GitExposure,
} from '../types';
import { FileContext } from '../context/contextAnalyzer';

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
    if (gitExposure.isRemote) {
      gitScore = 20;
      gitDesc = 'Pushed to remote repository branch (external exposure risk)';
    } else if (gitExposure.isPresentInHistory) {
      gitScore = 16;
      gitDesc = `Committed to Git history across ${gitExposure.branches.length || 1} branch(es) (${gitExposure.exposureDurationDays} days exposure)`;
    } else if (gitExposure.isPresentInHead) {
      gitScore = 12;
      gitDesc = 'Committed in current HEAD commit';
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

export function computeBlastRadius(riskScore: number, gitExposure?: GitExposure): BlastRadius {
  const factors: string[] = [];
  let score = Math.round(riskScore * 0.5);

  const workingTreeExposed = gitExposure ? gitExposure.isPresentInHead : true;
  const gitHistoryExposed = gitExposure ? gitExposure.isPresentInHistory : false;
  const commitCount = gitExposure?.isPresentInHistory ? 1 : 0;
  const branches = gitExposure?.branches || ['main'];
  const branchCount = branches.length;
  const remoteExposed = gitExposure?.isRemote || false;
  const exposureDurationDays = gitExposure?.exposureDurationDays || 0;

  if (workingTreeExposed) {
    factors.push('Active working tree contains exposed secret');
    score += 15;
  }
  if (gitHistoryExposed) {
    factors.push(`Git history contains commit records across ${branchCount} branch(es)`);
    score += 20;
  }
  if (remoteExposed) {
    factors.push('Secret has been synchronized to remote tracking branches');
    score += 25;
  }
  if (exposureDurationDays > 7) {
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
    remoteExposed
      ? 'Remote & history exposure'
      : gitHistoryExposed
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
