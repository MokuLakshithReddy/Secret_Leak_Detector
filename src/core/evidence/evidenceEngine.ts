import { RuleDefinition, EvidenceItem, EvidenceModel } from '../types';
import {
  calculateShannonEntropy,
  calculateNormalizedEntropy,
  detectCharacterSet,
} from '../entropy/entropy';
import { FileContext, LexicalContext } from '../context/contextAnalyzer';
import { evaluateFalsePositive } from '../classifier/falsePositiveClassifier';

export interface EvidenceCalculationResult {
  confidence: number;
  evidence: EvidenceModel;
  isSuppressed: boolean;
  suppressReason?: string;
}

export function buildEvidenceModel(
  rule: RuleDefinition,
  rawSecret: string,
  fileContext: FileContext,
  lexicalContext: LexicalContext,
  filePath: string
): EvidenceCalculationResult {
  const items: EvidenceItem[] = [];
  let confidence = rule.baseConfidence;

  // 1. Pattern Signal
  items.push({
    signal: 'KNOWN_PATTERN_MATCH',
    description: `Matched recognized credential signature for ${rule.provider} (${rule.name})`,
    confidenceImpact: 0,
    details: { ruleId: rule.id, provider: rule.provider },
  });

  // 2. Entropy Signal
  const shannonEntropy = calculateShannonEntropy(rawSecret);
  const normalizedEntropy = calculateNormalizedEntropy(rawSecret);
  const { setName } = detectCharacterSet(rawSecret);

  if (shannonEntropy >= 4.5) {
    confidence = Math.min(100, confidence + 5);
    items.push({
      signal: 'HIGH_ENTROPY',
      description: `Cryptographic entropy: ${shannonEntropy} bits/char (${setName} set), indicates non-human randomness`,
      confidenceImpact: +5,
      details: { shannonEntropy, normalizedEntropy, characterSet: setName },
    });
  } else if (shannonEntropy >= 3.4) {
    items.push({
      signal: 'MODERATE_ENTROPY',
      description: `Moderate entropy: ${shannonEntropy} bits/char (${setName} set)`,
      confidenceImpact: 0,
      details: { shannonEntropy, normalizedEntropy, characterSet: setName },
    });
  } else {
    // If entropy is low and the rule requires minEntropy
    if (rule.minEntropy && shannonEntropy < rule.minEntropy) {
      confidence = Math.max(10, confidence - 30);
      items.push({
        signal: 'LOW_ENTROPY',
        description: `Low entropy score: ${shannonEntropy} bits/char below minimum threshold of ${rule.minEntropy}`,
        confidenceImpact: -30,
        details: { shannonEntropy, minEntropy: rule.minEntropy },
      });
    }
  }

  // 3. Variable Identifier Signal
  if (lexicalContext.isSensitiveIdentifier) {
    confidence = Math.min(100, confidence + 10);
    items.push({
      signal: 'SENSITIVE_IDENTIFIER',
      description: `Assigned to sensitive identifier: '${lexicalContext.inferredVariable || 'credential'}'`,
      confidenceImpact: +10,
      details: { identifier: lexicalContext.inferredVariable },
    });
  } else if (lexicalContext.isBenignIdentifier) {
    confidence = Math.max(10, confidence - 25);
    items.push({
      signal: 'BENIGN_IDENTIFIER',
      description: `Identifier name indicates mock or sample value: '${lexicalContext.inferredVariable}'`,
      confidenceImpact: -25,
      details: { identifier: lexicalContext.inferredVariable },
    });
  }

  // 4. File Context Signal
  if (fileContext.isConfig || fileContext.isSensitiveName) {
    confidence = Math.min(100, confidence + 8);
    items.push({
      signal: 'PRODUCTION_CONFIG_FILE',
      description: `Located in configuration or secret storage file (${fileContext.fileExtension})`,
      confidenceImpact: +8,
      details: { isConfig: fileContext.isConfig, extension: fileContext.fileExtension },
    });
  }

  if (fileContext.isTest) {
    confidence = Math.max(20, confidence - 20);
    items.push({
      signal: 'TEST_FILE_PENALTY',
      description: 'Found inside test/mock directory structure',
      confidenceImpact: -20,
    });
  }

  if (fileContext.isDoc) {
    confidence = Math.max(20, confidence - 25);
    items.push({
      signal: 'DOCUMENTATION_PENALTY',
      description: 'Found inside documentation or markdown guide',
      confidenceImpact: -25,
    });
  }

  // 5. False Positive & Placeholder Check
  const fpCheck = evaluateFalsePositive(rawSecret, lexicalContext.inferredVariable, filePath);
  if (fpCheck.isFalsePositive) {
    return {
      confidence: 0,
      evidence: {
        items: [
          {
            signal: 'KNOWN_PLACEHOLDER_REJECTED',
            description: fpCheck.reason || 'Placeholder value rejected',
            confidenceImpact: -100,
          },
        ],
        shannonEntropy,
        normalizedEntropy,
        characterSet: setName,
        surroundingCode: {
          before: lexicalContext.surroundingBefore,
          targetLine: lexicalContext.matchedLine,
          after: lexicalContext.surroundingAfter,
          inferredVariable: lexicalContext.inferredVariable,
        },
        fileContext: {
          fileExtension: fileContext.fileExtension,
          isConfig: fileContext.isConfig,
          isTest: fileContext.isTest,
          isDoc: fileContext.isDoc,
          isSensitiveName: fileContext.isSensitiveName,
          isExampleOrSample: fileContext.isExampleOrSample,
        },
      },
      isSuppressed: true,
      suppressReason: fpCheck.reason,
    };
  }

  if (fpCheck.confidencePenalty > 0) {
    confidence = Math.max(10, confidence - fpCheck.confidencePenalty);
  }

  const finalConfidence = Math.max(0, Math.min(100, Math.round(confidence)));

  const evidenceModel: EvidenceModel = {
    items,
    shannonEntropy,
    normalizedEntropy,
    characterSet: setName,
    surroundingCode: {
      before: lexicalContext.surroundingBefore,
      targetLine: lexicalContext.matchedLine,
      after: lexicalContext.surroundingAfter,
      inferredVariable: lexicalContext.inferredVariable,
    },
    fileContext: {
      fileExtension: fileContext.fileExtension,
      isConfig: fileContext.isConfig,
      isTest: fileContext.isTest,
      isDoc: fileContext.isDoc,
      isSensitiveName: fileContext.isSensitiveName,
      isExampleOrSample: fileContext.isExampleOrSample,
    },
  };

  return {
    confidence: finalConfidence,
    evidence: evidenceModel,
    isSuppressed: false,
  };
}
