import { SecretFinding } from '../types';

/**
 * Formats findings into OASIS SARIF v2.1.0 format for GitHub Code Scanning / CI security alerts.
 */
export function formatAsSarif(findings: SecretFinding[]): object {
  const rulesMap = new Map<string, any>();

  for (const f of findings) {
    if (!rulesMap.has(f.type)) {
      rulesMap.set(f.type, {
        id: f.type.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
        name: f.type,
        shortDescription: {
          text: `Exposed ${f.provider} ${f.type}`,
        },
        fullDescription: {
          text: f.riskAssessment.summary,
        },
        defaultConfiguration: {
          level:
            f.risk === 'CRITICAL' || f.risk === 'HIGH'
              ? 'error'
              : f.risk === 'MEDIUM'
              ? 'warning'
              : 'note',
        },
        properties: {
          tags: ['security', 'credentials', f.provider.toLowerCase()],
          precision: f.confidence >= 90 ? 'very-high' : 'high',
        },
      });
    }
  }

  const results = findings.map((f) => {
    const ruleId = f.type.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    return {
      ruleId,
      level:
        f.risk === 'CRITICAL' || f.risk === 'HIGH'
          ? 'error'
          : f.risk === 'MEDIUM'
          ? 'warning'
          : 'note',
      message: {
        text: `Potential credential exposure: ${f.type} (${f.redactedSecret}) with confidence ${f.confidence}% and risk score ${f.riskAssessment.score}/100.`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: f.file.replace(/\\/g, '/'),
              uriBaseId: '%SRCROOT%',
            },
            region: {
              startLine: f.line,
              startColumn: f.column,
              endColumn: f.column + f.length,
            },
          },
        },
      ],
      properties: {
        confidence: f.confidence,
        riskScore: f.riskAssessment.score,
        blastRadius: f.riskAssessment.blastRadius.level,
        fingerprint: f.fingerprint,
        evidence: f.evidence.items.map((i) => i.description),
      },
    };
  });

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Secret Leak Detector',
            semanticVersion: '1.0.0',
            informationUri: 'https://github.com/MokuLakshithReddy/Secret_Leak_Detector',
            rules: Array.from(rulesMap.values()),
          },
        },
        results,
      },
    ],
  };
}
