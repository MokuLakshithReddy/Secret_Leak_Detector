import * as fs from 'fs';
import * as path from 'path';
import { getRealWorldCorpus } from '../evaluation/datasets/realWorldCorpus';
import { scanContent } from '../src/core/scanner/scanner';

const corpus = getRealWorldCorpus();
console.log('Investigating SLD findings across the 100 Real-World Corpus fixtures...\n');

const truePositives = corpus.filter(f => f.category === 'true_positive');
const falsePositives = corpus.filter(f => f.category === 'false_positive');

const missedTPs: any[] = [];
const detectedFPs: any[] = [];

for (const tp of truePositives) {
  const findings = scanContent(tp.content, tp.relativePath);
  if (findings.length === 0) {
    missedTPs.push({
      id: tp.id,
      path: tp.relativePath,
      provider: tp.provider,
      sourcePattern: tp.sourcePattern,
      description: tp.description,
      contentSnippet: tp.content.trim().split('\n').slice(0, 8).join('\n')
    });
  }
}

for (const fp of falsePositives) {
  const findings = scanContent(fp.content, fp.relativePath);
  if (findings.length > 0) {
    detectedFPs.push({
      id: fp.id,
      path: fp.relativePath,
      sourcePattern: fp.sourcePattern,
      findings: findings.map(f => ({ ruleId: f.ruleId, secret: f.secret, line: f.line }))
    });
  }
}

console.log(`========================================================================`);
console.log(`MISSED SECRETS (FALSE NEGATIVES): ${missedTPs.length} out of ${truePositives.length} True Positives`);
console.log(`========================================================================\n`);

missedTPs.forEach((m, idx) => {
  console.log(`[FN #${idx + 1}] ID: ${m.id}`);
  console.log(`  File:        ${m.path}`);
  console.log(`  Provider:    ${m.provider}`);
  console.log(`  Pattern:     ${m.sourcePattern}`);
  console.log(`  Description: ${m.description}`);
  console.log(`  Snippet:`);
  console.log(m.contentSnippet.split('\n').map((l: string) => '    | ' + l).join('\n'));
  console.log('');
});

console.log(`========================================================================`);
console.log(`FALSE POSITIVES DETECTED: ${detectedFPs.length} out of ${falsePositives.length} False Positives`);
console.log(`========================================================================\n`);

detectedFPs.forEach((f, idx) => {
  console.log(`[FP #${idx + 1}] ID: ${f.id}`);
  console.log(`  File:        ${f.path}`);
  console.log(`  Pattern:     ${f.sourcePattern}`);
  console.log(`  Triggered:   ${JSON.stringify(f.findings)}`);
  console.log('');
});
