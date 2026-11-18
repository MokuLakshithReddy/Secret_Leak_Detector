#!/usr/bin/env node
'use strict';

/**
 * Creates a process-based blind review packet from the maintainer-labelled
 * held-out corpus. Expected labels, detector rules, descriptions, source IDs,
 * and scanner outcomes are intentionally not copied into the packet.
 *
 * The generated fixture contents are synthetic test data. Keep the output
 * outside the repository and send it directly to the independent reviewer.
 */
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const repositoryRoot = path.resolve(__dirname, '..', '..');
const tsNode = require('ts-node');

// The corpus file lives outside tsconfig's src/ rootDir. Override rootDir for
// this one transpile-only load; the generator does not execute the scanner.
tsNode.register({
  project: path.join(repositoryRoot, 'tsconfig.json'),
  transpileOnly: true,
  compilerOptions: { rootDir: repositoryRoot },
});

const corpusPath = path.join(repositoryRoot, 'evaluation', 'datasets', 'heldOutCorpus.ts');
const corpusModule = require(corpusPath);
const corpus = corpusModule.HELD_OUT_CORPUS;

function fail(message) {
  console.error(`Independent review packet generation failed: ${message}`);
  process.exit(1);
}

function csvCell(value) {
  return '"' + String(value).replace(/"/g, '""') + '"';
}

function parseOutputArgument(argv) {
  const index = argv.indexOf('--output');
  if (index === -1) return null;
  if (!argv[index + 1] || argv[index + 1].startsWith('--')) {
    fail('Provide a path after --output.');
  }
  return path.resolve(process.cwd(), argv[index + 1]);
}

if (!Array.isArray(corpus) || corpus.length !== 40) {
  fail(`Expected exactly 40 held-out cases; received ${Array.isArray(corpus) ? corpus.length : 'no corpus'}.`);
}

const sourceIds = new Set();
for (const entry of corpus) {
  if (!entry || typeof entry.id !== 'string' || sourceIds.has(entry.id)) {
    fail('Every source case must have a unique string ID.');
  }
  sourceIds.add(entry.id);
  if (typeof entry.file !== 'string' || !Number.isInteger(entry.line) ||
      typeof entry.content !== 'string' || entry.content.length === 0) {
    fail(`Case ${entry.id} is missing file/line/content context.`);
  }
}

// Randomize the order for every packet. Neutral IDs prevent the source ID's
// TP/TN prefix from leaking the maintainer's expected classification.
const shuffled = corpus
  .map((entry) => ({
    sortKey: crypto.randomBytes(16).toString('hex'),
    value: { file: entry.file, line: entry.line, content: entry.content },
  }))
  .sort((a, b) => a.sortKey.localeCompare(b.sortKey))
  .map((entry) => entry.value);

const packetId = crypto.randomUUID();
const cases = shuffled.map((entry, index) => ({
  caseId: `IR-${String(index + 1).padStart(3, '0')}`,
  file: entry.file,
  line: entry.line,
  content: entry.content,
}));

// Assert that no maintainer-only fields have crossed the export boundary.
const allowedKeys = new Set(['caseId', 'file', 'line', 'content']);
for (const entry of cases) {
  if (Object.keys(entry).some((key) => !allowedKeys.has(key)) ||
      Object.keys(entry).length !== allowedKeys.size) {
    fail('A reviewer packet entry contains an unexpected field.');
  }
}

const packet = {
  schemaVersion: '1.0',
  packetId,
  generatedAt: new Date().toISOString(),
  caseCount: cases.length,
  instructions: 'Classify each case as positive, negative, or ambiguous and record a rationale. Do not infer labels from case order.',
  cases,
};

const requestedOutput = parseOutputArgument(process.argv.slice(2));
const outputDirectory = requestedOutput
  ? path.dirname(requestedOutput)
  : path.join(os.tmpdir(), 'sld-independent-review', packetId);
const packetPath = requestedOutput || path.join(outputDirectory, 'blind-review-packet.json');
const worksheetPath = path.join(outputDirectory, `review-worksheet-${packetId}.csv`);

try {
  fs.mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });
  fs.writeFileSync(packetPath, JSON.stringify(packet, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });

  const worksheet = [
    ['packetId', 'caseId', 'classification', 'rationale'].map(csvCell).join(','),
    ...cases.map((entry) => [packetId, entry.caseId, '', ''].map(csvCell).join(',')),
  ].join('\n') + '\n';
  fs.writeFileSync(worksheetPath, worksheet, { encoding: 'utf8', mode: 0o600 });
} catch (error) {
  fail(error && error.message ? error.message : String(error));
}

console.log('Blind review packet generated.');
console.log(`Packet ID: ${packetId}`);
console.log(`Cases: ${cases.length}`);
console.log(`Packet: ${packetPath}`);
console.log(`Worksheet: ${worksheetPath}`);
console.log('The packet contains synthetic fixture values. Send both files directly to the reviewer; do not commit them.');
