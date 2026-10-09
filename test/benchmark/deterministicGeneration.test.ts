/**
 * Deterministic Benchmark Generation Verification Test
 * Confirms that corpus generation is 100% reproducible and byte-for-byte deterministic
 * across independent runs using seeded PRNG.
 */

import * as fs from 'fs';
import * as path from 'path';
import { generateCorpus, calculateCorpusChecksum } from '../../evaluation/datasets/corpusGenerator';

let passed = 0;
let failed = 0;

function assert(cond: boolean, msg: string) {
  if (!cond) {
    console.error(`❌ FAILED: ${msg}`);
    failed++;
  } else {
    console.log(`✅ PASSED: ${msg}`);
    passed++;
  }
}

console.log('============================================================');
console.log('🎲 VERIFYING DETERMINISTIC BENCHMARK GENERATION');
console.log('============================================================\n');

const testDirA = path.join(process.cwd(), 'evaluation', 'temp_det_a');
const testDirB = path.join(process.cwd(), 'evaluation', 'temp_det_b');
const testDirC = path.join(process.cwd(), 'evaluation', 'temp_det_c');

try {
  // 1. Generate run A
  console.log('Generating Run A (Seed: 0x5eec73)...');
  const itemsA = generateCorpus(testDirA, 0x5eec73);
  const checksumA = calculateCorpusChecksum(testDirA, itemsA);
  console.log(`Run A Manifest Checksum: ${checksumA}`);

  // 2. Generate run B with identical seed
  console.log('Generating Run B (Seed: 0x5eec73)...');
  const itemsB = generateCorpus(testDirB, 0x5eec73);
  const checksumB = calculateCorpusChecksum(testDirB, itemsB);
  console.log(`Run B Manifest Checksum: ${checksumB}`);

  assert(itemsA.length === itemsB.length, `Corpus sizes match (${itemsA.length} files)`);
  assert(checksumA === checksumB, 'Corpus checksums are 100% byte-for-byte identical across runs');

  // 3. Generate run C with different seed
  console.log('Generating Run C (Seed: 0x998877)...');
  const itemsC = generateCorpus(testDirC, 0x998877);
  const checksumC = calculateCorpusChecksum(testDirC, itemsC);
  console.log(`Run C Manifest Checksum: ${checksumC}`);

  assert(checksumA !== checksumC, 'Altering seed produces a unique, distinct pseudo-random corpus');

} finally {
  // Cleanup temp directories
  try { fs.rmSync(testDirA, { recursive: true, force: true }); } catch {}
  try { fs.rmSync(testDirB, { recursive: true, force: true }); } catch {}
  try { fs.rmSync(testDirC, { recursive: true, force: true }); } catch {}
}

console.log('\n============================================================');
console.log(`🎉 DETERMINISM TEST SUMMARY: ${passed} PASSED, ${failed} FAILED`);
console.log('============================================================\n');

if (failed > 0) process.exit(1);
