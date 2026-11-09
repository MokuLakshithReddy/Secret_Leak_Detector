#!/usr/bin/env node
'use strict';

const { execFileSync } = require('node:child_process');

const ALLOWED_FILES = new Set([
  'package.json',
  'README.md',
  'LICENSE',
  'SECURITY.md',
  'CHANGELOG.md',
  'dist/cli.js',
  'dist/ast-parser.js',
  'dist/uninstall.js',
]);
const REQUIRED_FILES = [
  'package.json',
  'README.md',
  'LICENSE',
  'dist/cli.js',
  'dist/ast-parser.js',
];

function main() {
  let output;
  try {
    output = execFileSync('npm', ['pack', '--dry-run', '--json'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'inherit'],
      maxBuffer: 16 * 1024 * 1024,
    });
  } catch (error) {
    const detail = error.stderr ? String(error.stderr) : error.message;
    throw new Error(`npm pack --dry-run failed: ${detail}`);
  }

  let report;
  try {
    report = JSON.parse(output);
  } catch (error) {
    throw new Error(`npm pack returned invalid JSON: ${error.message}`);
  }

  if (!Array.isArray(report) || !report[0] || !Array.isArray(report[0].files)) {
    throw new Error('npm pack returned an unexpected file manifest.');
  }

  const packaged = report[0].files.map((entry) => entry.path);
  const packagedSet = new Set(packaged);
  const missing = REQUIRED_FILES.filter((file) => !packagedSet.has(file));
  const unexpected = packaged.filter((file) => !ALLOWED_FILES.has(file));

  if (missing.length || unexpected.length) {
    if (missing.length) {
      console.error(`Missing required npm package files: ${missing.join(', ')}`);
    }
    if (unexpected.length) {
      console.error(`Unexpected files in npm package: ${unexpected.join(', ')}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log(`npm package contents verified (${packaged.length} files):`);
  for (const file of packaged.sort()) console.log(`  - ${file}`);
}

try {
  main();
} catch (error) {
  console.error(error.message || error);
  process.exitCode = 1;
}
