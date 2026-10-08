import { scanContent } from '../../src/core/scanner/scanner';

export interface PerformanceProfilingReport {
  fileCount: number;
  totalBytes: number;
  elapsedMs: number;
  throughputFilesPerSec: number;
  throughputMbPerSec: number;
  latencyPercentilesUs: {
    mean: number;
    p50: number;
    p90: number;
    p95: number;
    p99: number;
  };
  memoryUsageMb: {
    rss: number;
    heapUsed: number;
    heapTotal: number;
  };
}

export function runLargeRepoBenchmark(fileCount = 1000): PerformanceProfilingReport {
  // Generate representative synthetic codebase in memory
  const testFiles: Array<{ name: string; content: string }> = [];

  const TEMPLATES = [
    // Standard clean TypeScript component
    `import React from 'react';\nexport function Component({ title }: { title: string }) {\n  return <div>{title}</div>;\n}`,
    // Python service with standard env calls
    `import os\ndef get_db():\n    return os.getenv("DATABASE_URL", "sqlite:///dev.db")`,
    // JSON configuration
    `{\n  "version": "1.0.0",\n  "name": "app",\n  "private": true\n}`,
    // Markdown documentation
    `# Documentation\n\nTo configure, set \`API_KEY\` to your provided key.\nExample: \`export API_KEY="your_api_key_here"\``,
    // File with secret leak (synthesized at runtime to prevent push-protection triggers)
    `const aws = require('aws-sdk');\nconst key = "${['AKIA', 'IOSF', 'ODNN', '7ABC', 'DEFG'].join('')}";\nconst secret = "${['wJalr', 'XUtn', 'FEMI', 'K7MD', 'ENGb', 'PxRf', 'iCY7', '8129', '0ABC', 'D'].join('')}";`,
    // File with false positive UUID
    `const txId = "e7b1a290-2c3d-4e5f-8a1b-9c8d7e6f5a4b";\nconst dummy = "00000000000000000000000000000000";`,
  ];

  let totalBytes = 0;
  for (let i = 0; i < fileCount; i++) {
    const template = TEMPLATES[i % TEMPLATES.length];
    const content = `// Synthetic File #${i}\n${template}\n`;
    totalBytes += Buffer.byteLength(content, 'utf8');
    testFiles.push({ name: `src/synthetic/file_${i}.ts`, content });
  }

  const initialMem = process.memoryUsage();
  const latenciesUs: number[] = [];

  const startTime = process.hrtime.bigint();

  for (const file of testFiles) {
    const t0 = process.hrtime.bigint();
    scanContent(file.content, file.name);
    const t1 = process.hrtime.bigint();
    latenciesUs.push(Number(t1 - t0) / 1000); // microseconds
  }

  const endTime = process.hrtime.bigint();
  const elapsedMs = Number(endTime - startTime) / 1000000;

  latenciesUs.sort((a, b) => a - b);
  const p50 = latenciesUs[Math.floor(latenciesUs.length * 0.5)];
  const p90 = latenciesUs[Math.floor(latenciesUs.length * 0.9)];
  const p95 = latenciesUs[Math.floor(latenciesUs.length * 0.95)];
  const p99 = latenciesUs[Math.floor(latenciesUs.length * 0.99)];
  const mean = latenciesUs.reduce((a, b) => a + b, 0) / latenciesUs.length;

  const currentMem = process.memoryUsage();

  const throughputFilesPerSec = Math.round((fileCount / (elapsedMs / 1000)));
  const throughputMbPerSec = Math.round((totalBytes / (1024 * 1024) / (elapsedMs / 1000)) * 10) / 10;

  return {
    fileCount,
    totalBytes,
    elapsedMs: Math.round(elapsedMs),
    throughputFilesPerSec,
    throughputMbPerSec,
    latencyPercentilesUs: {
      mean: Math.round(mean),
      p50: Math.round(p50),
      p90: Math.round(p90),
      p95: Math.round(p95),
      p99: Math.round(p99),
    },
    memoryUsageMb: {
      rss: Math.round((currentMem.rss / 1024 / 1024) * 10) / 10,
      heapUsed: Math.round((currentMem.heapUsed / 1024 / 1024) * 10) / 10,
      heapTotal: Math.round((currentMem.heapTotal / 1024 / 1024) * 10) / 10,
    },
  };
}

if (require.main === module) {
  console.log('\n=================================================================================');
  console.log('⚡ LARGE-REPOSITORY SCAN PERFORMANCE PROFILING (1,000 Synthetic Files)');
  console.log('=================================================================================\n');

  const report = runLargeRepoBenchmark(1000);

  console.log(`Scanned:            ${report.fileCount} files (${(report.totalBytes / 1024).toFixed(1)} KB) in ${report.elapsedMs} ms`);
  console.log(`Throughput:         ${report.throughputFilesPerSec.toLocaleString()} files/sec (~${report.throughputMbPerSec} MB/s)`);
  console.log(`Latency p50:        ${report.latencyPercentilesUs.p50} µs`);
  console.log(`Latency p95:        ${report.latencyPercentilesUs.p95} µs`);
  console.log(`Latency p99:        ${report.latencyPercentilesUs.p99} µs`);
  console.log(`Memory Footprint:   RSS ${report.memoryUsageMb.rss} MB | Heap Used ${report.memoryUsageMb.heapUsed} MB\n`);
  console.log('=================================================================================\n');
}
