const esbuild = require('esbuild');

const isProduction = process.argv.includes('--production');
const isWatch = process.argv.includes('--watch');
const isTest = process.argv.includes('--test');
const isBenchmark = process.argv.includes('--benchmark');
const isCliOnly = process.argv.includes('--cli');
const isDemo = process.argv.includes('--demo');

async function buildAll() {
  if (isTest) {
    await esbuild.build({
      entryPoints: ['test/runAllTests.ts'],
      bundle: true,
      outfile: 'dist/test-suite.js',
      format: 'cjs',
      platform: 'node',
      target: 'node18',
      sourcemap: true,
    });
    console.log('Build completed: dist/test-suite.js');
    return;
  }

  if (isBenchmark) {
    await esbuild.build({
      entryPoints: ['evaluation/benchmarks/reproducibleBenchmark.ts'],
      bundle: true,
      outfile: 'dist/benchmark.js',
      format: 'cjs',
      platform: 'node',
      target: 'node18',
      sourcemap: true,
    });
    console.log('Build completed: dist/benchmark.js');
    return;
  }

  if (process.argv.includes('--multi-benchmark')) {
    await esbuild.build({
      entryPoints: ['evaluation/benchmarks/multiScannerRunner.ts'],
      bundle: true,
      outfile: 'dist/multi-benchmark.js',
      format: 'cjs',
      platform: 'node',
      target: 'node18',
      sourcemap: true,
    });
    console.log('Build completed: dist/multi-benchmark.js');
    return;
  }

  if (process.argv.includes('--regression-gate')) {
    await esbuild.build({
      entryPoints: ['evaluation/benchmarks/ciRegressionGate.ts'],
      bundle: true,
      outfile: 'dist/regression-gate.js',
      format: 'cjs',
      platform: 'node',
      target: 'node18',
      sourcemap: true,
    });
    console.log('Build completed: dist/regression-gate.js');
    return;
  }

  if (process.argv.includes('--profile')) {
    await esbuild.build({
      entryPoints: ['evaluation/benchmarks/largeRepoBenchmark.ts'],
      bundle: true,
      outfile: 'dist/profile.js',
      format: 'cjs',
      platform: 'node',
      target: 'node18',
      sourcemap: true,
    });
    console.log('Build completed: dist/profile.js');
    return;
  }

  if (isDemo) {
    await esbuild.build({
      entryPoints: ['scripts/demo-cli.ts'],
      bundle: true,
      outfile: 'dist/demo-cli.js',
      format: 'cjs',
      platform: 'node',
      target: 'node18',
      sourcemap: true,
    });
    console.log('Build completed: dist/demo-cli.js');
    return;
  }

  // Build CLI
  await esbuild.build({
    entryPoints: ['src/cli/index.ts'],
    bundle: true,
    outfile: 'dist/cli.js',
    format: 'cjs',
    platform: 'node',
    target: 'node18',
    sourcemap: !isProduction,
    minify: isProduction,
    logLevel: 'info',
  });
  console.log('Build completed: dist/cli.js');

  if (isCliOnly) return;

  // Build Extension
  const extConfig = {
    entryPoints: ['src/extension.ts'],
    bundle: true,
    outfile: 'dist/extension.js',
    external: ['vscode'],
    format: 'cjs',
    platform: 'node',
    target: 'node18',
    sourcemap: !isProduction,
    minify: isProduction,
    logLevel: 'info',
  };

  if (isWatch) {
    const ctx = await esbuild.context(extConfig);
    await ctx.watch();
    console.log('Watching for extension changes...');
  } else {
    await esbuild.build(extConfig);
    console.log('Build completed: dist/extension.js');
  }
}

buildAll().catch((err) => {
  console.error(err);
  process.exit(1);
});
