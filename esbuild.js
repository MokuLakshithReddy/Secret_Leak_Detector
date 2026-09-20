const esbuild = require('esbuild');

const isProduction = process.argv.includes('--production');
const isWatch = process.argv.includes('--watch');
const isTest = process.argv.includes('--test');
const isDemo = process.argv.includes('--demo');

let config;

if (isTest) {
  config = {
    entryPoints: ['test/suite.ts'],
    bundle: true,
    outfile: 'dist/test-suite.js',
    format: 'cjs',
    platform: 'node',
    target: 'node18',
    sourcemap: true,
  };
} else if (isDemo) {
  config = {
    entryPoints: ['scripts/demo-cli.ts'],
    bundle: true,
    outfile: 'dist/demo-cli.js',
    format: 'cjs',
    platform: 'node',
    target: 'node18',
    sourcemap: true,
  };
} else {
  config = {
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
}

async function main() {
  if (isWatch) {
    const ctx = await esbuild.context(config);
    await ctx.watch();
    console.log('Watching for changes...');
  } else {
    await esbuild.build(config);
    console.log(`Build completed: ${config.outfile}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
