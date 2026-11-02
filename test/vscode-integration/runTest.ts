import * as os from 'os';
import * as path from 'path';
import { runTests } from '@vscode/test-electron';

async function main() {
  try {
    delete process.env.ELECTRON_RUN_AS_NODE;

    // The folder containing the Extension Manifest package.json
    const extensionDevelopmentPath = path.resolve(__dirname, '../../');

    // The path to test runner script
    const extensionTestsPath = path.resolve(__dirname, '../../dist/test/vscode-integration/suite/index.js');
    const cachePath = process.env.VSCODE_TEST_CACHE_PATH || path.join(os.tmpdir(), '.vscode-test-cache');

    console.log('Starting real VS Code Extension Host tests via @vscode/test-electron...');
    console.log(`Extension development path: ${extensionDevelopmentPath}`);
    console.log(`Extension test runner:     ${extensionTestsPath}`);
    console.log(`VS Code test cache:        ${cachePath}`);

    // Download VS Code and execute real extension host integration tests
    await runTests({
      cachePath,
      extensionDevelopmentPath,
      extensionTestsPath,
      launchArgs: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-extensions',
        '--disable-gpu',
        '--disable-workspace-trust',
      ],
    });

    console.log('✅ Real VS Code Extension Host tests completed successfully.');
  } catch (err: any) {
    console.error('❌ Failed to run VS Code extension host tests:', err?.message || err);
    process.exit(1);
  }
}

main();

