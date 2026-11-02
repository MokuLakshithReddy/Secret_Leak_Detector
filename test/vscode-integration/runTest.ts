import * as path from 'path';
import { runTests } from '@vscode/test-electron';

async function main() {
  try {
    // The folder containing the Extension Manifest package.json
    const extensionDevelopmentPath = path.resolve(__dirname, '../../');

    // The path to test runner script
    const extensionTestsPath = path.resolve(__dirname, '../../dist/test/vscode-integration/suite/index.js');

    console.log('Starting real VS Code Extension Host tests via @vscode/test-electron...');
    console.log(`Extension development path: ${extensionDevelopmentPath}`);
    console.log(`Extension test runner:     ${extensionTestsPath}`);

    // Download VS Code and execute real extension host integration tests
    await runTests({
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

