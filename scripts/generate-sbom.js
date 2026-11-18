#!/usr/bin/env node
'use strict';

/**
 * Generates an authoritative CycloneDX v1.5 Software Bill of Materials (SBOM)
 * for Secret Leak Detector release artifacts.
 *
 * Verifies that all bundled distribution files exist and calculates cryptographic
 * SHA-256 integrity hashes for each packaged component and build-time toolchain dependency.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const rootDir = path.resolve(__dirname, '..');
const packageJsonPath = path.join(rootDir, 'package.json');
const packageLockPath = path.join(rootDir, 'package-lock.json');

function computeFileSha256(filePath) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Cannot compute SHA-256: file not found at ${filePath}`);
  }
  const buffer = fs.readFileSync(filePath);
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function generateSbom(outputPath) {
  const pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
  const lock = fs.existsSync(packageLockPath)
    ? JSON.parse(fs.readFileSync(packageLockPath, 'utf8'))
    : null;

  const targetOut = outputPath || path.join(rootDir, 'sbom.cyclonedx.json');

  const runtimeArtifacts = [
    { name: 'dist/cli.js', description: 'Self-contained CLI executable bundle' },
    { name: 'dist/extension.js', description: 'VS Code Extension host entry point bundle' },
    { name: 'dist/ast-parser.js', description: 'Standalone compiler AST parser bundle' },
    { name: 'dist/uninstall.js', description: 'Extension uninstaller and hook cleanup utility' },
  ];

  const components = [];

  for (const artifact of runtimeArtifacts) {
    const absPath = path.join(rootDir, artifact.name);
    let hash = 'NOT_BUILT';
    let size = 0;
    if (fs.existsSync(absPath)) {
      hash = computeFileSha256(absPath);
      size = fs.statSync(absPath).size;
    }

    components.push({
      type: 'file',
      name: artifact.name,
      version: pkg.version,
      description: artifact.description,
      hashes: [
        {
          alg: 'SHA-256',
          content: hash,
        },
      ],
      properties: [
        { name: 'fileSize', value: String(size) },
        { name: 'runtimeDependencyCount', value: '0' },
      ],
    });
  }

  // Enumerate full dependency tree (direct and transitive) from package-lock
  if (lock && lock.packages) {
    const directDev = new Set(Object.keys(lock.packages['']?.devDependencies || {}));
    const directProd = new Set(Object.keys(lock.packages['']?.dependencies || {}));
    const seenPurls = new Set();

    for (const [pkgPath, depMeta] of Object.entries(lock.packages)) {
      if (!pkgPath || pkgPath === '' || !pkgPath.includes('node_modules/')) continue;
      const depName = pkgPath.substring(pkgPath.lastIndexOf('node_modules/') + 'node_modules/'.length);
      const version = depMeta.version || '0.0.0';
      const purl = `pkg:npm/${encodeURIComponent(depName).replace('%40', '@')}@${version}`;

      if (seenPurls.has(purl)) continue;
      seenPurls.add(purl);

      const isDirect = directDev.has(depName) || directProd.has(depName);
      const isDev = depMeta.dev !== false;

      components.push({
        type: 'library',
        name: depName,
        version: version,
        scope: isDev ? 'optional' : 'required',
        purl,
        description: isDirect
          ? `Direct build-time toolchain dependency (${depName})`
          : `Transitive toolchain dependency (${depName})`,
        licenses: depMeta.license ? [{ license: { id: depMeta.license } }] : undefined,
        hashes: depMeta.integrity
          ? [
              {
                alg: depMeta.integrity.startsWith('sha512-')
                  ? 'SHA-512'
                  : depMeta.integrity.startsWith('sha1-')
                  ? 'SHA-1'
                  : 'SHA-256',
                content: depMeta.integrity.replace(/^sha\d+-/, ''),
              },
            ]
          : undefined,
        externalReferences: depMeta.resolved
          ? [
              {
                type: 'distribution',
                url: depMeta.resolved,
              },
            ]
          : undefined,
      });
    }
  }

  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [
        {
          vendor: 'Secret Leak Detector Security Engineering',
          name: 'generate-sbom',
          version: pkg.version,
        },
      ],
      component: {
        type: 'application',
        name: pkg.name,
        version: pkg.version,
        description: pkg.description,
        licenses: [
          {
            license: {
              name: 'Proprietary - See LICENSE',
            },
          },
        ],
        purl: `pkg:npm/${encodeURIComponent(pkg.name)}@${pkg.version}`,
      },
    },
    components,
  };

  fs.writeFileSync(targetOut, JSON.stringify(bom, null, 2) + '\n', 'utf8');
  console.log(`✅ CycloneDX v1.5 SBOM generated successfully: ${targetOut}`);
  console.log(`   Components recorded: ${components.length} (${runtimeArtifacts.length} runtime bundles, ${components.length - runtimeArtifacts.length} toolchain dependencies)`);
  return bom;
}

function verifySbom(sbomPath) {
  const target = sbomPath || path.join(rootDir, 'sbom.cyclonedx.json');
  if (!fs.existsSync(target)) {
    throw new Error(`SBOM file not found at ${target}. Run 'npm run sbom' to generate.`);
  }
  const content = JSON.parse(fs.readFileSync(target, 'utf8'));
  if (content.bomFormat !== 'CycloneDX' || content.specVersion !== '1.5') {
    throw new Error(`Invalid SBOM format: expected CycloneDX 1.5, got ${content.bomFormat} ${content.specVersion}`);
  }
  if (!Array.isArray(content.components) || content.components.length === 0) {
    throw new Error('SBOM contains no component entries.');
  }

  for (const comp of content.components) {
    if (comp.type === 'file' && comp.name.startsWith('dist/')) {
      const absPath = path.join(rootDir, comp.name);
      if (!fs.existsSync(absPath)) {
        throw new Error(`SBOM references bundle '${comp.name}' which does not exist on disk.`);
      }
      const actualHash = computeFileSha256(absPath);
      const recordedHash = comp.hashes?.find((h) => h.alg === 'SHA-256')?.content;
      if (actualHash !== recordedHash) {
        throw new Error(`SBOM hash mismatch for '${comp.name}': recorded=${recordedHash}, actual=${actualHash}`);
      }
    }
  }
  console.log(`✅ SBOM verification passed: all runtime file hashes match disk artifacts.`);
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--verify')) {
    verifySbom(args[args.indexOf('--verify') + 1]);
    return;
  }
  const outIndex = args.indexOf('--output');
  const targetOut = outIndex !== -1 ? args[outIndex + 1] : undefined;
  generateSbom(targetOut);
}

try {
  main();
} catch (err) {
  console.error(`❌ SBOM error: ${err.message || err}`);
  process.exit(1);
}
