import * as fs from 'fs';
import * as path from 'path';
import { scanContent, buildScanResult } from '../src/engine/scanner';

async function runDemo() {
  console.log('\n============================================================');
  console.log('🛡️  SECRET LEAK DETECTOR: LIVE DEMO & LIFECYCLE SIMULATION');
  console.log('============================================================\n');

  const vulnerableFilePath = path.join(__dirname, '..', 'samples', 'sample-vulnerable-file.js');
  const code = fs.readFileSync(vulnerableFilePath, 'utf8');

  console.log('📂 Target File:', vulnerableFilePath);
  console.log('📄 File Content:\n' + code.trim());
  console.log('\n------------------------------------------------------------');
  console.log('STAGE 1: [DETECT] & [PROVE] - Running Secret Detection Engine...');
  console.log('------------------------------------------------------------');

  const startTime = Date.now();
  const findings = scanContent(code, 'samples/sample-vulnerable-file.js');
  const duration = Date.now() - startTime;

  console.log(`⚡ Scan completed in ${duration}ms! Found ${findings.length} leaked credential(s):\n`);

  findings.forEach((f, idx) => {
    console.log(`[Leak #${idx + 1}]`);
    console.log(`  • Type:        ${f.type} (${f.provider})`);
    console.log(`  • Location:    Line ${f.line}, Col ${f.column}`);
    console.log(`  • Risk Level:  ${f.risk}`);
    console.log(`  • Confidence:  ${f.confidence}%`);
    console.log(`  • Entropy:     ${f.entropy} bits/char`);
    console.log(`  • Redacted:    ${f.redactedSecret}`);
    console.log(`  • Remediation: ${f.remediation}\n`);
  });

  console.log('------------------------------------------------------------');
  console.log('STAGE 2: [BLOCK] - Intercepting Git Commit Attempt');
  console.log('------------------------------------------------------------');

  const result = buildScanResult(findings, 1, duration);
  if (result.blocked) {
    console.log(`
🚨❌ COMMIT BLOCKED: Critical secrets detected before commit!
------------------------------------------------------------
Why:
  Hardcoded secrets detected in source code before leaving your machine.
Total Leaks:     ${findings.length}
Critical Leaks:  ${findings.filter((f) => f.risk === 'CRITICAL').length}
High Leaks:      ${findings.filter((f) => f.risk === 'HIGH').length}

Remediation Action:
  1. Extract hardcoded values into .env
  2. Protect .env in .gitignore
  3. Replace code values with process.env.VARIABLE_NAME
------------------------------------------------------------
`);
  }

  console.log('------------------------------------------------------------');
  console.log('STAGE 3: [FIX] - Executing Automated Quick Fix (Move to .env)');
  console.log('------------------------------------------------------------');

  const envVars: string[] = [];
  let remediatedCode = code;

  for (const f of findings) {
    let varName = 'SECRET_KEY';
    if (f.type.includes('AWS Access Key')) varName = 'AWS_ACCESS_KEY_ID';
    else if (f.type.includes('GitHub')) varName = 'GITHUB_TOKEN';
    else if (f.type.includes('Stripe')) varName = 'STRIPE_SECRET_KEY';
    else if (f.type.includes('OpenAI')) varName = 'OPENAI_API_KEY';
    else if (f.type.includes('Database')) varName = 'DATABASE_URL';

    envVars.push(`${varName}="${f.rawSecret}"`);
    remediatedCode = remediatedCode.replace(`"${f.rawSecret}"`, `process.env.${varName}`);
  }

  console.log('📝 Generated .env file content:');
  console.log(envVars.join('\n'));

  console.log('\n🔒 Ensuring .gitignore includes .env:');
  console.log('.env\n.env.*.local');

  console.log('\n📄 Remediated Code:');
  console.log(remediatedCode.trim());

  console.log('\n------------------------------------------------------------');
  console.log('STAGE 4: [RESCAN] & [ALLOW] - Re-running Scanner on Fixed Code');
  console.log('------------------------------------------------------------');

  const rescanFindings = scanContent(remediatedCode, 'samples/sample-remediated-file.js');
  console.log(`Findings remaining: ${rescanFindings.length}`);

  if (rescanFindings.length === 0) {
    console.log(`
============================================================
🎉 COMMIT ALLOWED!
All credentials safely extracted to .env and git-ignored.
Your changes are now clean and safe to commit / push.
============================================================
`);
  } else {
    console.error('❌ Still found secrets after remediation!');
    process.exit(1);
  }
}

runDemo().catch(console.error);
