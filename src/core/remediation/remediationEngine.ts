import * as fs from 'fs';
import * as path from 'path';
import { RuleDefinition, RemediationPlan, SecretFinding } from '../types';
import { redactSecret } from '../redactor/redactor';

export function buildRemediationPlan(
  rule: RuleDefinition,
  rawSecret: string,
  filePath: string,
  line: number,
  inferredVarName?: string
): RemediationPlan {
  const envVarName = rule.suggestedEnvName(inferredVarName);
  const replacementCode = `process.env.${envVarName}`;
  const redacted = redactSecret(rawSecret);

  const steps = [
    `1. Revoke / rotate credential immediately with provider: ${rule.provider}`,
    `2. Migrate secret value to local .env file (${envVarName})`,
    `3. Replace hardcoded literal in ${filePath} with ${replacementCode}`,
    `4. Verify .env is listed in .gitignore so it is never committed`,
    `5. If committed previously, purge from Git history using git-filter-repo or BFG`,
    `6. Rescan file and commit to verify exposure is eliminated`,
  ];

  const envFileSnippet = `${envVarName}="${rawSecret}"`;
  const envExampleSnippet = `${envVarName}=your_${envVarName.toLowerCase()}_here`;

  const gitHistoryPurgeCommand = `git filter-repo --invert-paths --path "${filePath}"`;

  // Create unified diff preview
  const diffPreview = `--- a/${filePath}
+++ b/${filePath}
@@ -${line},1 +${line},1 @@
- ... "${redacted}" ...
+ ... ${replacementCode} ...`;

  return {
    steps,
    envVarName,
    replacementCode,
    envFileSnippet,
    envExampleSnippet,
    gitHistoryPurgeCommand,
    diffPreview,
  };
}

export interface ApplyRemediationResult {
  success: boolean;
  message: string;
  envPath: string;
  modifiedFile: string;
}

export function applyControlledRemediation(
  finding: SecretFinding,
  workspaceRoot: string
): ApplyRemediationResult {
  try {
    const targetFile = finding.fullPath;
    if (!fs.existsSync(targetFile)) {
      return {
        success: false,
        message: `Target file not found: ${targetFile}`,
        envPath: '',
        modifiedFile: targetFile,
      };
    }

    const fileContent = fs.readFileSync(targetFile, 'utf8');
    if (!fileContent.includes(finding.rawSecret)) {
      return {
        success: false,
        message: 'Secret no longer found in target file (may have already been modified).',
        envPath: '',
        modifiedFile: targetFile,
      };
    }

    // 1. Replace the secret in target file
    const newContent = fileContent.replace(
      new RegExp(escapeRegExp(finding.rawSecret), 'g'),
      finding.remediation.replacementCode
    );
    fs.writeFileSync(targetFile, newContent, 'utf8');

    // 2. Append to .env
    const envPath = path.join(workspaceRoot, '.env');
    const envLine = `\n# Secured by Secret Leak Detector\n${finding.remediation.envFileSnippet}\n`;
    fs.appendFileSync(envPath, envLine, 'utf8');

    // 3. Ensure .env is in .gitignore
    const gitignorePath = path.join(workspaceRoot, '.gitignore');
    if (fs.existsSync(gitignorePath)) {
      const gitignore = fs.readFileSync(gitignorePath, 'utf8');
      if (!gitignore.includes('.env')) {
        fs.appendFileSync(gitignorePath, '\n# Credentials\n.env\n.env.*.local\n', 'utf8');
      }
    } else {
      fs.writeFileSync(gitignorePath, '# Credentials\n.env\n.env.*.local\n', 'utf8');
    }

    // 4. Update or create .env.example
    const envExamplePath = path.join(workspaceRoot, '.env.example');
    const exampleLine = `${finding.remediation.envExampleSnippet}\n`;
    if (!fs.existsSync(envExamplePath) || !fs.readFileSync(envExamplePath, 'utf8').includes(finding.remediation.envVarName)) {
      fs.appendFileSync(envExamplePath, exampleLine, 'utf8');
    }

    return {
      success: true,
      message: `Successfully migrated ${finding.type} to .env (${finding.remediation.envVarName}) and replaced in ${finding.file}.`,
      envPath,
      modifiedFile: targetFile,
    };
  } catch (err: any) {
    return {
      success: false,
      message: `Remediation failed: ${err.message}`,
      envPath: '',
      modifiedFile: finding.fullPath,
    };
  }
}

function escapeRegExp(string: string): string {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
