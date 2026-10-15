import * as fs from 'fs';
import * as path from 'path';
import { RuleDefinition, RemediationPlan, SecretFinding } from '../types';
import { redactSecret } from '../redactor/redactor';

export function escapeEnvValue(val: string): string {
  return val
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\$/g, '\\$')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
}

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
  const escapedSecret = escapeEnvValue(rawSecret);

  const steps = [
    `1. Revoke / rotate credential immediately with provider: ${rule.provider}`,
    `2. Migrate secret value to local .env file (${envVarName})`,
    `3. Replace hardcoded literal in ${filePath} with ${replacementCode}`,
    `4. Verify .env is listed in .gitignore so it is never committed`,
    `5. If committed previously, purge from Git history using git-filter-repo or BFG`,
    `6. Rescan file and commit to verify exposure is eliminated`,
  ];

  const envFileSnippet = `${envVarName}="${escapedSecret}"`;
  const envExampleSnippet = `${envVarName}=your_${envVarName.toLowerCase()}_here`;

  const gitHistoryPurgeCommand =
    `# WARNING: Use BFG Repo Cleaner to purge secrets from history (safer than filter-repo --invert-paths):\n` +
    `#   java -jar bfg.jar --replace-text secrets.txt <repo-dir>\n` +
    `# Where secrets.txt lists the exact literal to redact (one per line).\n` +
    `# Then force-push: git push --force --all && git push --force --tags\n` +
    `# Alternatively with git-filter-repo (rewrites content, not paths):\n` +
    `#   git filter-repo --replace-text secrets.txt`;

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

/**
 * Resolves a unique environment variable name, avoiding collisions
 * or reusing existing key if the secret value matches.
 */
export function resolveUniqueEnvVarName(
  envContent: string,
  suggestedName: string,
  rawSecret: string
): { varName: string; isReused: boolean } {
  const lines = envContent.split(/\r?\n/);
  const existingVars = new Map<string, string>();

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx !== -1) {
      const key = trimmed.substring(0, eqIdx).trim();
      let val = trimmed.substring(eqIdx + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.substring(1, val.length - 1);
      }
      existingVars.set(key, val);
    }
  }

  // If suggested name exists with identical secret value, safely reuse it
  if (existingVars.has(suggestedName)) {
    const existingVal = existingVars.get(suggestedName);
    if (existingVal === escapeEnvValue(rawSecret) || existingVal === rawSecret) {
      return { varName: suggestedName, isReused: true };
    }
    // Conflict: variable exists with different value, create unique suffix
    let suffix = 2;
    while (existingVars.has(`${suggestedName}_${suffix}`)) {
      if (existingVars.get(`${suggestedName}_${suffix}`) === rawSecret) {
        return { varName: `${suggestedName}_${suffix}`, isReused: true };
      }
      suffix++;
    }
    return { varName: `${suggestedName}_${suffix}`, isReused: false };
  }

  return { varName: suggestedName, isReused: false };
}

/**
 * Safely updates .gitignore to ensure .env is strictly protected.
 */
export function ensureGitignoreProtectsEnv(workspaceRoot: string): void {
  const gitignorePath = path.join(workspaceRoot, '.gitignore');
  if (fs.existsSync(gitignorePath)) {
    const content = fs.readFileSync(gitignorePath, 'utf8');
    const lines = content.split(/\r?\n/);
    const hasExactEnv = lines.some((line) => /^\s*\.env(?:\s|$)/.test(line));
    if (!hasExactEnv) {
      const prefix = content.endsWith('\n') || content.length === 0 ? '' : '\n';
      fs.appendFileSync(gitignorePath, `${prefix}# Credentials\n.env\n.env.*.local\n`, 'utf8');
    }
  } else {
    fs.writeFileSync(gitignorePath, '# Credentials\n.env\n.env.*.local\n', 'utf8');
  }
}

/**
 * Applies atomic remediation with automatic rollback if any phase fails.
 */
export function applyControlledRemediation(
  finding: SecretFinding,
  workspaceRoot: string
): ApplyRemediationResult {
  const targetFile = finding.fullPath;
  let originalFileContent: string | null = null;
  let originalEnvContent: string | null = null;
  let originalGitignoreContent: string | null = null;
  let originalEnvExampleContent: string | null = null;
  // Track whether each file was newly created by this function
  let envWasNewlyCreated = false;
  let gitignoreWasNewlyCreated = false;
  let envExampleWasNewlyCreated = false;
  const envPath = path.join(workspaceRoot, '.env');
  const gitignorePath = path.join(workspaceRoot, '.gitignore');

  try {
    if (!fs.existsSync(targetFile)) {
      return {
        success: false,
        message: `Target file not found: ${targetFile}`,
        envPath: '',
        modifiedFile: targetFile,
      };
    }

    originalFileContent = fs.readFileSync(targetFile, 'utf8');
    if (!originalFileContent.includes(finding.rawSecret)) {
      return {
        success: false,
        message: 'Secret no longer found in target file (may have already been modified).',
        envPath: '',
        modifiedFile: targetFile,
      };
    }

    // 1. Read existing .env if present and determine unique variable name
    let envContent = '';
    if (fs.existsSync(envPath)) {
      originalEnvContent = fs.readFileSync(envPath, 'utf8');
      envContent = originalEnvContent;
    } else {
      envWasNewlyCreated = true;
    }

    // Snapshot .gitignore state before mutation
    if (fs.existsSync(gitignorePath)) {
      originalGitignoreContent = fs.readFileSync(gitignorePath, 'utf8');
    } else {
      gitignoreWasNewlyCreated = true;
    }

    const suggestedName = finding.remediation?.envVarName || 'API_KEY';
    const { varName, isReused } = resolveUniqueEnvVarName(envContent, suggestedName, finding.rawSecret);
    const replacementCode = `process.env.${varName}`;
    const escapedValue = escapeEnvValue(finding.rawSecret);
    const envLine = `${varName}="${escapedValue}"\n`;

    // 2. Ensure .gitignore protects .env BEFORE writing credentials to disk
    ensureGitignoreProtectsEnv(workspaceRoot);

    // 3. Write to .env
    if (!isReused) {
      const prefix = envContent.endsWith('\n') || envContent.length === 0 ? '' : '\n';
      fs.appendFileSync(envPath, `${prefix}${envLine}`, 'utf8');
    }

    // 4. Update .env.example
    const envExamplePath = path.join(workspaceRoot, '.env.example');
    const exampleLine = `${varName}=your_${varName.toLowerCase()}_here\n`;
    const envExampleExists = fs.existsSync(envExamplePath);
    if (!envExampleExists) {
      envExampleWasNewlyCreated = true;
    } else {
      originalEnvExampleContent = fs.readFileSync(envExamplePath, 'utf8');
    }
    if (!envExampleExists || !fs.readFileSync(envExamplePath, 'utf8').includes(varName)) {
      const exContent = envExampleExists ? fs.readFileSync(envExamplePath, 'utf8') : '';
      const exPrefix = exContent.endsWith('\n') || exContent.length === 0 ? '' : '\n';
      fs.appendFileSync(envExamplePath, `${exPrefix}${exampleLine}`, 'utf8');
    }

    // 5. Replace secret literal in source file
    const newContent = originalFileContent.replace(
      new RegExp(escapeRegExp(finding.rawSecret), 'g'),
      replacementCode
    );
    fs.writeFileSync(targetFile, newContent, 'utf8');

    return {
      success: true,
      message: `Successfully migrated ${finding.type} to .env (${varName}) and replaced in ${finding.file}.`,
      envPath,
      modifiedFile: targetFile,
    };
  } catch (err: any) {
    // Transactional Rollback: Restore all mutated files to their pre-call state.
    // Source file
    if (originalFileContent !== null && fs.existsSync(targetFile)) {
      try { fs.writeFileSync(targetFile, originalFileContent, 'utf8'); } catch {}
    }
    // .env: delete if newly created, restore original content if pre-existing
    if (envWasNewlyCreated && fs.existsSync(envPath)) {
      try { fs.unlinkSync(envPath); } catch {}
    } else if (originalEnvContent !== null && fs.existsSync(envPath)) {
      try { fs.writeFileSync(envPath, originalEnvContent, 'utf8'); } catch {}
    }
    // .gitignore: delete if newly created, restore original content if pre-existing
    if (gitignoreWasNewlyCreated && fs.existsSync(gitignorePath)) {
      try { fs.unlinkSync(gitignorePath); } catch {}
    } else if (originalGitignoreContent !== null && fs.existsSync(gitignorePath)) {
      try { fs.writeFileSync(gitignorePath, originalGitignoreContent, 'utf8'); } catch {}
    }
    // .env.example: delete if newly created, restore original content if pre-existing
    const envExamplePath = path.join(workspaceRoot, '.env.example');
    if (envExampleWasNewlyCreated && fs.existsSync(envExamplePath)) {
      try { fs.unlinkSync(envExamplePath); } catch {}
    } else if (originalEnvExampleContent !== null && fs.existsSync(envExamplePath)) {
      try { fs.writeFileSync(envExamplePath, originalEnvExampleContent, 'utf8'); } catch {}
    }

    return {
      success: false,
      message: `Remediation failed and rolled back: ${err.message}`,
      envPath: '',
      modifiedFile: finding.fullPath,
    };
  }
}

function escapeRegExp(string: string): string {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
