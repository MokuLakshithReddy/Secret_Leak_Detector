import * as fs from 'fs';
import * as cp from 'child_process';
import * as path from 'path';
import * as os from 'os';
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

/**
 * Returns language-appropriate environment variable accessor syntax.
 */
export function getLanguageReplacement(filePath: string, varName: string): string {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case '.py':
      return `os.environ.get("${varName}")`;
    case '.go':
      return `os.Getenv("${varName}")`;
    case '.rb':
      return `ENV['${varName}']`;
    case '.php':
      return `getenv('${varName}')`;
    case '.java':
    case '.kt':
      return `System.getenv("${varName}")`;
    case '.rs':
      return `std::env::var("${varName}").unwrap()`;
    case '.sh':
    case '.bash':
    case '.zsh':
      return `"\${${varName}}"`;
    case '.yaml':
    case '.yml':
    case '.toml':
    case '.env':
      return `\${${varName}}`;
    case '.js':
    case '.jsx':
    case '.ts':
    case '.tsx':
    case '.mjs':
    case '.cjs':
    default:
      return `process.env.${varName}`;
  }
}

/**
 * Returns true only when the source explicitly loads .env at runtime.
 * Moving a literal into .env without a loader silently breaks applications,
 * so unknown runtimes intentionally do not receive the automatic quick fix.
 */
export function supportsDotEnvMigration(source: string, filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case '.js':
    case '.jsx':
    case '.ts':
    case '.tsx':
    case '.mjs':
    case '.cjs':
      return /(?:import\\s*['"]dotenv\\/config['"]|require\\s*\\(\\s*['"]dotenv\\/config['"]\\s*\\)|dotenv\\s*\\.\\s*config\\s*\\(|require\\s*\\(\\s*['"]dotenv['"]\\s*\\)\\s*\\.\\s*config\\s*\\()/m.test(source);
    case '.py':
      return /(?:from\\s+dotenv\\s+import\\s+load_dotenv|load_dotenv\\s*\\()/m.test(source);
    case '.go':
      return /godotenv\\s*\\.\\s*Load\\s*\\(/m.test(source);
    case '.rb':
      return /(?:require\\s*['"]dotenv\\/(?:load|rails)['"]|Dotenv\\s*\\.\\s*load\\s*\\()/m.test(source);
    case '.php':
      return /Dotenv::create(?:Immutable|Mutable)\\s*\\([^;]*\\)\\s*->\\s*(?:load|safeLoad)\\s*\\(/m.test(source);
    case '.rs':
      return /(?:dotenv|dotenvy)::dotenv\\s*\\(/m.test(source);
    case '.sh':
    case '.bash':
    case '.zsh':
      return /(?:^|\\n)\\s*(?:source|\\.)\\s+['"]?\\.env(?:['"])?(?:\\s|$)/m.test(source);
    default:
      return false;
  }
}

export function buildRemediationPlan(
  rule: RuleDefinition,
  rawSecret: string,
  filePath: string,
  line: number,
  inferredVarName?: string
): RemediationPlan {
  const envVarName = rule.suggestedEnvName(inferredVarName);
  const replacementCode = getLanguageReplacement(filePath, envVarName);
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
  envProtection?: {
    enforced: boolean;
    isUnsupportedFs?: boolean;
    details?: string;
  };
  degradedSecurity?: boolean;
  warning?: string;
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

  // Check git tracking and ignore status
  try {
    const { execFileSync } = require('child_process');
    try {
      execFileSync('git', ['rev-parse', '--is-inside-work-tree'], { cwd: workspaceRoot, stdio: 'ignore' });
    } catch {
      // In a non-git directory, skip Git repository index and ignore validation cleanly
      return;
    }

    try {
      execFileSync('git', ['ls-files', '--error-unmatch', '.env'], { cwd: workspaceRoot, stdio: 'ignore' });
      throw new Error('.env is already tracked in Git index. Run "git rm --cached .env" to untrack it before storing secrets.');
    } catch (lsErr: any) {
      if (lsErr.message && lsErr.message.includes('already tracked in Git index')) {
        throw lsErr;
      }
    }

    try {
      execFileSync('git', ['check-ignore', '-q', '.env'], { cwd: workspaceRoot, stdio: 'ignore' });
    } catch {
      // If check-ignore returned non-zero, .env is not ignored
      throw new Error('.env is not ignored by Git according to git check-ignore.');
    }
  } catch (err: any) {
    if (err.message && (err.message.includes('already tracked') || err.message.includes('not ignored by Git'))) {
      throw err;
    }
  }
}

/**
 * Enforces strict filesystem permissions on .env files to ensure credentials are protected.
 * - On POSIX systems, enforces octal mode 0600 (owner read/write only).
 * - On Windows (NTFS), hardens the Access Control List (ACL) via `icacls`, removing inherited
 *   permissions and restricting explicit access to the current executing user only.
 *   On non-NTFS volumes (e.g. FAT32/exFAT) where Windows ACLs are not supported, verifies read/write access.
 */
export interface SecurityPrincipal {
  username: string;
  domain?: string;
  qualifiedName: string;
  userSid?: string;
}

/**
 * Discovers the current user's security principal on Windows (or fallback environments),
 * querying whoami /user to obtain the authoritative domain, username, and account SID.
 */
export function getCurrentSecurityPrincipal(
  cpModule: typeof cp = cp,
  targetPlatform: string = process.platform
): SecurityPrincipal {
  let username = process.env.USERNAME || process.env.USER;
  if (!username) {
    try {
      username = os.userInfo().username;
    } catch {}
  }
  if (!username) {
    username = 'unknown';
  }

  let domain = process.env.USERDOMAIN;
  let qualifiedName = domain ? `${domain}\\${username}` : username;
  let userSid: string | undefined = process.env.USER_SID;

  if (targetPlatform === 'win32') {
    try {
      const whoamiOut = cpModule
        .execFileSync('whoami', ['/user', '/fo', 'csv'], {
          encoding: 'utf8',
          stdio: 'pipe',
          windowsHide: true,
        })
        .toString();

      const lines = whoamiOut.split(/\r?\n/).filter((l) => l.trim().length > 0);
      for (const line of lines) {
        if (/User Name.*SID/i.test(line)) continue;
        const match = line.match(/"([^"]+)"\s*,\s*"([^"]+)"/);
        if (match) {
          qualifiedName = match[1].trim();
          userSid = match[2].trim();
          if (qualifiedName.includes('\\')) {
            const parts = qualifiedName.split('\\');
            domain = parts[0];
            username = parts.slice(1).join('\\');
          }
          break;
        }
      }
    } catch {
      // whoami not available or mocked; fall back to environment / os values
    }
  }

  return { username, domain, qualifiedName, userSid };
}

/**
 * Strictly verifies whether an Access Control Entry (ACE) principal matches the current user or SYSTEM.
 * Never matches on bare username suffixes when a domain prefix differs (preventing OTHERDOMAIN\user from
 * matching CURRENTDOMAIN\user), and checks the account SID when available.
 */
export function isPrincipalAuthorized(rawAccount: string, principal: SecurityPrincipal): boolean {
  const accountTrim = rawAccount.trim();
  const accountLower = accountTrim.toLowerCase();
  const accountBare = accountTrim.split('\\').pop()?.toLowerCase() || '';

  // SYSTEM account check (NT AUTHORITY\SYSTEM, SID S-1-5-18)
  if (
    accountLower === 'nt authority\\system' ||
    accountBare === 'system' ||
    accountLower === 's-1-5-18' ||
    accountLower === '*s-1-5-18'
  ) {
    return true;
  }

  // Exact SID check
  const sidCandidate = accountLower.startsWith('*') ? accountLower.slice(1) : accountLower;
  if (principal.userSid && sidCandidate === principal.userSid.toLowerCase()) {
    return true;
  }

  // Domain-qualified account check (e.g. "DOMAIN\username")
  if (accountTrim.includes('\\')) {
    // If account has a domain prefix, it MUST match the current user's fully qualified domain\username.
    // Accounts with differing domain prefixes (e.g. "OTHERDOMAIN\Lakshith") will NEVER match!
    return accountLower === principal.qualifiedName.toLowerCase();
  }

  // Bare account check without domain prefix (e.g. "testuser", "runner", or local account)
  // Bare name matches ONLY if bare username matches the current user's username
  return accountBare === principal.username.toLowerCase();
}

/**
 * Enforces strict 0600 file permissions on POSIX, and user-exclusive ACLs on Windows:
 * - On POSIX: sets mode to 0600 (owner read/write only, zero permissions for group/others)
 *   and verifies the resulting mode using statSync.
 * - On Windows (NTFS):
 *   1. Strips inherited permissions and explicitly grants the current user Full Control (:F).
 *   2. Queries existing explicit Access Control Entries (ACEs) via icacls.
 *   3. Actively strips any broad or unsafe explicit permissions granted to other accounts/groups
 *      (e.g. Everyone, BUILTIN\Users, Guest, secondary accounts).
 *   4. Verifies effective ACLs, ensuring only the current user (and SYSTEM) retains access.
 *   5. Distinguishes genuinely unsupported filesystems (e.g. FAT32/exFAT) from security or
 *      operational errors, throwing descriptive errors when ACL protection cannot be enforced.
 */
export function enforceEnvFilePermissions(
  envPath: string,
  fsModule: typeof fs = fs,
  targetPlatform: string = process.platform,
  cpModule: typeof cp = cp
): { enforced: boolean; isUnsupportedFs?: boolean; details?: string } {
  if (targetPlatform === 'win32') {
    fsModule.accessSync(envPath, fs.constants.R_OK | fs.constants.W_OK);
    const principal = getCurrentSecurityPrincipal(cpModule, targetPlatform);
    if (!principal.username || principal.username === 'unknown') {
      throw new Error('Failed to enforce Windows ACLs: neither USERNAME nor USER environment variable is set');
    }

    try {
      // 1. Remove inherited ACLs and grant exclusive Full Control to the current user principal
      const grantTarget = principal.qualifiedName || principal.username;
      cpModule.execFileSync('icacls', [envPath, '/inheritance:r', '/grant:r', `${grantTarget}:F`], {
        stdio: 'pipe',
        windowsHide: true,
      });

      // 2. Query effective ACLs to discover any explicit permissions granted to other accounts
      const queryOut = cpModule
        .execFileSync('icacls', [envPath], {
          encoding: 'utf8',
          stdio: 'pipe',
          windowsHide: true,
        })
        .toString();

      const lines = queryOut.split(/\r?\n/).filter((l: string) => l.trim().length > 0);
      const unsafeAccounts: string[] = [];

      for (const line of lines) {
        if (/successfully processed|failed processing|processed file/i.test(line)) continue;
        const match = line.match(/(?:^|[^\\]\s+|^.+?\s+)([A-Za-z0-9_\\\-\.\$@\* ]+?):(\([^\)]+\)+)/);
        if (match) {
          const rawAccount = match[1].trim();
          if (!isPrincipalAuthorized(rawAccount, principal)) {
            unsafeAccounts.push(rawAccount);
          }
        }
      }

      // 3. Remove all discovered unsafe explicit accounts
      for (const unsafeAcc of unsafeAccounts) {
        try {
          cpModule.execFileSync('icacls', [envPath, '/remove', unsafeAcc], {
            stdio: 'pipe',
            windowsHide: true,
          });
        } catch (removeErr: any) {
          throw new Error(`Failed to remove unsafe explicit ACL for account '${unsafeAcc}': ${removeErr?.message || removeErr}`);
        }
      }

      // 4. Verify effective permissions after cleanup
      const verifyOut = cpModule
        .execFileSync('icacls', [envPath], {
          encoding: 'utf8',
          stdio: 'pipe',
          windowsHide: true,
        })
        .toString();

      const remainingUnsafe: string[] = [];
      for (const line of verifyOut.split(/\r?\n/).filter(Boolean)) {
        if (/successfully processed|failed processing|processed file/i.test(line)) continue;
        const match = line.match(/(?:^|[^\\]\s+|^.+?\s+)([A-Za-z0-9_\\\-\.\$@\* ]+?):(\([^\)]+\)+)/);
        if (match) {
          const rawAccount = match[1].trim();
          if (!isPrincipalAuthorized(rawAccount, principal)) {
            remainingUnsafe.push(rawAccount);
          }
        }
      }

      if (remainingUnsafe.length > 0) {
        throw new Error(
          `Security error: Windows ACL enforcement failed on '${envPath}'. Unsafe explicit permissions remain for: ${remainingUnsafe.join(', ')}`
        );
      }

      return { enforced: true, details: `ACL hardened exclusively for ${principal.qualifiedName}` };
    } catch (err: any) {
      const errMsg = err?.message || String(err);
      const isUnsupportedFs =
        /does not support ACL|not supported|Incorrect function|No security ID|0x80070001|The volume does not support/i.test(errMsg);

      if (isUnsupportedFs) {
        return {
          enforced: false,
          isUnsupportedFs: true,
          details: `Volume does not support ACLs (FAT32/exFAT): ${errMsg}`,
        };
      }

      // Operational or security failure on supported volume: do NOT swallow!
      throw new Error(`Failed to enforce Windows ACL protection on '${envPath}': ${errMsg}`);
    }
  } else {
    try {
      fsModule.chmodSync(envPath, 0o600);
    } catch (err: any) {
      throw new Error(`Failed to chmod .env to 0600: ${err?.message || err}`);
    }
    const stat = fsModule.statSync(envPath);
    const mode = stat.mode & 0o777;
    if ((mode & 0o077) !== 0) {
      throw new Error(`Permission enforcement failed: .env file mode is 0o${mode.toString(8)}, expected 0o600`);
    }
    return { enforced: true, details: 'POSIX mode set to 0600' };
  }
}

export function applyControlledRemediation(
  finding: SecretFinding,
  workspaceRoot: string,
  fsModule: typeof fs = fs,
  targetPlatform: string = process.platform,
  cpModule: typeof cp = cp
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
    if (!fsModule.existsSync(targetFile)) {
      return {
        success: false,
        message: `Target file not found: ${targetFile}`,
        envPath: '',
        modifiedFile: targetFile,
      };
    }

    originalFileContent = fsModule.readFileSync(targetFile, 'utf8');
    if (!supportsDotEnvMigration(originalFileContent, targetFile)) {
      return {
        success: false,
        message: 'Automatic .env migration is unavailable: no supported .env runtime loader was detected in this file. Configure the environment loader first, then retry.',
        envPath: '',
        modifiedFile: targetFile,
      };
    }
    const secretToSearch = finding.sourceExpression || finding.rawSecret;
    if (!originalFileContent.includes(secretToSearch) && !originalFileContent.includes(finding.rawSecret)) {
      return {
        success: false,
        message: 'Secret no longer found in target file (may have already been modified).',
        envPath: '',
        modifiedFile: targetFile,
      };
    }

    // 1. Read existing .env if present and determine unique variable name
    let envContent = '';
    if (fsModule.existsSync(envPath)) {
      originalEnvContent = fsModule.readFileSync(envPath, 'utf8');
      envContent = originalEnvContent;
    } else {
      envWasNewlyCreated = true;
      try {
        fsModule.writeFileSync(envPath, '', { mode: 0o600, encoding: 'utf8' });
      } catch {}
    }

    // Snapshot .gitignore state before mutation
    if (fsModule.existsSync(gitignorePath)) {
      originalGitignoreContent = fsModule.readFileSync(gitignorePath, 'utf8');
    } else {
      gitignoreWasNewlyCreated = true;
    }

    const suggestedName = finding.remediation?.envVarName || 'API_KEY';
    const { varName, isReused } = resolveUniqueEnvVarName(envContent, suggestedName, finding.rawSecret);
    const replacementCode = getLanguageReplacement(targetFile, varName);
    const escapedValue = escapeEnvValue(finding.rawSecret);
    const envLine = `${varName}="${escapedValue}"\n`;

    // 2. Ensure .gitignore protects .env BEFORE writing credentials to disk
    ensureGitignoreProtectsEnv(workspaceRoot);

    // 3. Enforce owner-only protection BEFORE writing credential material.
    const envProtection = enforceEnvFilePermissions(envPath, fsModule, targetPlatform, cpModule);
    if (!envProtection.enforced) {
      throw new Error(`Could not enforce private .env permissions (${envProtection.details || 'unsupported filesystem'}). No credential was written.`);
    }
    if (!isReused) {
      const prefix = envContent.endsWith('\n') || envContent.length === 0 ? '' : '\n';
      fsModule.appendFileSync(envPath, `${prefix}${envLine}`, 'utf8');
    }
    const degradedSecurity = false;
    const warning: string | undefined = undefined;
    const message = `Successfully migrated ${finding.type} to .env (${varName}) and replaced in ${finding.file}.`;

    // 4. Update .env.example
    const envExamplePath = path.join(workspaceRoot, '.env.example');
    const exampleLine = `${varName}=your_${varName.toLowerCase()}_here\n`;
    const envExampleExists = fsModule.existsSync(envExamplePath);
    if (!envExampleExists) {
      envExampleWasNewlyCreated = true;
    } else {
      originalEnvExampleContent = fsModule.readFileSync(envExamplePath, 'utf8');
    }
    if (!envExampleExists || !fsModule.readFileSync(envExamplePath, 'utf8').includes(varName)) {
      const exContent = envExampleExists ? fsModule.readFileSync(envExamplePath, 'utf8') : '';
      const exPrefix = exContent.endsWith('\n') || exContent.length === 0 ? '' : '\n';
      fsModule.appendFileSync(envExamplePath, `${exPrefix}${exampleLine}`, 'utf8');
    }

    // 5. Replace secret literal in source file, stripping enclosing quotes so replacementCode is evaluated
    let newContent = originalFileContent;
    const targetExpr = finding.sourceExpression || finding.rawSecret;
    const doubleQuoted = `"${targetExpr}"`;
    const singleQuoted = `'${targetExpr}'`;
    const backtickQuoted = `\`${targetExpr}\``;

    if (newContent.includes(doubleQuoted)) {
      newContent = newContent.replace(new RegExp(escapeRegExp(doubleQuoted), 'g'), replacementCode);
    } else if (newContent.includes(singleQuoted)) {
      newContent = newContent.replace(new RegExp(escapeRegExp(singleQuoted), 'g'), replacementCode);
    } else if (newContent.includes(backtickQuoted)) {
      newContent = newContent.replace(new RegExp(escapeRegExp(backtickQuoted), 'g'), replacementCode);
    } else if (newContent.includes(targetExpr)) {
      newContent = newContent.replace(new RegExp(escapeRegExp(targetExpr), 'g'), replacementCode);
    } else {
      newContent = newContent.replace(new RegExp(escapeRegExp(finding.rawSecret), 'g'), replacementCode);
    }

    fsModule.writeFileSync(targetFile, newContent, 'utf8');

    return {
      success: true,
      message,
      envPath,
      modifiedFile: targetFile,
      envProtection,
      degradedSecurity,
      warning,
    };
  } catch (err: any) {
    // Transactional Rollback: restore all mutated files to their pre-call state.
    const rollbackFailures: string[] = [];

    // Helper: atomic write-via-temp-file to avoid leaving a partially-written file
    const atomicWrite = (filePath: string, content: string): void => {
      const tmp = `${filePath}.sld-tmp-${Date.now()}`;
      fsModule.writeFileSync(tmp, content, 'utf8');
      fsModule.renameSync(tmp, filePath);
    };

    // Source file
    if (originalFileContent !== null) {
      try {
        atomicWrite(targetFile, originalFileContent);
        const restored = fsModule.readFileSync(targetFile, 'utf8');
        if (restored !== originalFileContent) {
          rollbackFailures.push(`source file restored with mismatched content (${targetFile})`);
        }
      } catch (rbErr: any) {
        rollbackFailures.push(`source file restore failed (${targetFile}): ${rbErr.message}`);
      }
    }

    // .env: delete if newly created, restore if pre-existing
    if (envWasNewlyCreated && fsModule.existsSync(envPath)) {
      try {
        fsModule.unlinkSync(envPath);
        if (fsModule.existsSync(envPath)) rollbackFailures.push(`.env delete did not take effect`);
      } catch (rbErr: any) {
        rollbackFailures.push(`.env delete failed: ${rbErr.message}`);
      }
    } else if (originalEnvContent !== null && fsModule.existsSync(envPath)) {
      try {
        atomicWrite(envPath, originalEnvContent);
      } catch (rbErr: any) {
        rollbackFailures.push(`.env restore failed: ${rbErr.message}`);
      }
    }

    // .gitignore: delete if newly created, restore if pre-existing
    if (gitignoreWasNewlyCreated && fsModule.existsSync(gitignorePath)) {
      try {
        fsModule.unlinkSync(gitignorePath);
        if (fsModule.existsSync(gitignorePath)) rollbackFailures.push(`.gitignore delete did not take effect`);
      } catch (rbErr: any) {
        rollbackFailures.push(`.gitignore delete failed: ${rbErr.message}`);
      }
    } else if (originalGitignoreContent !== null && fsModule.existsSync(gitignorePath)) {
      try {
        atomicWrite(gitignorePath, originalGitignoreContent);
      } catch (rbErr: any) {
        rollbackFailures.push(`.gitignore restore failed: ${rbErr.message}`);
      }
    }

    // .env.example: delete if newly created, restore if pre-existing
    const envExamplePath = path.join(workspaceRoot, '.env.example');
    if (envExampleWasNewlyCreated && fsModule.existsSync(envExamplePath)) {
      try {
        fsModule.unlinkSync(envExamplePath);
        if (fsModule.existsSync(envExamplePath)) rollbackFailures.push(`.env.example delete did not take effect`);
      } catch (rbErr: any) {
        rollbackFailures.push(`.env.example delete failed: ${rbErr.message}`);
      }
    } else if (originalEnvExampleContent !== null && fsModule.existsSync(envExamplePath)) {
      try {
        atomicWrite(envExamplePath, originalEnvExampleContent);
      } catch (rbErr: any) {
        rollbackFailures.push(`.env.example restore failed: ${rbErr.message}`);
      }
    }

    const rollbackStatus =
      rollbackFailures.length === 0
        ? 'Rollback completed successfully.'
        : `ROLLBACK INCOMPLETE — manual inspection required: ${rollbackFailures.join('; ')}`;

    return {
      success: false,
      message: `Remediation failed: ${err.message}. ${rollbackStatus}`,
      envPath: '',
      modifiedFile: finding.fullPath,
    };
  }
}

function escapeRegExp(string: string): string {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
