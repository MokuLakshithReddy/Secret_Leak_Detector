/**
 * VS Code extension uninstallation hook.
 * Safely removes SLD-managed pre-commit hooks or restores backed-up user hooks,
 * and cleans up the persistent CLI copy in globalStorage.
 */
import * as fs from 'fs';
import * as path from 'path';

const SLD_HOOK_MARKER = '# [SLD_HOOK_MANAGED]';

export function cleanHook(hookPath: string): boolean {
  if (!fs.existsSync(hookPath)) return false;
  try {
    const content = fs.readFileSync(hookPath, 'utf8');
    if (!content.includes(SLD_HOOK_MARKER)) return false;

    const dir = path.dirname(hookPath);
    const latestBackupMarker = path.join(dir, 'pre-commit.sld-backup.latest');
    let restored = false;

    if (fs.existsSync(latestBackupMarker)) {
      try {
        const backupPath = fs.readFileSync(latestBackupMarker, 'utf8').trim();
        if (fs.existsSync(backupPath) && path.dirname(backupPath) === dir) {
          fs.copyFileSync(backupPath, hookPath);
          fs.unlinkSync(latestBackupMarker);
          fs.unlinkSync(backupPath);
          restored = true;
        }
      } catch {}
    }

    if (!restored) {
      fs.unlinkSync(hookPath);
    }
    return true;
  } catch {
    return false;
  }
}

function getGlobalStorageCandidates(): string[] {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const appData =
    process.env.APPDATA ||
    (process.platform === 'darwin'
      ? path.join(home, 'Library', 'Application Support')
      : path.join(home, '.config'));

  const appNames = ['Code', 'Code - Insiders', 'VSCodium', 'Cursor', 'Windsurf'];
  const dirs: string[] = [];

  for (const app of appNames) {
    dirs.push(path.join(appData, app, 'User', 'globalStorage', 'mokulakshithreddy.secret-leak-detector'));
    if (process.platform === 'win32') {
      dirs.push(path.join(home, 'AppData', 'Roaming', app, 'User', 'globalStorage', 'mokulakshithreddy.secret-leak-detector'));
    }
  }

  // Also check standard Linux/macOS ~/.config paths
  dirs.push(path.join(home, '.config', 'Code', 'User', 'globalStorage', 'mokulakshithreddy.secret-leak-detector'));
  return dirs;
}

export function runUninstall(): void {
  // 1. Clean current working directory hook if any
  cleanHook(path.join(process.cwd(), '.git', 'hooks', 'pre-commit'));

  // 2. Discover recorded repositories and hooks across globalStorage directories
  const storageDirs = getGlobalStorageCandidates();
  for (const sDir of storageDirs) {
    if (!fs.existsSync(sDir)) continue;

    const recordFile = path.join(sDir, 'installed-hooks.json');
    if (fs.existsSync(recordFile)) {
      try {
        const hooks: string[] = JSON.parse(fs.readFileSync(recordFile, 'utf8'));
        if (Array.isArray(hooks)) {
          for (const h of hooks) {
            cleanHook(h);
          }
        }
        fs.unlinkSync(recordFile);
      } catch {}
    }

    // 3. Remove stable CLI binary from globalStorage so no frozen orphaned scanner survives
    const cliPath = path.join(sDir, 'cli.js');
    if (fs.existsSync(cliPath)) {
      try {
        fs.unlinkSync(cliPath);
      } catch {}
    }
  }
}

runUninstall();
