/**
 * VS Code extension uninstallation hook.
 * Safely removes SLD-managed pre-commit hooks or restores backed-up user hooks,
 * cleans up the persistent CLI copy in globalStorage, and outputs a summary.
 */
import * as fs from 'fs';
import * as path from 'path';

const SLD_HOOK_MARKER = '# [SLD_HOOK_MANAGED]';

export function cleanHook(hookPath: string): boolean {
  if (!fs.existsSync(hookPath)) return false;
  try {
    const content = fs.readFileSync(hookPath, 'utf8');
    const isSldHook = content.includes(SLD_HOOK_MARKER);
    if (!isSldHook) return false;

    const dir = path.dirname(hookPath);
    const latestBackupMarker = path.join(dir, 'pre-commit.sld-backup.latest');
    let restored = false;

    if (fs.existsSync(latestBackupMarker)) {
      try {
        const backupPath = fs.readFileSync(latestBackupMarker, 'utf8').trim();
        if (fs.existsSync(backupPath) && path.dirname(backupPath) === dir) {
          const stat = fs.statSync(backupPath);
          fs.copyFileSync(backupPath, hookPath);
          try {
            fs.chmodSync(hookPath, stat.mode);
          } catch {}
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

function extractFileUris(obj: any, results: Set<string>): void {
  if (!obj) return;
  if (typeof obj === 'string') {
    if (obj.startsWith('file://')) {
      let diskPath = decodeURIComponent(obj.replace(/^file:\/\/\/?/, '/'));
      if (process.platform === 'win32' && /^\/[a-zA-Z]:/.test(diskPath)) {
        diskPath = diskPath.slice(1);
      }
      results.add(path.normalize(diskPath));
    }
  } else if (Array.isArray(obj)) {
    for (const item of obj) {
      extractFileUris(item, results);
    }
  } else if (typeof obj === 'object') {
    for (const key of Object.keys(obj)) {
      extractFileUris(obj[key], results);
    }
  }
}

function cleanWorkspacesFromWorkspaceStorage(appData: string, app: string, cleanedList: string[]): void {
  try {
    const wsStorageDir = path.join(appData, app, 'User', 'workspaceStorage');
    if (!fs.existsSync(wsStorageDir)) return;
    const entries = fs.readdirSync(wsStorageDir, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const wsJson = path.join(wsStorageDir, entry.name, 'workspace.json');
      if (fs.existsSync(wsJson)) {
        try {
          const raw = fs.readFileSync(wsJson, 'utf8');
          const data = JSON.parse(raw);
          const uris = new Set<string>();
          extractFileUris(data, uris);
          for (const dir of uris) {
            const hookPath = path.join(dir, '.git', 'hooks', 'pre-commit');
            if (cleanHook(hookPath)) {
              cleanedList.push(hookPath);
            }
          }
        } catch {}
      }
    }
  } catch (err: any) {
    console.warn(`[Secret Leak Detector] Warning reading workspaceStorage for ${app}: ${err?.message || err}`);
  }
}

function cleanWorkspacesFromStorageJson(appData: string, app: string, cleanedList: string[]): void {
  try {
    const storageJsonPath = path.join(appData, app, 'User', 'globalStorage', 'storage.json');
    if (!fs.existsSync(storageJsonPath)) return;
    const content = fs.readFileSync(storageJsonPath, 'utf8');
    const parsed = JSON.parse(content);
    const uris = new Set<string>();
    extractFileUris(parsed, uris);
    for (const dir of uris) {
      const hookPath = path.join(dir, '.git', 'hooks', 'pre-commit');
      if (cleanHook(hookPath)) {
        cleanedList.push(hookPath);
      }
    }
  } catch (err: any) {
    console.warn(`[Secret Leak Detector] Warning parsing storage.json for ${app}: ${err?.message || err}`);
  }
}

function getOtherUserHomes(): string[] {
  const homes: string[] = [];
  try {
    const usersParent =
      process.platform === 'win32'
        ? 'C:\\Users'
        : process.platform === 'darwin'
        ? '/Users'
        : '/home';
    if (fs.existsSync(usersParent)) {
      const currentHome = process.env.HOME || process.env.USERPROFILE || '';
      const entries = fs.readdirSync(usersParent, { withFileTypes: true });
      for (const e of entries) {
        if (e.isDirectory() && !e.name.startsWith('.')) {
          const uPath = path.join(usersParent, e.name);
          if (path.resolve(uPath) !== path.resolve(currentHome)) {
            homes.push(uPath);
          }
        }
      }
    }
  } catch {}
  return homes;
}

function getGlobalStorageCandidates(cleanedList: string[]): string[] {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const appData =
    process.env.APPDATA ||
    (process.platform === 'darwin'
      ? path.join(home, 'Library', 'Application Support')
      : path.join(home, '.config'));

  const appNames = ['Code', 'Code - Insiders', 'VSCodium', 'Cursor', 'Windsurf'];
  const extNames = [
    'mokulakshithreddy.secret-leak-detector',
    'MokuLakshithReddy.secret-leak-detector',
    'secret-leak-detector',
  ];
  const dirs: string[] = [];

  for (const app of appNames) {
    const baseGlobalStorage = path.join(appData, app, 'User', 'globalStorage');
    if (fs.existsSync(baseGlobalStorage)) {
      try {
        const subdirs = fs.readdirSync(baseGlobalStorage, { withFileTypes: true });
        for (const s of subdirs) {
          if (s.isDirectory() && s.name.toLowerCase().includes('secret-leak-detector')) {
            dirs.push(path.join(baseGlobalStorage, s.name));
          }
        }
      } catch {}
    }

    for (const ext of extNames) {
      dirs.push(path.join(appData, app, 'User', 'globalStorage', ext));
      if (process.platform === 'win32') {
        dirs.push(path.join(home, 'AppData', 'Roaming', app, 'User', 'globalStorage', ext));
        dirs.push(path.join(home, 'AppData', 'Local', app, 'User', 'globalStorage', ext));
      }
    }
    // Discover workspaces from storage.json and workspaceStorage
    cleanWorkspacesFromStorageJson(appData, app, cleanedList);
    cleanWorkspacesFromWorkspaceStorage(appData, app, cleanedList);
  }

  // Also check standard Linux/macOS ~/.config paths
  for (const ext of extNames) {
    dirs.push(path.join(home, '.config', 'Code', 'User', 'globalStorage', ext));
  }
  return dirs;
}

export function runUninstall(): void {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const cleanedHooks: string[] = [];

  // 1. Clean current working directory hook if any
  const cwdHook = path.join(process.cwd(), '.git', 'hooks', 'pre-commit');
  if (cleanHook(cwdHook)) {
    cleanedHooks.push(cwdHook);
  }

  // 2. Clean hooks recorded in user-global ~/.sld/installed-hooks.json
  const sldRecord = path.join(home, '.sld', 'installed-hooks.json');
  if (fs.existsSync(sldRecord)) {
    try {
      const hooks: string[] = JSON.parse(fs.readFileSync(sldRecord, 'utf8'));
      if (Array.isArray(hooks)) {
        for (const h of hooks) {
          if (cleanHook(h)) {
            cleanedHooks.push(h);
          }
        }
      }
      fs.unlinkSync(sldRecord);
    } catch (err: any) {
      console.warn(`[Secret Leak Detector] Warning reading ~/.sld/installed-hooks.json: ${err?.message || err}`);
    }
  }

  // 3. Clean hooks recorded in other user profiles if accessible
  const otherHomes = getOtherUserHomes();
  for (const oHome of otherHomes) {
    const oRecord = path.join(oHome, '.sld', 'installed-hooks.json');
    if (fs.existsSync(oRecord)) {
      try {
        const hooks: string[] = JSON.parse(fs.readFileSync(oRecord, 'utf8'));
        if (Array.isArray(hooks)) {
          for (const h of hooks) {
            if (cleanHook(h)) {
              cleanedHooks.push(h);
            }
          }
        }
        try {
          fs.unlinkSync(oRecord);
        } catch {}
      } catch {}
    }
  }

  // 4. Clean hooks configured via global core.hooksPath if any
  try {
    const { execFileSync } = require('child_process');
    const globalHooksPath = execFileSync('git', ['config', '--global', 'core.hooksPath'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (globalHooksPath) {
      const gHook = path.join(globalHooksPath, 'pre-commit');
      if (cleanHook(gHook)) {
        cleanedHooks.push(gHook);
      }
    }
  } catch {}

  // 5. Discover recorded repositories and hooks across globalStorage directories and storage.json
  const storageDirs = getGlobalStorageCandidates(cleanedHooks);
  for (const sDir of storageDirs) {
    if (!fs.existsSync(sDir)) continue;

    const recordFile = path.join(sDir, 'installed-hooks.json');
    if (fs.existsSync(recordFile)) {
      try {
        const hooks: string[] = JSON.parse(fs.readFileSync(recordFile, 'utf8'));
        if (Array.isArray(hooks)) {
          for (const h of hooks) {
            if (cleanHook(h)) {
              cleanedHooks.push(h);
            }
          }
        }
        fs.unlinkSync(recordFile);
      } catch (err: any) {
        console.warn(`[Secret Leak Detector] Warning reading ${recordFile}: ${err?.message || err}`);
      }
    }

    // Remove stable CLI binary from globalStorage so no frozen orphaned scanner survives
    const cliPath = path.join(sDir, 'cli.js');
    if (fs.existsSync(cliPath)) {
      try {
        fs.unlinkSync(cliPath);
      } catch {}
    }
  }

  console.log(`[Secret Leak Detector] Uninstallation complete: cleaned ${cleanedHooks.length} Git hook(s).`);
  if (cleanedHooks.length > 0) {
    for (const h of cleanedHooks) {
      console.log(`  - Cleaned: ${h}`);
    }
  }
}

if (typeof require !== 'undefined' && require.main === module) {
  runUninstall();
}
