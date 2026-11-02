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
    const isSldHook = content.includes(SLD_HOOK_MARKER);
    if (!isSldHook) return false;

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

function cleanWorkspacesFromWorkspaceStorage(appData: string, app: string): void {
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
          const uri = data.folder || data.workspace;
          if (uri && typeof uri === 'string' && uri.startsWith('file://')) {
            let diskPath = decodeURIComponent(uri.replace(/^file:\/\/\/?/, '/'));
            if (process.platform === 'win32' && /^\/[a-zA-Z]:/.test(diskPath)) {
              diskPath = diskPath.slice(1);
            }
            cleanHook(path.join(diskPath, '.git', 'hooks', 'pre-commit'));
          }
        } catch {}
      }
    }
  } catch {}
}

function getGlobalStorageCandidates(): string[] {
  const home = process.env.HOME || process.env.USERPROFILE || '';
  const appData =
    process.env.APPDATA ||
    (process.platform === 'darwin'
      ? path.join(home, 'Library', 'Application Support')
      : path.join(home, '.config'));

  const appNames = ['Code', 'Code - Insiders', 'VSCodium', 'Cursor', 'Windsurf'];
  const extNames = ['mokulakshithreddy.secret-leak-detector', 'MokuLakshithReddy.secret-leak-detector', 'secret-leak-detector'];
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
    cleanWorkspacesFromStorageJson(appData, app);
    cleanWorkspacesFromWorkspaceStorage(appData, app);
  }

  // Also check standard Linux/macOS ~/.config paths
  for (const ext of extNames) {
    dirs.push(path.join(home, '.config', 'Code', 'User', 'globalStorage', ext));
  }
  return dirs;
}

function cleanWorkspacesFromStorageJson(appData: string, app: string): void {
  try {
    const storageJsonPath = path.join(appData, app, 'User', 'globalStorage', 'storage.json');
    if (!fs.existsSync(storageJsonPath)) return;
    const content = fs.readFileSync(storageJsonPath, 'utf8');
    const matches = content.match(/"(?:file|folderUri|workspaceUri)":\s*"file:\/\/\/([^"]+)"/g);
    if (matches) {
      for (const m of matches) {
        const pMatch = m.match(/"file:\/\/\/([^"]+)"/);
        if (pMatch && pMatch[1]) {
          let diskPath = decodeURIComponent(pMatch[1]);
          if (process.platform === 'win32' && /^\/[a-zA-Z]:/.test(diskPath)) {
            diskPath = diskPath.slice(1);
          }
          cleanHook(path.join(diskPath, '.git', 'hooks', 'pre-commit'));
        }
      }
    }
  } catch {}
}

function recursivelyCleanGitHooks(dir: string, depth = 0, maxDepth = 2): void {
  if (depth > maxDepth || !fs.existsSync(dir)) return;
  try {
    const gitHook = path.join(dir, '.git', 'hooks', 'pre-commit');
    if (fs.existsSync(gitHook)) {
      cleanHook(gitHook);
    }
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const e of entries) {
      if (e.isDirectory() && e.name !== '.git' && e.name !== 'node_modules' && e.name !== 'AppData') {
        recursivelyCleanGitHooks(path.join(dir, e.name), depth + 1, maxDepth);
      }
    }
  } catch {}
}

function cleanCommonDevDirs(home: string): void {
  const common = ['Projects', 'Documents', 'Desktop', 'workspace', 'repos', 'src', 'dev', 'code', 'git'];
  for (const c of common) {
    const parentDir = path.join(home, c);
    recursivelyCleanGitHooks(parentDir, 0, 2);
  }
}

export function runUninstall(): void {
  const home = process.env.HOME || process.env.USERPROFILE || '';

  // 1. Clean current working directory hook if any
  cleanHook(path.join(process.cwd(), '.git', 'hooks', 'pre-commit'));

  // 2. Clean hooks recorded in user-global ~/.sld/installed-hooks.json
  const sldRecord = path.join(home, '.sld', 'installed-hooks.json');
  if (fs.existsSync(sldRecord)) {
    try {
      const hooks: string[] = JSON.parse(fs.readFileSync(sldRecord, 'utf8'));
      if (Array.isArray(hooks)) {
        for (const h of hooks) {
          cleanHook(h);
        }
      }
      fs.unlinkSync(sldRecord);
    } catch {}
  }

  // 3. Clean hooks configured via global core.hooksPath if any
  try {
    const { execFileSync } = require('child_process');
    const globalHooksPath = execFileSync('git', ['config', '--global', 'core.hooksPath'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (globalHooksPath) {
      cleanHook(path.join(globalHooksPath, 'pre-commit'));
    }
  } catch {}

  // 4. Discover recorded repositories and hooks across globalStorage directories and storage.json
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

    // Remove stable CLI binary from globalStorage so no frozen orphaned scanner survives
    const cliPath = path.join(sDir, 'cli.js');
    if (fs.existsSync(cliPath)) {
      try {
        fs.unlinkSync(cliPath);
      } catch {}
    }
  }

  // 5. Sweep common developer workspaces in user home
  cleanCommonDevDirs(home);
}

if (typeof require !== 'undefined' && require.main === module) {
  runUninstall();
}
