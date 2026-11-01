/**
 * VS Code extension uninstallation hook.
 * Safely removes SLD-managed pre-commit hooks or restores backed-up user hooks.
 */
import * as fs from 'fs';
import * as path from 'path';

const SLD_HOOK_MARKER = '# [SLD_HOOK_MANAGED]';

function cleanHook(hookPath: string) {
  if (!fs.existsSync(hookPath)) return;
  try {
    const content = fs.readFileSync(hookPath, 'utf8');
    if (!content.includes(SLD_HOOK_MARKER)) return;

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
  } catch {}
}

function run() {
  const cwd = process.cwd();
  cleanHook(path.join(cwd, '.git', 'hooks', 'pre-commit'));
}

run();
