import * as fs from 'fs';
import * as path from 'path';

export const CURRENT_VERSION = '1.0.3';

export function getPackageVersion(): string {
  try {
    const candidates = [
      path.resolve(__dirname, '../../package.json'),
      path.resolve(__dirname, '../../../package.json'),
      path.resolve(__dirname, '../package.json'),
      path.resolve(__dirname, 'package.json'),
    ];
    for (const c of candidates) {
      if (fs.existsSync(c)) {
        const pkg = JSON.parse(fs.readFileSync(c, 'utf8'));
        if (pkg.version) return pkg.version;
      }
    }
  } catch {}
  return CURRENT_VERSION;
}
