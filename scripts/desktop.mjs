import { spawn } from 'node:child_process';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';
const root = resolve(import.meta.dirname, '..');
const child = spawn(process.execPath, [join(root, 'apps/ui/node_modules/@tauri-apps/cli/tauri.js'), ...process.argv.slice(2)], {
  cwd: join(root, 'apps/desktop'), stdio: 'inherit',
  env: { ...process.env, PATH: `${join(homedir(), '.cargo/bin')}${process.platform === 'win32' ? ';' : ':'}${process.env.PATH ?? ''}` },
});
child.on('error', error => { console.error(error); process.exit(1); });
child.on('exit', code => process.exit(code ?? 1));
