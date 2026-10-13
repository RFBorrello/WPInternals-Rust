import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';

const root = resolve(import.meta.dirname, '..');
const suffix = process.platform === 'win32' ? '.exe' : '';
const cargo = existsSync(join(homedir(), '.cargo', 'bin', `cargo${suffix}`)) ? join(homedir(), '.cargo', 'bin', `cargo${suffix}`) : `cargo${suffix}`;
const localBindgen = join(root, '.tools', 'bin', `wasm-bindgen${suffix}`);
const bindgen = existsSync(localBindgen) ? localBindgen : `wasm-bindgen${suffix}`;
function run(command, args) {
  const result = spawnSync(command, args, { cwd: root, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
run(cargo, ['build', '--locked', '--release', '--target', 'wasm32-unknown-unknown', '-p', 'wpi-wasm']);
run(bindgen, ['--target', 'web', '--out-dir', 'crates/wpi-wasm/pkg', '--out-name', 'wpi_wasm', 'target/wasm32-unknown-unknown/release/wpi_wasm.wasm']);
