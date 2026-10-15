import { spawnSync } from 'node:child_process';
import { resolve, join } from 'node:path';
import { copyFileSync, cpSync, mkdirSync } from 'node:fs';
const root=resolve(import.meta.dirname,'..');
function run(file,args,cwd=root) {
  const result=spawnSync(process.execPath,[file,...args],{cwd,stdio:'inherit'});
  if (result.error) throw result.error;
  if (result.status!==0) process.exit(result.status??1);
}
run(join(root,'scripts/build-wasm.mjs'),[]);
run(join(root,'apps/ui/node_modules/typescript/bin/tsc'),['-b'],join(root,'apps/ui'));
run(join(root,'apps/ui/node_modules/vite/bin/vite.js'),['build'],join(root,'apps/ui'));
const dist = join(root, 'apps/ui/dist');
const licenses = join(dist, 'licenses');
mkdirSync(licenses, { recursive: true });
copyFileSync(join(root, 'LICENSE'), join(dist, 'LICENSE'));
copyFileSync(join(root, 'THIRD_PARTY_NOTICES.md'), join(dist, 'THIRD_PARTY_NOTICES.md'));
cpSync(join(root, 'resources/licenses'), licenses, { recursive: true });
copyFileSync(join(root, 'resources/upstream/LICENSE'), join(licenses, 'WPinternals-MIT'));
for (const license of ['MIT', 'APACHE']) {
  copyFileSync(join(root, `vendor/ntfs/LICENSE-${license}`), join(licenses, `ntfs-${license}`));
}
