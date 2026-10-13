import { spawnSync } from 'node:child_process';
import { resolve, join } from 'node:path';
const root=resolve(import.meta.dirname,'..');
function run(file,args,cwd=root) {
  const result=spawnSync(process.execPath,[file,...args],{cwd,stdio:'inherit'});
  if (result.error) throw result.error;
  if (result.status!==0) process.exit(result.status??1);
}
run(join(root,'scripts/build-wasm.mjs'),[]);
run(join(root,'apps/ui/node_modules/typescript/bin/tsc'),['-b'],join(root,'apps/ui'));
run(join(root,'apps/ui/node_modules/vite/bin/vite.js'),['build'],join(root,'apps/ui'));
