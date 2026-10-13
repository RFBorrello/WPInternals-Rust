import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { basename } from 'node:path';
for (const file of process.argv.slice(2)) {
  const hash=createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  console.log(`${hash.digest('hex')}  ${basename(file)}`);
}
