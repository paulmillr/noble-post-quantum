import { readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
export const __dirname = dirname(fileURLToPath(import.meta.url));

const readGZ = (path) => {
  let data = readFileSync(`${__dirname}/${path}`);
  if (path.endsWith('.gz')) data = gunzipSync(data);
  return Buffer.from(data).toString('utf8');
};

export const readKAT = (name, firstField) => {
  const data = readGZ(`vectors/KAT/${name}`);
  let cases;
  if (!firstField) cases = data.split(/\n\n/gm);
  else {
    cases = data.split(firstField);
    if (cases[0] === '') cases.shift();
    if (cases[cases.length - 1] === '') cases.pop();
    cases = cases.map((i) => `${firstField}${i}`);
  }
  const res = [];
  let i = 0;
  for (const c of cases) {
    if (c.startsWith('#') || !c) continue;
    const lines = c.split('\n');
    const out = {};
    for (const l of lines) {
      const [k, v] = l.split('=');
      if (!k) continue;
      out[k.trim()] = v.trim();
    }
    res.push(out);
  }
  return res;
};

export const jsonGZ = (path) => JSON.parse(readGZ(path));
