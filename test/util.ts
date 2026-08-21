import { readFileSync } from 'node:fs';
import { dirname, join as pjoin } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import {
  jsonGZ as readJsonGZ,
  jsonGZGroups as readJsonGZGroups,
} from './vectors/acvp-vectors/utils.js';
export const __dirname = dirname(fileURLToPath(import.meta.url));

function readGZ(path) {
  let data = readFileSync(pjoin(__dirname, path));
  if (path.endsWith('.gz')) data = gunzipSync(data);
  return new TextDecoder().decode(data);
}

export function jsonGZ(path) {
  return readJsonGZ(pjoin(__dirname, path));
}

export function jsonGZGroups(path) {
  return readJsonGZGroups(pjoin(__dirname, path));
}

export function readKAT(name, firstField) {
  const data = readGZ(pjoin('vectors', 'KAT', name));
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
}
