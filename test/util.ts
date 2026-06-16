import { createReadStream, readFileSync } from 'node:fs';
import { dirname, join as pjoin } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createGunzip, gunzipSync } from 'node:zlib';
export const __dirname = dirname(fileURLToPath(import.meta.url));

function readGZ(path) {
  let data = readFileSync(pjoin(__dirname, path));
  if (path.endsWith('.gz')) data = gunzipSync(data);
  return new TextDecoder().decode(data);
}

export function jsonGZ(path) {
  return JSON.parse(readGZ(path));
}

function textStream(path) {
  const stream = createReadStream(pjoin(__dirname, path));
  if (!path.endsWith('.gz')) return stream.setEncoding('utf8');
  return stream.pipe(createGunzip()).setEncoding('utf8');
}

export async function* jsonGZGroups(path) {
  const key = '"testGroups"';
  let buf = '';
  let inGroups = false;
  let inObject = false;
  let inString = false;
  let escaped = false;
  let depth = 0;
  let obj = '';
  for await (const chunk of textStream(path)) {
    buf += chunk;
    while (buf.length) {
      if (!inGroups) {
        const keyStart = buf.indexOf(key);
        if (keyStart === -1) {
          buf = buf.slice(Math.max(0, buf.length - key.length));
          break;
        }
        const arrayStart = buf.indexOf('[', keyStart + key.length);
        if (arrayStart === -1) {
          buf = buf.slice(keyStart);
          break;
        }
        buf = buf.slice(arrayStart + 1);
        inGroups = true;
      }
      if (!inObject) {
        const next = buf.search(/[^\s,]/);
        if (next === -1) {
          buf = '';
          break;
        }
        buf = buf.slice(next);
        if (buf[0] === ']') return;
        if (buf[0] !== '{') throw new Error(`expected JSON object in ${path}`);
        inObject = true;
        inString = false;
        escaped = false;
        depth = 0;
        obj = '';
      }
      let end = -1;
      for (let i = 0; i < buf.length; i++) {
        const c = buf[i];
        if (inString) {
          if (escaped) escaped = false;
          else if (c === '\\') escaped = true;
          else if (c === '"') inString = false;
          continue;
        }
        if (c === '"') inString = true;
        else if (c === '{') depth++;
        else if (c === '}') {
          depth--;
          if (depth === 0) {
            end = i + 1;
            break;
          }
        }
      }
      if (end === -1) {
        obj += buf;
        buf = '';
        break;
      }
      obj += buf.slice(0, end);
      buf = buf.slice(end);
      inObject = false;
      yield JSON.parse(obj);
    }
  }
  if (inGroups || inObject) throw new Error(`unexpected end of JSON stream in ${path}`);
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
