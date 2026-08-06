/**
 * Re-prints the SLH-DSA table from README "Speed" section.
 *
 * Usage:
 *   node benchmark/slh-dsa.ts            # all 12 variants (slow: several minutes)
 *   node benchmark/slh-dsa.ts 128f 192f  # only variants matching the given substrings
 *
 * Slow ('s') variants take seconds per signature, so they are measured with a
 * single sample; fast operations are sampled until MAX_RUN_TIME is exhausted.
 */
import { utils } from '@paulmillr/jsbt/benchmark.js';
import * as slh from '../src/slh-dsa.ts';
import { randomBytes } from '../src/utils.ts';

const MAX_RUN_TIME = 10n ** 9n; // 1 second per measurement, in nanoseconds

// Same order as README
const VARIANTS = [
  ['sha2_128f', slh.slh_dsa_sha2_128f],
  ['shake_128f', slh.slh_dsa_shake_128f],
  ['sha2_192f', slh.slh_dsa_sha2_192f],
  ['shake_192f', slh.slh_dsa_shake_192f],
  ['sha2_256f', slh.slh_dsa_sha2_256f],
  ['shake_256f', slh.slh_dsa_shake_256f],
  ['sha2_128s', slh.slh_dsa_sha2_128s],
  ['shake_128s', slh.slh_dsa_shake_128s],
  ['sha2_192s', slh.slh_dsa_sha2_192s],
  ['shake_192s', slh.slh_dsa_shake_192s],
  ['sha2_256s', slh.slh_dsa_sha2_256s],
  ['shake_256s', slh.slh_dsa_shake_256s],
] as const;

function formatMs(nanoseconds: bigint): string {
  const ms = Number(nanoseconds) / 1e6;
  const rounded = ms >= 10 ? Math.round(ms) : Math.round(ms * 10) / 10;
  return `${rounded}ms`;
}

async function measure(fn: () => unknown): Promise<string> {
  const { stats } = await utils.benchmarkRaw(fn, MAX_RUN_TIME);
  return formatMs(stats.mean);
}

function printTable(rows: string[][]) {
  const header = ['', 'keygen', 'sign', 'verify'];
  const all = [header, ...rows];
  const widths = header.map((_, i) => Math.max(...all.map((row) => row[i].length)));
  const line = (cells: string[]) =>
    '| ' + cells.map((cell, i) => cell.padEnd(widths[i])).join(' | ') + ' |';
  console.log(line(header));
  console.log(line(widths.map((w) => '-'.repeat(w))));
  for (const row of rows) console.log(line(row));
}

(async () => {
  const filters = process.argv.slice(2);
  const selected = VARIANTS.filter(
    ([name]) => !filters.length || filters.some((f) => name.includes(f))
  );
  if (!selected.length) throw new Error('No SLH-DSA variant matches ' + filters.join(', '));

  const msg = randomBytes(32);
  const rows: string[][] = [];
  for (const [name, lib] of selected) {
    console.error(`# ${name}`); // progress goes to stderr, table to stdout
    const { publicKey, secretKey } = lib.keygen();
    const signature = lib.sign(msg, secretKey);
    const keygen = await measure(() => lib.keygen());
    const sign = await measure(() => lib.sign(msg, secretKey));
    const verify = await measure(() => lib.verify(signature, msg, publicKey));
    rows.push([name, keygen, sign, verify]);
  }
  printTable(rows);
})();
