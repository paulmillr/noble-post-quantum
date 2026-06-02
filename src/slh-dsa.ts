/**
 * SLH-DSA: StateLess Hash-based Digital Signature Standard from
 * [FIPS-205](https://csrc.nist.gov/pubs/fips/205/ipd). A.k.a. Sphincs+ v3.1.
 *
 * There are many different kinds of SLH, but basically `sha2` / `shake` indicate internal hash,
 * `128` / `192` / `256` indicate security level, and `s` /`f` indicate trade-off (Small / Fast).
 *
 * Hashes function similarly to signatures. You hash a private key to get a public key,
 * which can be used to verify the private key. However, this only works once since
 * disclosing the pre-image invalidates the key.
 *
 * To address the "one-time" limitation, we can use a Merkle tree root hash:
 * h(h(h(0) || h(1)) || h(h(2) || h(3))))
 *
 * This allows us to have the same public key output from the hash, but disclosing one
 * path in the tree doesn't invalidate the others. By choosing a path related to the
 * message, we can "sign" it.
 *
 * Limitation: Only a fixed number of signatures can be made. For instance, a Merkle tree
 * with depth 8 allows 256 distinct messages. Using different trees for each node can
 * prevent forgeries, but the key will still degrade over time.
 *
 * WOTS: One-time signatures (can be forged if same key used twice).
 * FORS: Forest of Random Subsets
 *
 * Check out [official site](https://sphincs.org) & [repo](https://github.com/sphincs/sphincsplus).
 * @module
 */
/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { hmac } from '@awasm/noble/hmac.js';
import * as noble from '@awasm/noble/noble.js';
import { sha256, sha512, shake256 } from '@awasm/noble/stub.js';
import { copyFast, copyFast32, u32, type CHash, type HashState } from '@awasm/noble/utils.js';
import { bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js';
import { createView } from '@noble/hashes/utils.js';
import {
  abytes,
  checkHash,
  cleanBytes,
  copyBytes,
  EMPTY,
  equalBytes,
  getMask,
  getMessage,
  getMessagePrehash,
  randomBytes,
  splitCoder,
  validateSigOpts,
  validateVerOpts,
  vecCoder,
  type Signer,
  type SigOpts,
  type TArg,
  type TRet,
  type VerOpts,
} from './utils.ts';

// Install noble version to stubs for backward compatibility. Could be removed on next major release.
sha256.install(noble.sha256, { onlyMissing: true });
sha512.install(noble.sha512, { onlyMissing: true });
shake256.install(noble.shake256, { onlyMissing: true });

/**
 * * N: Security parameter (in bytes). W: Winternitz parameter
 * * H: Hypertree height. D: Hypertree layers
 * * K: FORS trees numbers. A: FORS trees height
 */
export type SphincsOpts = {
  /** Security parameter in bytes. */
  N: number;
  /** Winternitz parameter. */
  W: number;
  /** Total hypertree height. */
  H: number;
  /** Number of hypertree layers. */
  D: number;
  /** Number of FORS trees. */
  K: number;
  /** Height of each FORS tree. */
  A: number;
  /** Target security level in bits. */
  securityLevel: number;
};

/** Hash customization options for SLH-DSA context creation. */
export type SphincsHashOpts = {
  /** Whether to use the compressed-address variant from the standard. */
  isCompressed?: boolean;
  /** Factory that binds one parameter set to one per-key hash context generator. */
  getContext: GetContext;
};

/** Winternitz signature params. */
/**
 * Built-in SLH-DSA Table 2 subset keyed by strength/profile.
 * SHA2 and SHAKE pairs share the same numeric rows here, so the hash family is chosen separately.
 * `securityLevel` stores 128/192/256-bit strengths for `checkHash(...)`,
 * not Table 2's category labels 1/3/5.
 * Other Table 2 columns such as `m`, public-key bytes, and signature bytes
 * stay derived at the export layer.
 */
export const PARAMS: Record<string, SphincsOpts> = /* @__PURE__ */ (() =>
  Object.freeze({
    '128f': Object.freeze({ W: 16, N: 16, H: 66, D: 22, K: 33, A: 6, securityLevel: 128 }),
    '128s': Object.freeze({ W: 16, N: 16, H: 63, D: 7, K: 14, A: 12, securityLevel: 128 }),
    '192f': Object.freeze({ W: 16, N: 24, H: 66, D: 22, K: 33, A: 8, securityLevel: 192 }),
    '192s': Object.freeze({ W: 16, N: 24, H: 63, D: 7, K: 17, A: 14, securityLevel: 192 }),
    '256f': Object.freeze({ W: 16, N: 32, H: 68, D: 17, K: 35, A: 9, securityLevel: 256 }),
    '256s': Object.freeze({ W: 16, N: 32, H: 64, D: 8, K: 22, A: 14, securityLevel: 256 }),
  } as const))();

// FIPS 205 `ADRS.setTypeAndClear(...)` selectors. Local names shorten the spec labels
// (`WOTS_HASH` -> `WOTS`, `TREE` -> `HASHTREE`, `FORS_ROOTS` -> `FORSPK`), and `setAddr({ type })`
// below only writes the type word; callers still need to preserve or overwrite the trailing words.
const AddressType = {
  WOTS: 0,
  WOTSPK: 1,
  HASHTREE: 2,
  FORSTREE: 3,
  FORSPK: 4,
  WOTSPRF: 5,
  FORSPRF: 6,
} as const;

/** Address byte array of size `ADDR_BYTES`. */
export type ADRS = Uint8Array;
type AddrPatch = (msg: Uint8Array, pos: number, i: number, view: DataView) => void;
type WotsPatch = (hash: number) => AddrPatch;
type ParallelOut = Uint8Array[];
type HashPrefix = { bytes: Uint8Array; state?: TArg<HashState> };
/** Parameters for one batched WOTS tree walk using operation-owned scratch buffers. */
type WotsJob = {
  /** Base address copied into each lane before the patch callback writes lane-specific fields. */
  baseAddr: Uint8Array;
  /** Number of chain lanes, usually `leafCount * WOTS_LEN`. */
  count: number;
  /** Global leaf offset for the current subtree. */
  idxOffset: number;
  /** Leaf being signed; outside the subtree means keygen should not capture a WOTS signature. */
  leafIdx: number;
  /** Target chain step for each WOTS chain when a signature leaf is present. */
  steps: Uint32Array;
  /** Destination for the one WOTS signature captured from the target leaf. */
  sig: Uint8Array;
  /** One output view per XMSS leaf; these become the first reduction level input. */
  out: Uint8Array[];
  /** Writes lane-specific WOTS-PRF address fields into the packed PRF batch. */
  prfPatch: AddrPatch;
  /** Creates the patcher for a WOTS hash-chain step address. */
  hashPatch: WotsPatch;
  /** Writes lane-specific WOTSPK address fields for the public-key-to-leaf hash. */
  pkPatch: AddrPatch;
};

/** Hash and tweakable-hash callbacks bound to one SLH-DSA keypair context. */
export type Context = {
  /**
   * Derive a PRF output for one address.
   * @param addr - Address bytes.
   * @returns PRF output bytes.
   */
  PRFaddr: (addr: TArg<ADRS>) => TRet<Uint8Array>;
  /**
   * Derive the randomized message hash prefix.
   * @param skPRF - Secret PRF seed.
   * @param random - Per-signature randomness.
   * @param msg - Message bytes.
   * @returns PRF output bytes.
   */
  PRFmsg: (
    skPRF: TArg<Uint8Array>,
    random: TArg<Uint8Array>,
    msg: TArg<Uint8Array>
  ) => TRet<Uint8Array>;
  /**
   * Hash one randomized message transcript.
   * @param R - Randomized message prefix.
   * @param pk - Public key bytes.
   * @param m - Message bytes.
   * @param outLen - Output length in bytes.
   * @returns Transcript hash bytes.
   */
  Hmsg: (
    R: TArg<Uint8Array>,
    pk: TArg<Uint8Array>,
    m: TArg<Uint8Array>,
    outLen: number
  ) => TRet<Uint8Array>;
  /**
   * Tweakable hash over one input block.
   * @param input - Input block.
   * @param addr - Address bytes.
   * @param out - Optional destination for the `N`-byte output.
   * @returns Hash output bytes, aliasing `out` when a destination is provided.
   */
  thash1: (input: TArg<Uint8Array>, addr: TArg<ADRS>, out?: TArg<Uint8Array>) => TRet<Uint8Array>;
  /**
   * Tweakable hash over multiple input blocks.
   * @param blocks - Number of input blocks.
   * @param input - Concatenated input bytes.
   * @param addr - Address bytes.
   * @param out - Optional destination for the `N`-byte output.
   * @returns Hash output bytes, aliasing `out` when a destination is provided.
   */
  thashN: (
    blocks: number,
    input: TArg<Uint8Array>,
    addr: TArg<ADRS>,
    out?: TArg<Uint8Array>
  ) => TRet<Uint8Array>;
  /**
   * Batched multi-block tweakable hash for tree reductions.
   *
   * Each lane hashes `prefix || patched(baseAddr, lane) || input[lane]`, where each input lane is
   * `blocks * N` bytes. Callers pass slices of the operation pair buffer as `input` and may pass
   * output views into the same operation scratch, allowing one reduction level to feed the next
   * without materializing `Uint8Array[]` results elsewhere.
   *
   * Returned views are caller-owned when `out` is supplied; otherwise they are scratch-owned and
   * valid only until the next batched context call that reuses the same scratch shape.
   *
   * @param blocks - Number of `N`-byte input blocks per lane.
   * @param input - Flat input buffer with `blocks * N` bytes per lane.
   * @param baseAddr - Address template bytes copied into each packed lane before patching.
   * @param count - Number of lanes to hash.
   * @param patch - Per-lane mutator that writes the address words that vary by lane.
   * @param out - Optional one-view-per-lane output destinations.
   * @returns One hash output view per lane.
   */
  thashNFill: (
    blocks: number,
    input: TArg<Uint8Array>,
    baseAddr: TArg<Uint8Array>,
    count: number,
    patch: AddrPatch,
    out?: TArg<ParallelOut>
  ) => TRet<Uint8Array[]>;
  /**
   * Build the first FORS tree level without a temporary PRF buffer.
   *
   * The PRF stage writes into scratch input views for the same lane shape. The leaf stage then
   * repatches those lanes from `FORSPRF` addresses to `FORSTREE` addresses and hashes the PRF bytes
   * directly into `out`, which is normally the first reduction `pairBuf` view list. Selected PRF
   * values must be copied into the signature before another scratch call reuses the PRF views.
   *
   * @param baseAddr - Address template bytes copied into each FORS lane before patching.
   * @param count - Number of FORS leaf lanes.
   * @param prfPatch - Per-lane mutator for the `FORSPRF` address.
   * @param leafPatch - Per-lane mutator for the matching `FORSTREE` address.
   * @param out - One leaf-output destination per lane, usually views over `pairBuf`.
   * @returns Scratch-owned PRF views and leaf output views.
   */
  forsLeavesFill: (
    baseAddr: TArg<Uint8Array>,
    count: number,
    prfPatch: AddrPatch,
    leafPatch: AddrPatch,
    out: TArg<ParallelOut>
  ) => TRet<{ prfs: Uint8Array[]; leaves: Uint8Array[] }>;
  /**
   * Compute all WOTS+ chains for one XMSS tree in batched dependency steps.
   *
   * The job describes one tree walk. The context runs the PRF batch for every chain lane, advances
   * all chains step by step with `hash.parallel(...)`, copies only the target signature chain
   * values into `job.sig`, and writes each WOTS public key leaf into `job.out`. `job.out` is then
   * consumed immediately by the XMSS reduction code.
   *
   * @param job - Address patchers, target signature metadata, and output views for one WOTS tree.
   */
  wotsFill: (job: TArg<WotsJob>) => void;
  /** Wipe any buffered hash state for the current context. */
  clean: () => void;
};
/** Factory that creates a context generator for one SLH-DSA parameter set. */
export type GetContext = (
  opts: SphincsOpts
) => (pub_seed: TArg<Uint8Array>, sk_seed?: TArg<Uint8Array>, sign?: boolean) => TRet<Context>;

// Local FIPS 205 Algorithm 4 `base_2^b(...)` implementation. Bits are consumed in big-endian
// order within each input byte, and callers must provide at least `ceil(outLen * b / 8)` bytes;
// short inputs are not rejected and would zero-extend implicitly.
const base2b = (outLen: number, b: number) => {
  const mask = getMask(b);
  return (bytes: TArg<Uint8Array>): TRet<Uint32Array> => {
    const baseB = new Uint32Array(outLen);
    for (let out = 0, pos = 0, bits = 0, total = 0; out < outLen; out++) {
      while (bits < b) {
        total = (total << 8) | bytes[pos++];
        bits += 8;
      }
      bits -= b;
      baseB[out] = (total >>> bits) & mask;
    }
    return baseB as TRet<Uint32Array>;
  };
};

function getMaskBig(bits: number) {
  return (1n << BigInt(bits)) - 1n; // 4 -> 0b1111
}

/** Public SLH-DSA signer with prehash customization. */
export type SphincsSigner = Signer & {
  internal: TRet<Signer>;
  securityLevel: number;
  prehash: (hash: TArg<CHash>) => TRet<Signer>;
};

/** One parameter/hash instantiation of the public SLH-DSA API.
 * `keygen(seed)` is a deterministic 3N-byte library hook around the internal keygen flow,
 * and `getPublicKey(secretKey)` only extracts the embedded public key
 * instead of recomputing `PK.root`.
 */
function gen(opts: SphincsOpts, hashOpts_: TArg<SphincsHashOpts>): TRet<SphincsSigner> {
  const hashOpts = hashOpts_ as SphincsHashOpts;
  const { N, W, H, D, K, A, securityLevel: securityLevel } = opts;
  const getContext = hashOpts.getContext(opts);
  if (W !== 16) throw new Error('Unsupported Winternitz parameter');
  const WOTS_LOGW = 4;
  const WOTS_LEN1 = Math.floor((8 * N) / WOTS_LOGW);
  const WOTS_LEN2 = N <= 8 ? 2 : N <= 136 ? 3 : 4;
  const TREE_HEIGHT = Math.floor(H / D);
  const WOTS_LEN = WOTS_LEN1 + WOTS_LEN2;

  let ADDR_BYTES = 22;
  let OFFSET_LAYER = 0;
  let OFFSET_TREE = 1;
  let OFFSET_TYPE = 9;
  let OFFSET_KP_ADDR2 = 12;
  let OFFSET_KP_ADDR1 = 13;
  let OFFSET_CHAIN_ADDR = 17;
  let OFFSET_TREE_INDEX = 18;
  let OFFSET_HASH_ADDR = 21;
  if (!hashOpts.isCompressed) {
    ADDR_BYTES = 32;
    OFFSET_LAYER += 3;
    OFFSET_TREE += 7;
    OFFSET_TYPE += 10;
    OFFSET_KP_ADDR2 += 10;
    OFFSET_KP_ADDR1 += 10;
    OFFSET_CHAIN_ADDR += 10;
    OFFSET_TREE_INDEX += 10;
    OFFSET_HASH_ADDR += 10;
  }
  // Mutates and returns `addr` in place. For the built-in parameter sets, the layer / chain /
  // hash / height / keypair values fit in the low byte(s), and the tree value fits in 64 bits,
  // so the untouched leading bytes in the wider FIPS 205 ADRS / ADRS_c fields stay zero.
  // `height` / `chain` and `index` / `hash` share the same spec words, so callers must use the
  // address-type-specific combinations instead of mixing both meanings in one call.
  const setAddr = (
    opts: TArg<{
      type?: (typeof AddressType)[keyof typeof AddressType];
      height?: number;
      tree?: bigint;
      index?: number;
      layer?: number;
      chain?: number;
      hash?: number;
      keypair?: number;
      subtreeAddr?: ADRS;
      keypairAddr?: ADRS;
    }>,
    addr: TArg<ADRS> = new Uint8Array(ADDR_BYTES)
  ) => {
    const { type, height, tree, layer, index, chain, hash, keypair } = opts;
    const { subtreeAddr, keypairAddr } = opts;
    const v = createView(addr);

    if (height !== undefined) addr[OFFSET_CHAIN_ADDR] = height;
    if (layer !== undefined) addr[OFFSET_LAYER] = layer;
    if (type !== undefined) addr[OFFSET_TYPE] = type;
    if (chain !== undefined) addr[OFFSET_CHAIN_ADDR] = chain;
    if (hash !== undefined) addr[OFFSET_HASH_ADDR] = hash;
    if (index !== undefined) v.setUint32(OFFSET_TREE_INDEX, index, false);
    if (subtreeAddr) copyFast(addr, 0, subtreeAddr, 0, OFFSET_TREE + 8);
    if (tree !== undefined) v.setBigUint64(OFFSET_TREE, tree, false);
    if (keypair !== undefined) {
      addr[OFFSET_KP_ADDR1] = keypair;
      if (TREE_HEIGHT > 8) addr[OFFSET_KP_ADDR2] = keypair >>> 8;
    }
    if (keypairAddr) {
      copyFast(addr, 0, keypairAddr, 0, OFFSET_TREE + 8);
      addr[OFFSET_KP_ADDR1] = keypairAddr[OFFSET_KP_ADDR1];
      if (TREE_HEIGHT > 8) addr[OFFSET_KP_ADDR2] = keypairAddr[OFFSET_KP_ADDR2];
    }
    return addr;
  };
  const writeKeypair = (addr: Uint8Array, pos: number, keypair: number) => {
    addr[pos + OFFSET_KP_ADDR1] = keypair;
    if (TREE_HEIGHT > 8) addr[pos + OFFSET_KP_ADDR2] = keypair >>> 8;
  };
  const writeIndexSlot = (
    dst: Uint8Array,
    pos: number,
    type: (typeof AddressType)[keyof typeof AddressType],
    index: number,
    height: number | undefined,
    view: DataView
  ) => {
    dst[pos + OFFSET_TYPE] = type;
    if (height !== undefined) dst[pos + OFFSET_CHAIN_ADDR] = height;
    view.setUint32(pos + OFFSET_TREE_INDEX, index, false);
  };
  const writeWotsSlot = (
    dst: Uint8Array,
    pos: number,
    keypair: number,
    type: (typeof AddressType)[keyof typeof AddressType],
    chain: number,
    hash: number
  ) => {
    writeKeypair(dst, pos, keypair);
    dst[pos + OFFSET_TYPE] = type;
    dst[pos + OFFSET_CHAIN_ADDR] = chain;
    dst[pos + OFFSET_HASH_ADDR] = hash;
  };
  const isAligned4 = (buf: Uint8Array) => (buf.byteOffset & 3) === 0;

  const chainCoder = base2b(WOTS_LEN2, WOTS_LOGW);
  const chainLengths = (msg: TArg<Uint8Array>) => {
    const W1 = base2b(WOTS_LEN1, WOTS_LOGW)(msg);
    let csum = 0;
    for (let i = 0; i < W1.length; i++) csum += W - 1 - W1[i]; // ▷ Compute checksum
    // csum ← csum ≪ ((8 − ((len2 · lg(w)) mod 8)) mod 8
    csum <<= (8 - ((WOTS_LEN2 * WOTS_LOGW) % 8)) % 8;
    // Checksum to base(LOG_W)
    const W2 = chainCoder(numberToBytesBE(csum, Math.ceil((WOTS_LEN2 * WOTS_LOGW) / 8)));
    // W1 || W2 (concatBytes cannot concat TypedArrays)
    const lengths = new Uint32Array(WOTS_LEN);
    lengths.set(W1);
    lengths.set(W2, W1.length);
    return lengths;
  };
  const messageToIndices = base2b(K, A);

  const TREE_BITS = TREE_HEIGHT * (D - 1);
  const LEAF_BITS = TREE_HEIGHT;
  const hashMsgCoder = splitCoder(
    'hashedMessage',
    Math.ceil((A * K) / 8),
    Math.ceil(TREE_BITS / 8),
    Math.ceil(TREE_HEIGHT / 8)
  );
  // `pkSeed` is the full public key byte string `PK.seed || PK.root`; after splitting `Hmsg`,
  // mask away any spare high bits so `idx_tree` / `idx_leaf` match the spec's final mod-2^k steps.
  const hashMessage = (
    R: TArg<Uint8Array>,
    pkSeed: TArg<Uint8Array>,
    msg: TArg<Uint8Array>,
    context: TArg<Context>
  ) => {
    const rawContext = context as Context;
    // digest ← Hmsg(R, PK.seed, PK.root, M)
    const digest = rawContext.Hmsg(R, pkSeed, msg, hashMsgCoder.bytesLen);
    const [md, tmpIdxTree, tmpIdxLeaf] = hashMsgCoder.decode(digest);
    const tree = bytesToNumberBE(tmpIdxTree) & getMaskBig(TREE_BITS);
    const leafIdx = Number(bytesToNumberBE(tmpIdxLeaf)) & getMask(LEAF_BITS);
    return { tree, leafIdx, md };
  };

  const splitViews = (buf: Uint8Array, count: number, len: number) => {
    const out = new Array<Uint8Array>(count);
    for (let i = 0; i < count; i++) out[i] = buf.subarray(i * len, (i + 1) * len);
    return out;
  };
  // Reused across hypertree layers; rebuilding these views dominates smaller awasm hash batches.
  const createWotsBatch = (reducePairs = (1 << TREE_HEIGHT) >>> 1) => {
    const leafCount = 1 << TREE_HEIGHT;
    const pairBuf = new Uint8Array(reducePairs * 2 * N);
    const leafViews = splitViews(pairBuf, leafCount, N);
    return {
      leafViews,
      pairBuf,
      clean: () => {
        cleanBytes(pairBuf);
        leafViews.fill(EMPTY);
      },
    };
  };
  const createSignBatch = () => {
    const forsLeafCount = 1 << A;
    const total = K * forsLeafCount;
    const reducePairs = Math.max((1 << TREE_HEIGHT) >>> 1, total >>> 1);
    const wots = createWotsBatch(reducePairs);
    const forsLeafViews = splitViews(wots.pairBuf, total, N);
    const idxs = new Uint32Array(K);
    const clean = wots.clean;
    return {
      ...wots,
      forsLeafViews,
      idxs,
      clean: () => {
        clean();
        cleanBytes(idxs);
        forsLeafViews.fill(EMPTY);
      },
    };
  };
  // Fuse `xmss_sign` with the subtree-root computation needed by `ht_sign`, so one tree walk
  // yields both the WOTS/auth-path signature and the root that the next hypertree layer signs.
  const merkleSign = (
    context: TArg<Context>,
    wotsAddr: TArg<ADRS>,
    treeAddr: TArg<ADRS>,
    leafIdx: number,
    prevRoot: TArg<Uint8Array>,
    batch: ReturnType<typeof createWotsBatch>
  ): TRet<{ root: Uint8Array; sigWots: Uint8Array; sigAuth: Uint8Array }> => {
    setAddr({ type: AddressType.HASHTREE }, treeAddr);
    const wotsSig = new Uint8Array(WOTS_LEN * N);
    const wotsSteps = chainLengths(prevRoot);
    const leafAddr = setAddr({ subtreeAddr: wotsAddr });
    const rawContext = context as Context;
    const leafCount = 1 << TREE_HEIGHT;
    const work = batch;
    const { leafViews } = work;
    const chainCount = leafCount * WOTS_LEN;
    const job: WotsJob = {
      baseAddr: leafAddr,
      count: chainCount,
      idxOffset: 0,
      leafIdx,
      steps: wotsSteps,
      sig: wotsSig,
      out: leafViews,
      prfPatch: (msg, pos, i) => {
        const leaf = (i / WOTS_LEN) | 0;
        writeWotsSlot(msg, pos, leaf, AddressType.WOTSPRF, i - leaf * WOTS_LEN, 0);
      },
      hashPatch: (k) => (msg, pos, i) => {
        const leaf = (i / WOTS_LEN) | 0;
        writeWotsSlot(msg, pos, leaf, AddressType.WOTS, i - leaf * WOTS_LEN, k);
      },
      pkPatch: (msg, pos, i) => {
        msg[pos + OFFSET_TYPE] = AddressType.WOTSPK;
        writeKeypair(msg, pos, i);
      },
    };
    rawContext.wotsFill(job);
    let nodes = leafViews;
    const authPath = new Uint8Array(TREE_HEIGHT * N);
    const needAuth = leafIdx < 1 << TREE_HEIGHT;
    for (let h = 0, idx = needAuth ? leafIdx : 0; h < TREE_HEIGHT; h++, idx >>>= 1) {
      if (needAuth) copyFast(authPath, h * N, nodes[idx ^ 1], 0, N);
      const pairs = nodes.length >>> 1;
      // Pack one tree level as parallel lanes: lane i is left-node || right-node.
      // Level 0 already lives in `pairBuf`, so only higher levels need repacking.
      const packed = work.pairBuf.subarray(0, pairs * 2 * N);
      if (h !== 0)
        for (let i = 0; i < nodes.length; i += 2) {
          const pos = (i >>> 1) * 2 * N;
          copyFast(packed, pos, nodes[i], 0, N);
          copyFast(packed, pos + N, nodes[i + 1], 0, N);
        }
      nodes = rawContext.thashNFill(2, packed, treeAddr, pairs, (msg, pos, i, view) =>
        writeIndexSlot(msg, pos, AddressType.HASHTREE, i, h + 1, view)
      );
    }
    const root = nodes[0];
    cleanBytes(wotsSteps, leafAddr);
    return {
      root,
      sigWots: wotsSig,
      sigAuth: authPath,
    } as TRet<{ root: Uint8Array; sigWots: Uint8Array; sigAuth: Uint8Array }>;
  };

  const computeRoot = (
    leaf: TArg<Uint8Array>,
    leafIdx: number,
    idxOffset: number,
    authPath: TArg<Uint8Array>,
    treeHeight: number,
    context: TArg<Context>,
    addr: TArg<ADRS>,
    out?: TArg<Uint8Array>,
    work?: TArg<Uint8Array>
  ) => {
    const rawContext = context as Context;
    const buffer = work ? (work as Uint8Array).subarray(0, 2 * N) : new Uint8Array(2 * N);
    const b0 = buffer.subarray(0, N);
    const b1 = buffer.subarray(N, 2 * N);
    const words = N >>> 2;
    const buffer32 = u32(buffer);
    const leaf32 = isAligned4(leaf as Uint8Array) ? u32(leaf) : undefined;
    const authPath32 = isAligned4(authPath as Uint8Array) ? u32(authPath) : undefined;
    const copyLeaf = (pos: number) => {
      if (leaf32) copyFast32(buffer32, pos, leaf32, 0, words);
      else copyFast(buffer, pos * 4, leaf as Uint8Array, 0, N);
    };
    const copyAuth = (pos: number, authPos: number) => {
      if (authPath32) copyFast32(buffer32, pos, authPath32, authPos, words);
      else copyFast(buffer, pos * 4, authPath as Uint8Array, authPos * 4, N);
    };
    // Algorithm 11 hashes `node || AUTH[k]` for even nodes and `AUTH[k] || node` for odd ones,
    // so reuse one `2N` buffer and just swap which half receives the sibling at each level.
    // `idxOffset` carries the subtree base for the shared FORS path, so `leafIdx + idxOffset`
    // tracks the same tree-global index updates that Algorithms 11 and 17 apply to ADRS.
    // First iter
    if ((leafIdx & 1) !== 0) {
      copyLeaf(words);
      copyAuth(0, 0);
    } else {
      copyLeaf(0);
      copyAuth(words, 0);
    }
    leafIdx >>>= 1;
    idxOffset >>>= 1;
    // Rest
    for (let i = 0; i < treeHeight - 1; i++, leafIdx >>= 1, idxOffset >>= 1) {
      setAddr({ height: i + 1, index: leafIdx + idxOffset }, addr);
      const authPos = (i + 1) * words;
      if ((leafIdx & 1) !== 0) {
        rawContext.thashN(2, buffer, addr, b1);
        copyAuth(0, authPos);
      } else {
        rawContext.thashN(2, buffer, addr, b0);
        copyAuth(words, authPos);
      }
    }
    // Root
    setAddr({ height: treeHeight, index: leafIdx + idxOffset }, addr);
    return rawContext.thashN(2, buffer, addr, out);
  };

  const seedCoder = splitCoder('seed', N, N, N);
  const publicCoder = splitCoder('publicKey', N, N);
  const secretCoder = splitCoder('secretKey', N, N, publicCoder.bytesLen);
  const forsCoder = vecCoder(splitCoder('fors', N, N * A), K);
  const wotsCoder = vecCoder(splitCoder('wots', WOTS_LEN * N, TREE_HEIGHT * N), D);
  const sigCoder = splitCoder('signature', N, forsCoder, wotsCoder); // random || fors || wots
  const internal: TRet<Signer> = Object.freeze({
    info: Object.freeze({ type: 'internal-slh-dsa' }),
    lengths: Object.freeze({
      publicKey: publicCoder.bytesLen,
      secretKey: secretCoder.bytesLen,
      signature: sigCoder.bytesLen,
      seed: seedCoder.bytesLen,
      signRand: N,
    }),
    keygen(seed?: TArg<Uint8Array>) {
      if (seed !== undefined) abytes(seed, seedCoder.bytesLen, 'seed');
      seed = seed === undefined ? randomBytes(seedCoder.bytesLen) : copyBytes(seed);
      // Set SK.seed, SK.prf, and PK.seed to random n-byte
      const [secretSeed, secretPRF, publicSeed] = seedCoder.decode(seed);
      const context = getContext(publicSeed, secretSeed);
      const batch = createWotsBatch();
      try {
        // ADRS.setLayerAddress(d − 1)
        const topTreeAddr = setAddr({ layer: D - 1 });
        const wotsAddr = setAddr({ layer: D - 1 });
        //PK.root ←_xmss node(SK.seed, 0, h′, PK.seed, ADRS)
        const { root, sigWots, sigAuth } = merkleSign(
          context,
          wotsAddr,
          topTreeAddr,
          ~0 >>> 0,
          new Uint8Array(N),
          batch
        );
        const publicKey = publicCoder.encode([publicSeed, root]);
        const secretKey = secretCoder.encode([secretSeed, secretPRF, publicKey]);
        cleanBytes(secretSeed, secretPRF, root, sigWots, sigAuth, wotsAddr, topTreeAddr);
        return {
          publicKey: publicKey as TRet<Uint8Array>,
          secretKey: secretKey as TRet<Uint8Array>,
        };
      } finally {
        batch.clean();
        context.clean();
      }
    },
    getPublicKey: (secretKey: TArg<Uint8Array>): TRet<Uint8Array> => {
      const [_skSeed, _skPRF, pk] = secretCoder.decode(secretKey);
      return Uint8Array.from(pk) as TRet<Uint8Array>;
    },
    sign: (msg: TArg<Uint8Array>, sk: TArg<Uint8Array>, opts: TArg<SigOpts> = {}) => {
      validateSigOpts(opts);
      let { extraEntropy: random } = opts;
      const [skSeed, skPRF, pk] = secretCoder.decode(sk); // todo: fix
      const [pkSeed, _] = publicCoder.decode(pk);
      // Set opt_rand to either PK.seed or to a random n-byte string
      if (random === false) random = copyBytes(pkSeed);
      else if (random === undefined) random = randomBytes(N);
      else random = copyBytes(random);
      abytes(random, N);
      const context = getContext(pkSeed, skSeed, true);
      let R: Uint8Array | undefined;
      let treeAddr: Uint8Array | undefined;
      let wotsAddr: Uint8Array | undefined;
      let forsLeaf: Uint8Array | undefined;
      let forsPkAddr: Uint8Array | undefined;
      let indices: Uint32Array | undefined;
      let roots: Uint8Array[] | undefined;
      let batch: ReturnType<typeof createSignBatch> | undefined;
      try {
        // Generate randomizer
        R = context.PRFmsg(skPRF, random, msg) as Uint8Array; // R ← PRFmsg(SK.prf, opt_rand, M)
        let { tree, leafIdx, md } = hashMessage(R, pk, msg, context);
        // Create FORS signatures
        wotsAddr = setAddr({
          type: AddressType.WOTS,
          tree,
          keypair: leafIdx,
        });
        forsLeaf = setAddr({ keypairAddr: wotsAddr });
        indices = messageToIndices(md);
        batch = createSignBatch();
        let root: Uint8Array | undefined;
        let fors: [Uint8Array, Uint8Array][] | undefined;
        let wots: [Uint8Array, Uint8Array][] | undefined;
        const rawContext = context as Context;
        const leafCount = 1 << A;
        const total = K * leafCount;
        const addr = setAddr({ keypairAddr: wotsAddr }, forsLeaf);
        // First FORS level is PRF output followed by one-block thash, both over the same lane count.
        // `forsLeavesFill` writes leaves directly into the sign batch pair buffer.
        const { prfs, leaves } = rawContext.forsLeavesFill(
          addr,
          total,
          (buf, pos, lane, view) => {
            const tree = (lane / leafCount) | 0;
            const leaf = lane - tree * leafCount;
            writeIndexSlot(buf, pos, AddressType.FORSPRF, leaf + (tree << A), undefined, view);
          },
          (buf, pos, lane, view) => {
            const tree = (lane / leafCount) | 0;
            const leaf = lane - tree * leafCount;
            writeIndexSlot(buf, pos, AddressType.FORSTREE, leaf + (tree << A), undefined, view);
          },
          batch.forsLeafViews
        ) as { prfs: Uint8Array[]; leaves: Uint8Array[] };
        let nodes = leaves;
        fors = new Array<[Uint8Array, Uint8Array]>(K);
        batch.idxs.set(indices);
        for (let tree = 0; tree < K; tree++) {
          const authPath = new Uint8Array(A * N);
          fors[tree] = [copyBytes(prfs[tree * leafCount + indices[tree]]), authPath];
        }
        for (let h = 0, nodesPerTree = leafCount; h < A; h++, nodesPerTree >>>= 1) {
          const pairsPerTree = nodesPerTree >>> 1;
          const pairCount = K * pairsPerTree;
          for (let tree = 0; tree < K; tree++) {
            const nodeBase = tree * nodesPerTree;
            copyFast(fors[tree][1], h * N, nodes[nodeBase + (batch.idxs[tree] ^ 1)], 0, N);
            batch.idxs[tree] >>>= 1;
            if (h !== 0)
              for (let pair = 0; pair < pairsPerTree; pair++) {
                const out = tree * pairsPerTree + pair;
                const pos = out * 2 * N;
                copyFast(batch.pairBuf, pos, nodes[nodeBase + pair * 2], 0, N);
                copyFast(batch.pairBuf, pos + N, nodes[nodeBase + pair * 2 + 1], 0, N);
              }
          }
          nodes = rawContext.thashNFill(
            2,
            batch.pairBuf.subarray(0, pairCount * 2 * N),
            addr,
            pairCount,
            (buf, pos, lane, view) => {
              const tree = (lane / pairsPerTree) | 0;
              const pair = lane - tree * pairsPerTree;
              writeIndexSlot(
                buf,
                pos,
                AddressType.FORSTREE,
                pair + ((tree << A) >>> (h + 1)),
                h + 1,
                view
              );
            }
          ) as Uint8Array[];
        }
        roots = nodes as Uint8Array[];
        forsPkAddr = setAddr({
          type: AddressType.FORSPK,
          keypairAddr: wotsAddr,
        });
        root = context.thashN(
          K,
          new Uint8Array(nodes[0].buffer, nodes[0].byteOffset, K * N),
          forsPkAddr
        );
        let cleanRoot = true;
        // WOTS signatures
        treeAddr = setAddr({ type: AddressType.HASHTREE });
        wots = [];
        for (let i = 0; i < D; i++, tree >>= BigInt(TREE_HEIGHT)) {
          setAddr({ tree, layer: i }, treeAddr);
          setAddr({ subtreeAddr: treeAddr, keypair: leafIdx }, wotsAddr);
          const {
            sigWots,
            sigAuth,
            root: r,
          } = merkleSign(context, wotsAddr, treeAddr, leafIdx, root, batch);
          if (cleanRoot) cleanBytes(root);
          cleanRoot = false;
          root = r;
          wots.push([sigWots, sigAuth]);
          leafIdx = Number(tree & getMaskBig(TREE_HEIGHT));
        }
        const SIG = sigCoder.encode([R, fors, wots]);
        for (const [prf, auth] of fors) cleanBytes(prf, auth);
        for (const [sigWots, sigAuth] of wots) cleanBytes(sigWots, sigAuth);
        cleanBytes(root);
        return SIG as TRet<Uint8Array>;
      } finally {
        // Signing can throw after R/opt_rand exist; keep owned scratch wiping on the error path too.
        cleanBytes(random as Uint8Array);
        if (R) cleanBytes(R);
        if (treeAddr) cleanBytes(treeAddr);
        if (wotsAddr) cleanBytes(wotsAddr);
        if (forsLeaf) cleanBytes(forsLeaf);
        if (forsPkAddr) cleanBytes(forsPkAddr);
        if (indices) cleanBytes(indices);
        if (roots) cleanBytes(roots);
        if (batch) batch.clean();
        context.clean();
      }
    },
    verify: (sig: TArg<Uint8Array>, msg: TArg<Uint8Array>, publicKey: TArg<Uint8Array>) => {
      const [pkSeed, pubRoot] = publicCoder.decode(publicKey);
      const [random, forsVec, wotsVec] = sigCoder.decode(sig);
      const pk = publicKey;
      if (sig.length !== sigCoder.bytesLen) return false;
      const context = getContext(pkSeed);
      try {
        let { tree, leafIdx, md } = hashMessage(random, pk, msg, context);
        const wotsAddr = setAddr({
          type: AddressType.WOTS,
          tree,
          keypair: leafIdx,
        });
        // FORS signature
        const rootInput = new Uint8Array(K * N);
        const leafBuf = new Uint8Array(N);
        const nodeBuf = new Uint8Array(2 * N);
        const forsTreeAddr = setAddr({
          type: AddressType.FORSTREE,
          keypairAddr: wotsAddr,
        });
        const indices = messageToIndices(md);
        for (let i = 0; i < forsVec.length; i++) {
          const [prf, authPath] = forsVec[i];
          const idxOffset = i << A;
          setAddr({ height: 0, index: indices[i] + idxOffset }, forsTreeAddr);
          context.thash1(prf, forsTreeAddr, leafBuf);
          computeRoot(
            leafBuf,
            indices[i],
            idxOffset,
            authPath,
            A,
            context,
            forsTreeAddr,
            rootInput.subarray(i * N, (i + 1) * N),
            nodeBuf
          );
        }
        const forsPkAddr = setAddr({
          type: AddressType.FORSPK,
          keypairAddr: wotsAddr,
        });
        let root = context.thashN(K, rootInput, forsPkAddr); // root = thash()
        cleanBytes(rootInput);
        // WOTS signature
        const treeAddr = setAddr({ type: AddressType.HASHTREE });
        const wotsPkAddr = setAddr({ type: AddressType.WOTSPK });
        const wotsPk = new Uint8Array(WOTS_LEN * N);
        const wotsPkWords = u32(wotsPk);
        const wotsPkViews = splitViews(wotsPk, WOTS_LEN, N);
        const nWords = N >>> 2;
        for (let i = 0; i < wotsVec.length; i++, tree >>= BigInt(TREE_HEIGHT)) {
          const [wots, sigAuth] = wotsVec[i];
          const sigWords = isAligned4(wots) ? u32(wots) : undefined;
          setAddr({ tree, layer: i }, treeAddr);
          setAddr({ subtreeAddr: treeAddr, keypair: leafIdx }, wotsAddr);
          setAddr({ keypairAddr: wotsAddr }, wotsPkAddr);
          const lengths = chainLengths(root);
          for (let j = 0; j < WOTS_LEN; j++) {
            setAddr({ chain: j }, wotsAddr);
            const steps = W - 1 - lengths[j];
            const start = lengths[j];
            const out = wotsPkViews[j];
            if (sigWords) copyFast32(wotsPkWords, j * nWords, sigWords, j * nWords, nWords);
            else copyFast(wotsPk, j * N, wots, j * N, N);
            for (let k = start; k < start + steps && k < W; k++) {
              setAddr({ hash: k }, wotsAddr);
              context.thash1(out, wotsAddr, out);
            }
          }
          const leaf = context.thashN(WOTS_LEN, wotsPk, wotsPkAddr, leafBuf);
          root = computeRoot(
            leaf,
            leafIdx,
            0,
            sigAuth,
            TREE_HEIGHT,
            context,
            treeAddr,
            root,
            nodeBuf
          );
          leafIdx = Number(tree & getMaskBig(TREE_HEIGHT));
        }
        return equalBytes(root, pubRoot);
      } finally {
        context.clean();
      }
    },
  });
  return Object.freeze({
    info: Object.freeze({ type: 'slh-dsa' }),
    internal,
    securityLevel: securityLevel,
    lengths: internal.lengths,
    keygen: internal.keygen,
    getPublicKey: internal.getPublicKey,
    sign: (msg: TArg<Uint8Array>, secretKey: TArg<Uint8Array>, opts: TArg<SigOpts> = {}) => {
      validateSigOpts(opts);
      const M = getMessage(msg, opts.context);
      const res = internal.sign(M, secretKey, opts);
      cleanBytes(M);
      return res as TRet<Uint8Array>;
    },
    verify: (
      sig: TArg<Uint8Array>,
      msg: TArg<Uint8Array>,
      publicKey: TArg<Uint8Array>,
      opts: TArg<VerOpts> = {}
    ) => {
      validateVerOpts(opts);
      return internal.verify(sig, getMessage(msg, opts.context), publicKey);
    },
    prehash: (hash: TArg<CHash>): TRet<Signer> => {
      checkHash(hash as CHash, securityLevel);
      const rawHash = hash as CHash;
      return Object.freeze({
        info: Object.freeze({ type: 'hashslh-dsa' }),
        lengths: internal.lengths,
        keygen: internal.keygen,
        getPublicKey: internal.getPublicKey,
        sign: (msg: TArg<Uint8Array>, secretKey: TArg<Uint8Array>, opts: TArg<SigOpts> = {}) => {
          validateSigOpts(opts);
          const M = getMessagePrehash(rawHash, msg, opts.context);
          const res = internal.sign(M, secretKey, opts);
          cleanBytes(M);
          return res as TRet<Uint8Array>;
        },
        verify: (
          sig: TArg<Uint8Array>,
          msg: TArg<Uint8Array>,
          publicKey: TArg<Uint8Array>,
          opts: TArg<VerOpts> = {}
        ) => {
          validateVerOpts(opts);
          return internal.verify(sig, getMessagePrehash(rawHash, msg, opts.context), publicKey);
        },
      });
    },
  });
}

type ChunkEntry = {
  count: number;
  prefixLen: number;
  addrLen: number;
  inputLen: number;
  msgLen: number;
  msg: Uint8Array;
  first: Uint8Array;
  view: DataView;
  chunks: Uint8Array[];
  inputs: Uint8Array[];
  partLen?: number;
  parts: Uint8Array[];
};
type OutEntry = { count: number; buf: Uint8Array; out: Uint8Array[] };
type ScratchOpts = SphincsOpts & {
  WOTS_LEN: number;
  TREE_HEIGHT: number;
  addrLen: number;
  prefixLen: number;
  outLen: number;
  chains?: boolean;
  trees?: boolean;
  fors?: boolean;
};
/** Operation-scoped packed hash buffers and cached lane views for SLH parallel calls. */
type ParallelScratch = {
  /**
   * Return input-field views for a cached lane shape.
   *
   * These views point into the scratch message buffer after the prefix/address header. They are
   * used when a hash output should become the next call's input, for example FORS PRF bytes that
   * are immediately rehashed as FORS leaves. The views are scratch-owned and overwritten by later
   * calls using the same shape.
   *
   * @param count - Number of lanes in the cached shape.
   * @param inputLen - Input bytes per lane.
   * @returns One mutable input view per lane.
   */
  inputs: (count: number, inputLen: number) => Uint8Array[];
  /**
   * Return fixed-size pieces inside each lane input field.
   *
   * WOTS public-key-to-leaf hashing needs one lane per leaf, where the lane input is
   * `WOTS_LEN * N` bytes. This method exposes that input as `WOTS_LEN` adjacent `N`-byte pieces so
   * earlier chain hashes can write directly into the future WOTSPK lane input.
   *
   * @param count - Number of lanes in the cached shape.
   * @param inputLen - Input bytes per lane.
   * @param partLen - Size of each returned piece.
   * @returns Input-piece views ordered by lane, then part.
   */
  parts: (count: number, inputLen: number, partLen: number) => Uint8Array[];
  /**
   * Return reusable output views for a cached lane count.
   *
   * This is used by the SHAKE WOTS path, where keeping the chain state in a flat output buffer is
   * faster than writing strided chain outputs directly into future WOTSPK input lanes.
   *
   * @param count - Number of output lanes.
   * @returns The backing output buffer and one `outLen`-byte view per lane.
   */
  output: (count: number) => OutEntry;
  /**
   * Fill a complete packed `hash.parallel` message batch and run it.
   *
   * Lane `i` is `prefix || patched(baseAddr, i) || input[i]`. When `inputStride` is zero, every
   * lane reuses the first `inputLen` bytes from `input`; otherwise lane `i` reads from
   * `input.subarray(i * inputStride, i * inputStride + inputLen)`. Passing `out` writes results
   * directly into caller-provided lane views.
   *
   * @param count - Number of lanes.
   * @param prefix - Per-lane bytes before the address, empty when `prefixState` supplies them.
   * @param baseAddr - Address template copied into each lane.
   * @param patch - Per-lane address mutator.
   * @param input - Shared or strided source input bytes.
   * @param inputLen - Number of input bytes per lane.
   * @param inputStride - Distance between lane inputs, or zero to reuse one input.
   * @param out - Optional one-view-per-lane output destinations.
   * @param prefixState - Optional backend prefix state matching `prefix`.
   * @returns One hash output view per lane.
   */
  direct: (
    count: number,
    prefix: Uint8Array,
    baseAddr: Uint8Array,
    patch: AddrPatch,
    input: Uint8Array,
    inputLen: number,
    inputStride: number,
    out?: TArg<ParallelOut>,
    prefixState?: TArg<HashState>
  ) => TRet<Uint8Array[]>;
  /**
   * Fill only the prefix/address header for lanes whose input bytes are already in scratch.
   *
   * WOTS chain batching writes final chain outputs into the future WOTSPK input area before the
   * public-key-to-leaf hash runs. `header()` completes those lanes by writing `prefix` and patched
   * addresses, then hashes the already-populated input fields.
   *
   * @param count - Number of lanes.
   * @param prefix - Per-lane bytes before the address, empty when `prefixState` supplies them.
   * @param baseAddr - Address template copied into each lane.
   * @param patch - Per-lane address mutator.
   * @param inputLen - Number of existing input bytes per lane.
   * @param out - Optional one-view-per-lane output destinations.
   * @param prefixState - Optional backend prefix state matching `prefix`.
   * @returns One hash output view per lane.
   */
  header: (
    count: number,
    prefix: Uint8Array,
    baseAddr: Uint8Array,
    patch: AddrPatch,
    inputLen: number,
    out?: TArg<ParallelOut>,
    prefixState?: TArg<HashState>
  ) => TRet<Uint8Array[]>;
  /**
   * Repatch addresses for lanes whose input bytes are already in scratch, then run the batch.
   *
   * This is the cheap dependency-step path for WOTS and FORS: prior hash outputs already sit in the
   * lane input fields, so only the address words that encode the next hash step or tree type need
   * to change before the next `hash.parallel(...)` call.
   *
   * @param count - Number of lanes.
   * @param inputLen - Number of existing input bytes per lane.
   * @param patch - Per-lane address mutator.
   * @param out - Optional one-view-per-lane output destinations.
   * @param prefixState - Optional backend prefix state for the hash.
   * @returns One hash output view per lane.
   */
  patch: (
    count: number,
    inputLen: number,
    patch: AddrPatch,
    out?: TArg<ParallelOut>,
    prefixState?: TArg<HashState>
  ) => TRet<Uint8Array[]>;
  /** Wipe the scratch backing buffer; cached views are invalid after this operation context ends. */
  clean: () => void;
};
/**
 * Create fixed packed-message scratch for the SLH shapes selected by `opts`.
 *
 * The scratch owns one message buffer split into shape-specific lanes plus one reusable output
 * buffer per lane count. It does not grow or allocate fallback shapes after construction; a missing
 * shape is a bug in the caller's plan.
 */
const createParallelScratch = (hash: TArg<CHash>, opts: ScratchOpts): ParallelScratch => {
  const rawHash = hash as CHash;
  const { N, WOTS_LEN, TREE_HEIGHT, K, A, addrLen, prefixLen, outLen } = opts;
  const leafCount = 1 << TREE_HEIGHT;
  const forsLeafCount = 1 << A;
  const eachShape = (
    add: (count: number, inputLen: number, partLen?: number, group?: number) => void
  ) => {
    if (opts.chains) {
      add(leafCount * WOTS_LEN, N); // WOTS PRF/thash1 chains
      if (opts.fors) add(K * forsLeafCount, N); // FORS PRF/thash1 leaves
    }
    if (opts.trees) {
      add(leafCount, WOTS_LEN * N, N, 1); // WOTS public-key-to-leaf thash
      for (let pairs = leafCount >>> 1; pairs > 0; pairs >>>= 1) add(pairs, 2 * N);
      if (opts.fors)
        for (let pairs = forsLeafCount >>> 1; pairs > 0; pairs >>>= 1) add(K * pairs, 2 * N);
    }
  };
  // Only WOTS chain input and WOTSPK input must be live together; other shapes reuse group 0.
  const groupBytes: number[] = [];
  let outCount = 0;
  eachShape((count, inputLen, _partLen, group = 0) => {
    groupBytes[group] = Math.max(groupBytes[group] || 0, count * (prefixLen + addrLen + inputLen));
    outCount = Math.max(outCount, count);
  });
  let msgBytes = 0;
  const groupPos = new Array<number>(groupBytes.length);
  for (let i = 0; i < groupBytes.length; i++) {
    groupPos[i] = msgBytes;
    msgBytes += groupBytes[i] || 0;
  }
  const buf = new Uint8Array(msgBytes + outCount * outLen);
  const out = buf.subarray(msgBytes);
  const chunks: ChunkEntry[] = [];
  const outs: OutEntry[] = [];
  const outCounts = new Set<number>();
  const seen = new Set<string>();
  eachShape((count, inputLen, partLen, group = 0) => {
    const key = `${count}:${prefixLen}:${addrLen}:${inputLen}`;
    if (seen.has(key)) return;
    seen.add(key);
    const msgLen = prefixLen + addrLen + inputLen;
    const inputPos = prefixLen + addrLen;
    const off = groupPos[group];
    const msg = buf.subarray(off, off + count * msgLen);
    const view = createView(msg);
    const cs = new Array<Uint8Array>(count);
    const inputs = new Array<Uint8Array>(count);
    for (let i = 0; i < count; i++) cs[i] = msg.subarray(i * msgLen, (i + 1) * msgLen);
    for (let i = 0; i < count; i++) {
      const pos = i * msgLen + inputPos;
      inputs[i] = msg.subarray(pos, pos + inputLen);
    }
    const parts: Uint8Array[] = [];
    if (partLen) {
      const partsPerLane = inputLen / partLen;
      for (let lane = 0; lane < count; lane++) {
        const base = lane * msgLen + inputPos;
        for (let part = 0; part < partsPerLane; part++) {
          const pos = base + part * partLen;
          parts.push(msg.subarray(pos, pos + partLen));
        }
      }
    }
    chunks.push({
      count,
      prefixLen,
      addrLen,
      inputLen,
      msgLen,
      msg,
      first: cs[0],
      view,
      chunks: cs,
      inputs,
      partLen,
      parts,
    });
    outCounts.add(count);
  });
  for (const count of outCounts) {
    const buf = out.subarray(0, count * outLen);
    const os = new Array<Uint8Array>(count);
    for (let i = 0; i < count; i++) os[i] = buf.subarray(i * outLen, (i + 1) * outLen);
    outs.push({ count, buf, out: os });
  }
  const getChunks = (count: number, prefixLen: number, addrLen: number, inputLen: number) => {
    for (const c of chunks)
      if (
        c.count === count &&
        c.prefixLen === prefixLen &&
        c.addrLen === addrLen &&
        c.inputLen === inputLen
      )
        return c;
    throw new Error(
      `missing SLH parallel input shape count=${count} prefix=${prefixLen} addr=${addrLen} input=${inputLen}`
    );
  };
  const getOut = (count: number, dst?: TArg<ParallelOut>) => {
    if (Array.isArray(dst)) return dst as Uint8Array[];
    for (const o of outs) if (o.count === count) return o.out;
    throw new Error(`missing SLH parallel output shape count=${count}`);
  };
  const run = (entry: ChunkEntry, out?: TArg<ParallelOut>, prefixState?: TArg<HashState>) =>
    rawHash.parallel(entry.chunks, {
      dkLen: outLen,
      out: getOut(entry.count, out),
      prefixState,
    });
  const api: ParallelScratch = {
    inputs(count: number, inputLen: number) {
      return getChunks(count, prefixLen, addrLen, inputLen).inputs;
    },
    parts(count: number, inputLen: number, partLen: number) {
      const entry = getChunks(count, prefixLen, addrLen, inputLen);
      if (entry.partLen !== partLen)
        throw new Error(`missing SLH parallel input parts count=${count} part=${partLen}`);
      return entry.parts;
    },
    output(count: number) {
      for (const o of outs) if (o.count === count) return o;
      throw new Error(`missing SLH parallel output shape count=${count}`);
    },
    direct(
      count: number,
      prefix: Uint8Array,
      baseAddr: Uint8Array,
      patch: AddrPatch,
      input: Uint8Array,
      inputLen: number,
      inputStride: number,
      out?: TArg<ParallelOut>,
      prefixState?: TArg<HashState>
    ) {
      const entry = getChunks(count, prefix.length, baseAddr.length, inputLen);
      const { msg, msgLen, first, view } = entry;
      // Fill packed hash.parallel input. Lane i is `prefix || patched baseAddr || input`.
      // Lane 0 is copied across first because most bytes are shared between lanes.
      let pos = 0;
      first.set(prefix, pos);
      pos += prefix.length;
      copyFast(first, pos, baseAddr, 0, addrLen);
      patch(first, pos, 0, view);
      pos += addrLen;
      copyFast(first, pos, input, 0, inputLen);
      for (let done = 1; done < count; ) {
        const take = Math.min(done, count - done);
        msg.copyWithin(done * msgLen, 0, take * msgLen);
        done += take;
      }
      for (let i = 1; i < count; i++) {
        const base = i * msgLen + prefix.length;
        patch(msg, base, i, view);
        if (inputStride) copyFast(msg, base + addrLen, input, i * inputStride, inputLen);
      }
      return run(entry, out, prefixState);
    },
    header(
      count: number,
      prefix: Uint8Array,
      baseAddr: Uint8Array,
      patch: AddrPatch,
      inputLen: number,
      out?: TArg<ParallelOut>,
      prefixState?: TArg<HashState>
    ) {
      const entry = getChunks(count, prefix.length, baseAddr.length, inputLen);
      const { msg, msgLen, view } = entry;
      for (let i = 0; i < count; i++) {
        const base = i * msgLen;
        if (prefixLen) copyFast(msg, base, prefix, 0, prefixLen);
        copyFast(msg, base + prefixLen, baseAddr, 0, addrLen);
        patch(msg, base + prefixLen, i, view);
      }
      return run(entry, out, prefixState);
    },
    patch(
      count: number,
      inputLen: number,
      patch: AddrPatch,
      out?: TArg<ParallelOut>,
      prefixState?: TArg<HashState>
    ) {
      const entry = getChunks(count, prefixLen, addrLen, inputLen);
      const { msg, msgLen, view } = entry;
      for (let i = 0; i < count; i++) patch(msg, i * msgLen + prefixLen, i, view);
      return run(entry, out, prefixState);
    },
    clean() {
      cleanBytes(buf);
    },
  };
  return api;
};
const createWotsScratch = (
  opts: ScratchOpts,
  chain: ParallelScratch,
  pk: ParallelScratch = chain
) => {
  const { N, W, WOTS_LEN } = opts;
  return {
    /**
     * Run the SHA2-style WOTS path with chain outputs written into future WOTSPK input pieces.
     *
     * The chain scratch and WOTSPK scratch may be different hashes for SHA2 parameter sets, so this
     * method uses `chain` for PRF/thash1 steps and `pk` for the final WOTSPK-to-leaf hash. Final
     * chain outputs are written into `pk.parts(...)`, avoiding an intermediate WOTS public-key copy.
     *
     * @param prefix - Prefix bytes/state for PRF and chain hashes.
     * @param pkPrefix - Prefix bytes/state for the WOTSPK hash.
     * @param skSeed - Secret seed used by the WOTS PRF lanes.
     * @param job - One WOTS tree batch description.
     */
    chains(prefix: HashPrefix, pkPrefix: HashPrefix, skSeed: Uint8Array, job: WotsJob) {
      const { baseAddr, count, idxOffset, leafIdx, steps, sig, out, prfPatch, hashPatch, pkPatch } =
        job;
      const leafCount = count / WOTS_LEN;
      const state = chain.inputs(count, N);
      const pkInput = pk.parts(leafCount, WOTS_LEN * N, N);
      const target = leafIdx - idxOffset;
      const hasTarget = target >= 0 && target < leafCount;
      const targetBase = target * WOTS_LEN;
      chain.direct(
        count,
        prefix.bytes,
        baseAddr,
        prfPatch,
        skSeed,
        skSeed.length,
        0,
        state,
        prefix.state
      );
      for (let k = 0; k < W - 1; k++) {
        if (hasTarget) {
          for (let chainIdx = 0; chainIdx < WOTS_LEN; chainIdx++)
            if (k === steps[chainIdx])
              copyFast(sig, chainIdx * N, state[targetBase + chainIdx], 0, N);
        }
        chain.patch(count, N, hashPatch(k), k === W - 2 ? pkInput : state, prefix.state);
      }
      if (hasTarget) {
        for (let chainIdx = 0; chainIdx < WOTS_LEN; chainIdx++)
          if (W - 1 === steps[chainIdx])
            copyFast(sig, chainIdx * N, pkInput[targetBase + chainIdx], 0, N);
      }
      pk.header(leafCount, pkPrefix.bytes, baseAddr, pkPatch, WOTS_LEN * N, out, pkPrefix.state);
    },
    /**
     * Run the SHAKE WOTS path with chain state kept in one flat output buffer.
     *
     * SHAKE was slower when final chain outputs were written strided into WOTSPK input pieces, so
     * this path keeps the WOTS chain state in the scratch output buffer and uses one final direct
     * batch to hash `WOTS_LEN * N` bytes per leaf into `job.out`.
     *
     * @param prefix - Prefix bytes/state used by all WOTS hash calls.
     * @param skSeed - Secret seed used by the WOTS PRF lanes.
     * @param job - One WOTS tree batch description.
     */
    flat(prefix: HashPrefix, skSeed: Uint8Array, job: WotsJob) {
      const { baseAddr, count, idxOffset, leafIdx, steps, sig, out, prfPatch, hashPatch, pkPatch } =
        job;
      const leafCount = count / WOTS_LEN;
      const state = chain.inputs(count, N);
      const flat = chain.output(count);
      const target = leafIdx - idxOffset;
      const hasTarget = target >= 0 && target < leafCount;
      const targetBase = target * WOTS_LEN;
      chain.direct(
        count,
        prefix.bytes,
        baseAddr,
        prfPatch,
        skSeed,
        skSeed.length,
        0,
        state,
        prefix.state
      );
      if (hasTarget) {
        for (let chainIdx = 0; chainIdx < WOTS_LEN; chainIdx++)
          if (steps[chainIdx] === 0)
            copyFast(sig, chainIdx * N, state[targetBase + chainIdx], 0, N);
      }
      for (let k = 0; k < W - 1; k++) {
        chain.patch(count, N, hashPatch(k), state, prefix.state);
        if (hasTarget) {
          const step = k + 1;
          for (let chainIdx = 0; chainIdx < WOTS_LEN; chainIdx++)
            if (step === steps[chainIdx])
              copyFast(sig, chainIdx * N, state[targetBase + chainIdx], 0, N);
        }
      }
      for (let i = 0; i < count; i++) copyFast(flat.buf, i * N, state[i], 0, N);
      chain.direct(
        leafCount,
        prefix.bytes,
        baseAddr,
        pkPatch,
        flat.buf,
        WOTS_LEN * N,
        WOTS_LEN * N,
        out,
        prefix.state
      );
    },
  };
};
// FIPS 205 §11.1 SHAKE instantiation: this path hashes the full uncompressed address bytes,
// unlike the compressed 22-byte SHA2 path in §11.2.
const genShake = (): TRet<GetContext> => (opts: SphincsOpts) => {
  const { N, W, H, D } = opts;
  const WOTS_LEN = Math.floor((8 * N) / 4) + (N <= 8 ? 2 : N <= 136 ? 3 : 4);
  const TREE_HEIGHT = Math.floor(H / D);
  const scratchOpts = {
    ...opts,
    WOTS_LEN,
    TREE_HEIGHT,
    addrLen: 32,
    prefixLen: N,
    outLen: N,
    chains: true,
    trees: true,
  };
  return (pubSeed: TArg<Uint8Array>, skSeed?: TArg<Uint8Array>, sign = false): TRet<Context> => {
    const stats = { prf: 0, thash: 0, hmsg: 0, gen_message_random: 0 };
    // Keygen only walks WOTS/XMSS; FORS scratch is large and only needed while signing.
    const scratch = skSeed
      ? createParallelScratch(shake256, { ...scratchOpts, fors: sign })
      : undefined;
    const wotsScratch = scratch ? createWotsScratch(scratchOpts, scratch) : undefined;
    // §11.1 prefixes PRF/F/H/T_l with `PK.seed`, so cache that absorbed prefix once and clone it
    // for each address-bound call instead of reabsorbing the same seed every time.
    const rawPubSeed = pubSeed as Uint8Array;
    const h0 = shake256.create({}).update(rawPubSeed);
    // Prefix-state only saves work when the common prefix has already filled a backend block.
    // SHAKE's `PK.seed` is a short tail, so keep it in the packed message to avoid two copies/lane.
    const h0State = rawPubSeed.length === h0.blockLen ? h0.exportState() : undefined;
    const h0Prefix = h0State ? EMPTY : rawPubSeed;
    const h0tmp = h0.clone();
    const thash = (
      blocks: number,
      input: TArg<Uint8Array>,
      addr: TArg<ADRS>,
      out?: TArg<Uint8Array>
    ): TRet<Uint8Array> => {
      stats.thash++;
      const h = h0
        ._cloneInto(h0tmp)
        .update(addr)
        .update(input.subarray(0, blocks * N));
      if (out) return h.xofInto((out as Uint8Array).subarray(0, N)) as TRet<Uint8Array>;
      return h.xof(N) as TRet<Uint8Array>;
    };
    return {
      PRFaddr: (addr: TArg<ADRS>): TRet<Uint8Array> => {
        if (!skSeed) throw new Error('no sk seed');
        stats.prf++;
        const res = h0._cloneInto(h0tmp).update(addr).update(skSeed).xof(N);
        return res as TRet<Uint8Array>;
      },
      forsLeavesFill: (
        baseAddr: TArg<Uint8Array>,
        count: number,
        prfPatch: AddrPatch,
        leafPatch: AddrPatch,
        out: TArg<ParallelOut>
      ) => {
        if (!skSeed) throw new Error('no sk seed');
        if (!scratch) throw new Error('no scratch');
        const rawSkSeed = skSeed as Uint8Array;
        const rawAddr = baseAddr as Uint8Array;
        const prfs = scratch.inputs(count, N);
        stats.prf += count;
        stats.thash += count;
        scratch.direct(
          count,
          h0Prefix,
          rawAddr,
          prfPatch,
          rawSkSeed,
          rawSkSeed.length,
          0,
          prfs,
          h0State
        );
        const leaves = scratch.patch(count, N, leafPatch, out, h0State);
        return { prfs, leaves };
      },
      PRFmsg: (
        skPRF: TArg<Uint8Array>,
        random: TArg<Uint8Array>,
        msg: TArg<Uint8Array>
      ): TRet<Uint8Array> => {
        stats.gen_message_random++;
        return shake256.chunks([skPRF, random, msg], { dkLen: N });
      },
      Hmsg: (
        R: TArg<Uint8Array>,
        pk: TArg<Uint8Array>,
        m: TArg<Uint8Array>,
        outLen
      ): TRet<Uint8Array> => {
        stats.hmsg++;
        return shake256.chunks([R.subarray(0, N), pk, m], { dkLen: outLen });
      },
      thash1: thash.bind(null, 1),
      thashN: thash,
      thashNFill: (
        blocks: number,
        input: TArg<Uint8Array>,
        baseAddr: TArg<Uint8Array>,
        count: number,
        patch: AddrPatch,
        out?: TArg<ParallelOut>
      ): TRet<Uint8Array[]> => {
        if (!scratch) throw new Error('no scratch');
        const inputLen = blocks * N;
        stats.thash += count;
        // SHAKE keeps `PK.seed` in each packed lane unless it was exported as `prefixState`.
        // Each lane hashed here is `PK.seed || ADRS || input`.
        return scratch.direct(
          count,
          h0Prefix,
          baseAddr as Uint8Array,
          patch,
          input as Uint8Array,
          inputLen,
          inputLen,
          out,
          h0State
        );
      },
      wotsFill: (job: TArg<WotsJob>) => {
        if (!skSeed) throw new Error('no sk seed');
        if (!wotsScratch) throw new Error('no scratch');
        const rawJob = job as WotsJob;
        stats.prf += rawJob.count;
        stats.thash += rawJob.count * (W - 1) + rawJob.count / WOTS_LEN;
        wotsScratch.flat({ bytes: h0Prefix, state: h0State }, skSeed as Uint8Array, rawJob);
      },
      clean: () => {
        h0.destroy();
        h0tmp.destroy();
        if (scratch) scratch.clean();
        // Prefix states are opaque and must be destroyed by the hash that exported them.
        if (h0State) shake256.cleanState(h0State);
        //console.log(stats);
      },
    } as TRet<Context>;
  };
};

const SHAKE_SIMPLE = /* @__PURE__ */ (() => ({ getContext: genShake() }))();

/**
 * SLH-DSA-SHAKE-128f: Table 2 row `n=16, h=66, d=22, h'=3, a=6, k=33, lg w=4, m=34`;
 * lengths `publicKey=32`, `secretKey=64`, `signature=17088`, `seed=48`, `signRand=16`.
 * Also exposes `.prehash(...)`.
 */
export const slh_dsa_shake_128f: TRet<SphincsSigner> = /* @__PURE__ */ (() =>
  gen(PARAMS['128f'], SHAKE_SIMPLE))();
/**
 * SLH-DSA-SHAKE-128s: Table 2 row `n=16, h=63, d=7, h'=9, a=12, k=14, lg w=4, m=30`;
 * lengths `publicKey=32`, `secretKey=64`, `signature=7856`, `seed=48`, `signRand=16`.
 * Also exposes `.prehash(...)`.
 */
export const slh_dsa_shake_128s: TRet<SphincsSigner> = /* @__PURE__ */ (() =>
  gen(PARAMS['128s'], SHAKE_SIMPLE))();
/**
 * SLH-DSA-SHAKE-192f: Table 2 row `n=24, h=66, d=22, h'=3, a=8, k=33, lg w=4, m=42`;
 * lengths `publicKey=48`, `secretKey=96`, `signature=35664`, `seed=72`, `signRand=24`.
 * Also exposes `.prehash(...)`.
 */
export const slh_dsa_shake_192f: TRet<SphincsSigner> = /* @__PURE__ */ (() =>
  gen(PARAMS['192f'], SHAKE_SIMPLE))();
/**
 * SLH-DSA-SHAKE-192s: Table 2 row `n=24, h=63, d=7, h'=9, a=14, k=17, lg w=4, m=39`;
 * lengths `publicKey=48`, `secretKey=96`, `signature=16224`, `seed=72`, `signRand=24`.
 * Also exposes `.prehash(...)`.
 */
export const slh_dsa_shake_192s: TRet<SphincsSigner> = /* @__PURE__ */ (() =>
  gen(PARAMS['192s'], SHAKE_SIMPLE))();
/**
 * SLH-DSA-SHAKE-256f: Table 2 row `n=32, h=68, d=17, h'=4, a=9, k=35, lg w=4, m=49`;
 * lengths `publicKey=64`, `secretKey=128`, `signature=49856`, `seed=96`, `signRand=32`.
 * Also exposes `.prehash(...)`.
 */
export const slh_dsa_shake_256f: TRet<SphincsSigner> = /* @__PURE__ */ (() =>
  gen(PARAMS['256f'], SHAKE_SIMPLE))();
/**
 * SLH-DSA-SHAKE-256s: Table 2 row `n=32, h=64, d=8, h'=8, a=14, k=22, lg w=4, m=47`;
 * lengths `publicKey=64`, `secretKey=128`, `signature=29792`, `seed=96`, `signRand=32`.
 * Also exposes `.prehash(...)`.
 */
export const slh_dsa_shake_256s: TRet<SphincsSigner> = /* @__PURE__ */ (() =>
  gen(PARAMS['256s'], SHAKE_SIMPLE))();

type ShaType = typeof sha256 | typeof sha512;
// FIPS 205 §11.2 SHA2 instantiation. The `h0` / `h1` split is intentional:
// category-1 keeps everything on SHA-256, while category-3/5 keep `PRFaddr` / `thash1`
// on SHA-256 but switch `PRFmsg`, `Hmsg`, and multi-block `thashN` to SHA-512.
const genSha =
  (h0: ShaType, h1: ShaType): TRet<GetContext> =>
  (opts) => {
    const { N, W, H, D } = opts;
    const WOTS_LEN = Math.floor((8 * N) / 4) + (N <= 8 ? 2 : N <= 136 ? 3 : 4);
    const TREE_HEIGHT = Math.floor(H / D);
    const scratchOpts = {
      ...opts,
      WOTS_LEN,
      TREE_HEIGHT,
      addrLen: 22,
      prefixLen: 0,
      outLen: N,
    };
    return (
      pub_seed: TArg<Uint8Array>,
      sk_seed?: TArg<Uint8Array>,
      sign = false
    ): TRet<Context> => {
      const h0Scratch = sk_seed
        ? createParallelScratch(h0, {
            ...scratchOpts,
            chains: true,
            trees: h0 === h1,
            fors: sign,
          })
        : undefined;
      const h1Scratch =
        !sk_seed || h0 === h1
          ? h0Scratch
          : createParallelScratch(h1, {
              ...scratchOpts,
              trees: true,
              fors: sign,
            });
      const wotsScratch =
        h0Scratch && h1Scratch ? createWotsScratch(scratchOpts, h0Scratch, h1Scratch) : undefined;
      /*
    Perf debug stats, how much hashes we call?
    128f_simple: { prf: 8305, thash: 96_922, hmsg: 1, gen_message_random: 1, mgf1: 2 }
    256s_robust: { prf: 497_686, thash: 2_783_203, hmsg: 1, gen_message_random: 1, mgf1: 2_783_205}
    256f_simple: { prf: 36_179, thash: 309_693, hmsg: 1, gen_message_random: 1, mgf1: 2 }
    */
      const stats = { prf: 0, thash: 0, hmsg: 0, gen_message_random: 0, mgf1: 0 };

      const counterB = new Uint8Array(4);
      const counterV = createView(counterB);
      // §11.2 prefixes SHA2 PRF/F/H/T_l with `PK.seed || toByte(0, blockLen-N)`, so cache the
      // zero-padded seed block once for the SHA-256 lane and once for the SHA-512 lane.
      const rawPubSeed = pub_seed as Uint8Array;
      const h0Prefix = new Uint8Array(h0.blockLen);
      h0Prefix.set(rawPubSeed);
      const h1Prefix =
        h0 === h1 && h0.blockLen === h1.blockLen ? h0Prefix : new Uint8Array(h1.blockLen);
      if (h1Prefix !== h0Prefix) h1Prefix.set(rawPubSeed);
      const h0ps = h0.create().update(h0Prefix);
      const h1ps = h1.create().update(h1Prefix);
      const h0State = h0ps.exportState();
      const h1State = h1ps.exportState();

      const h0tmp = h0ps.clone();
      const h1tmp = h1ps.clone();

      // https://www.rfc-editor.org/rfc/rfc8017.html#appendix-B.2.1
      // This local helper is intentionally stricter than generic MGF1 reuse: current SLH-DSA callers
      // only request tiny `m`-byte outputs, but the guard below rejects `length > 2^32` instead of
      // RFC 8017's broader `maskLen > 2^32 * hLen` bound.
      function mgf1(seed: TArg<Uint8Array>, length: number, hash: ShaType): TRet<Uint8Array> {
        stats.mgf1++;
        const out = new Uint8Array(Math.ceil(length / hash.outputLen) * hash.outputLen);
        // NOT 2^32-1
        if (length > 2 ** 32) throw new Error('mask too long');
        for (let counter = 0, pos = 0; pos < out.length; counter++, pos += hash.outputLen) {
          counterV.setUint32(0, counter, false);
          hash.chunks([seed, counterB], { out, outPos: pos });
        }
        cleanBytes(out.subarray(length));
        return out.subarray(0, length) as TRet<Uint8Array>;
      }

      const thash =
        (hash: ShaType, h: typeof h0ps, hTmp: typeof h0ps, prefixState: TArg<HashState>) =>
        (
          blocks: number,
          input: TArg<Uint8Array>,
          addr: TArg<ADRS>,
          out?: TArg<Uint8Array>
        ): TRet<Uint8Array> => {
          stats.thash++;
          const msg = input.subarray(0, blocks * N);
          if (out)
            return hash.chunks([addr, msg], {
              dkLen: N,
              out: (out as Uint8Array).subarray(0, N),
              prefixState,
            });
          const d = h._cloneInto(hTmp).update(addr).update(msg).digest();
          return d.subarray(0, N) as TRet<Uint8Array>;
        };
      return {
        PRFaddr: (addr: TArg<ADRS>): TRet<Uint8Array> => {
          if (!sk_seed) throw new Error('No sk seed');
          stats.prf++;
          const res = h0ps._cloneInto(h0tmp).update(addr).update(sk_seed).digest().subarray(0, N);
          return res as TRet<Uint8Array>;
        },
        forsLeavesFill: (
          baseAddr: TArg<Uint8Array>,
          count: number,
          prfPatch: AddrPatch,
          leafPatch: AddrPatch,
          out: TArg<ParallelOut>
        ) => {
          if (!sk_seed) throw new Error('No sk seed');
          if (!h0Scratch) throw new Error('no scratch');
          const rawSkSeed = sk_seed as Uint8Array;
          const rawAddr = baseAddr as Uint8Array;
          const prfs = h0Scratch.inputs(count, N);
          stats.prf += count;
          stats.thash += count;
          h0Scratch.direct(
            count,
            EMPTY,
            rawAddr,
            prfPatch,
            rawSkSeed,
            rawSkSeed.length,
            0,
            prfs,
            h0State
          );
          const leaves = h0Scratch.patch(count, N, leafPatch, out, h0State);
          return { prfs, leaves };
        },
        PRFmsg: (
          skPRF: TArg<Uint8Array>,
          random: TArg<Uint8Array>,
          msg: TArg<Uint8Array>
        ): TRet<Uint8Array> => {
          stats.gen_message_random++;
          return hmac
            .create(h1, skPRF)
            .update(random)
            .update(msg)
            .digest()
            .subarray(0, N) as TRet<Uint8Array>;
        },
        Hmsg: (
          R: TArg<Uint8Array>,
          pk: TArg<Uint8Array>,
          m: TArg<Uint8Array>,
          outLen
        ): TRet<Uint8Array> => {
          stats.hmsg++;
          const r = R.subarray(0, N);
          const digest = h1.chunks([r, pk, m]);
          const seed = new Uint8Array(2 * N + digest.length);
          seed.set(r);
          copyFast(seed, N, pk, 0, N);
          seed.set(digest, 2 * N);
          const out = mgf1(seed, outLen, h1);
          cleanBytes(seed, digest);
          return out;
        },
        thash1: thash(h0, h0ps, h0tmp, h0State).bind(null, 1),
        thashN: thash(h1, h1ps, h1tmp, h1State),
        thashNFill: (
          blocks: number,
          input: TArg<Uint8Array>,
          baseAddr: TArg<Uint8Array>,
          count: number,
          patch: AddrPatch,
          out?: TArg<ParallelOut>
        ) => {
          if (!h1Scratch) throw new Error('no scratch');
          const inputLen = blocks * N;
          stats.thash += count;
          // SHA2 resumes from `PK.seed || zero-pad`, so packed lanes only hold `ADRS || input`.
          return h1Scratch.direct(
            count,
            EMPTY,
            baseAddr as Uint8Array,
            patch,
            input as Uint8Array,
            inputLen,
            inputLen,
            out,
            h1State
          );
        },
        wotsFill: (job: TArg<WotsJob>) => {
          if (!sk_seed) throw new Error('No sk seed');
          if (!wotsScratch) throw new Error('no scratch');
          const rawJob = job as WotsJob;
          stats.prf += rawJob.count;
          stats.thash += rawJob.count * (W - 1) + rawJob.count / WOTS_LEN;
          wotsScratch.chains(
            { bytes: EMPTY, state: h0State },
            { bytes: EMPTY, state: h1State },
            sk_seed as Uint8Array,
            rawJob
          );
        },
        clean: () => {
          h0ps.destroy();
          h1ps.destroy();
          h0tmp.destroy();
          h1tmp.destroy();
          if (h0Scratch) h0Scratch.clean();
          if (h1Scratch && h1Scratch !== h0Scratch) h1Scratch.clean();
          h0.cleanState(h0State);
          h1.cleanState(h1State);
          cleanBytes(h0Prefix, h1Prefix);
          //console.log(stats);
        },
      } as TRet<Context>;
    };
  };

const SHA256_SIMPLE = /* @__PURE__ */ (() => ({
  isCompressed: true,
  getContext: genSha(sha256, sha256),
}))();
const SHA512_SIMPLE = /* @__PURE__ */ (() => ({
  isCompressed: true,
  getContext: genSha(sha256, sha512),
}))();

/**
 * SLH-DSA-SHA2-128f: Table 2 row `n=16, h=66, d=22, h'=3, a=6, k=33, lg w=4, m=34`;
 * lengths `publicKey=32`, `secretKey=64`, `signature=17088`, `seed=48`, `signRand=16`.
 * Also exposes `.prehash(...)`.
 */
export const slh_dsa_sha2_128f: TRet<SphincsSigner> = /* @__PURE__ */ (() =>
  gen(PARAMS['128f'], SHA256_SIMPLE))();
/**
 * SLH-DSA-SHA2-128s: Table 2 row `n=16, h=63, d=7, h'=9, a=12, k=14, lg w=4, m=30`;
 * lengths `publicKey=32`, `secretKey=64`, `signature=7856`, `seed=48`, `signRand=16`.
 * Also exposes `.prehash(...)`.
 */
export const slh_dsa_sha2_128s: TRet<SphincsSigner> = /* @__PURE__ */ (() =>
  gen(PARAMS['128s'], SHA256_SIMPLE))();
/**
 * SLH-DSA-SHA2-192f: Table 2 row `n=24, h=66, d=22, h'=3, a=8, k=33, lg w=4, m=42`;
 * lengths `publicKey=48`, `secretKey=96`, `signature=35664`, `seed=72`, `signRand=24`.
 * Also exposes `.prehash(...)`.
 */
export const slh_dsa_sha2_192f: TRet<SphincsSigner> = /* @__PURE__ */ (() =>
  gen(PARAMS['192f'], SHA512_SIMPLE))();
/**
 * SLH-DSA-SHA2-192s: Table 2 row `n=24, h=63, d=7, h'=9, a=14, k=17, lg w=4, m=39`;
 * lengths `publicKey=48`, `secretKey=96`, `signature=16224`, `seed=72`, `signRand=24`.
 * Also exposes `.prehash(...)`.
 */
export const slh_dsa_sha2_192s: TRet<SphincsSigner> = /* @__PURE__ */ (() =>
  gen(PARAMS['192s'], SHA512_SIMPLE))();
/**
 * SLH-DSA-SHA2-256f: Table 2 row `n=32, h=68, d=17, h'=4, a=9, k=35, lg w=4, m=49`;
 * lengths `publicKey=64`, `secretKey=128`, `signature=49856`, `seed=96`, `signRand=32`.
 * Also exposes `.prehash(...)`.
 */
export const slh_dsa_sha2_256f: TRet<SphincsSigner> = /* @__PURE__ */ (() =>
  gen(PARAMS['256f'], SHA512_SIMPLE))();
/**
 * SLH-DSA-SHA2-256s: Table 2 row `n=32, h=64, d=8, h'=8, a=14, k=22, lg w=4, m=47`;
 * lengths `publicKey=64`, `secretKey=128`, `signature=29792`, `seed=96`, `signRand=32`.
 * Also exposes `.prehash(...)`.
 */
export const slh_dsa_sha2_256s: TRet<SphincsSigner> = /* @__PURE__ */ (() =>
  gen(PARAMS['256s'], SHA512_SIMPLE))();
