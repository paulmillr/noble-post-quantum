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
import { hmac } from '@noble/hashes/hmac.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { shake256 } from '@noble/hashes/sha3.js';
import {
  bytesToHex,
  concatBytes,
  createView,
  hexToBytes,
  type CHash,
} from '@noble/hashes/utils.js';
import {
  abytes,
  checkHash,
  cleanBytes,
  copyBytes,
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
   * @returns Hash output bytes.
   */
  thash1: (input: TArg<Uint8Array>, addr: TArg<ADRS>) => TRet<Uint8Array>;
  /**
   * Tweakable hash over multiple input blocks.
   * @param blocks - Number of input blocks.
   * @param input - Concatenated input bytes.
   * @param addr - Address bytes.
   * @returns Hash output bytes.
   */
  thashN: (blocks: number, input: TArg<Uint8Array>, addr: TArg<ADRS>) => TRet<Uint8Array>;
  /** Wipe any buffered hash state for the current context. */
  clean: () => void;
};
/** Factory that creates a context generator for one SLH-DSA parameter set. */
export type GetContext = (
  opts: SphincsOpts
) => (pub_seed: TArg<Uint8Array>, sk_seed?: TArg<Uint8Array>) => TRet<Context>;

function hexToNumber(hex: string): bigint {
  if (typeof hex !== 'string') throw new Error('hex string expected, got ' + typeof hex);
  return BigInt(hex === '' ? '0' : '0x' + hex); // Big Endian
}

// BE: Big Endian, LE: Little Endian. This is the local FIPS 205 `toInt(...)` equivalent.
function bytesToNumberBE(bytes: TArg<Uint8Array>): bigint {
  return hexToNumber(bytesToHex(bytes));
}

// Local in-range FIPS 205 `toByte(x, n)` equivalent; callers must keep `n < 256^len`.
function numberToBytesBE(n: number | bigint, len: number): TRet<Uint8Array> {
  return hexToBytes(n.toString(16).padStart(len * 2, '0'));
}

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
    if (subtreeAddr) addr.set(subtreeAddr.subarray(0, OFFSET_TREE + 8));
    if (tree !== undefined) v.setBigUint64(OFFSET_TREE, tree, false);
    if (keypair !== undefined) {
      addr[OFFSET_KP_ADDR1] = keypair;
      if (TREE_HEIGHT > 8) addr[OFFSET_KP_ADDR2] = keypair >>> 8;
    }
    if (keypairAddr) {
      addr.set(keypairAddr.subarray(0, OFFSET_TREE + 8));
      addr[OFFSET_KP_ADDR1] = keypairAddr[OFFSET_KP_ADDR1];
      if (TREE_HEIGHT > 8) addr[OFFSET_KP_ADDR2] = keypairAddr[OFFSET_KP_ADDR2];
    }
    return addr;
  };

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

  // Iterative `xmss_node` / `xmss_sign` core: mutate `treeAddr` in place, collapse completed
  // sibling pairs on `stack`, and record the sibling whenever the current subtree is the auth-path
  // neighbor of the target leaf at that height.
  const treehash = <T>(
    height: number,
    fn: TArg<(leafIdx: number, addrOffset: number, context: Context, info: T) => Uint8Array>
  ) =>
    function treehash_i(
      context: TArg<Context>,
      leafIdx: number,
      idxOffset: number,
      treeAddr: TArg<ADRS>,
      info: T
    ) {
      const rawContext = context as Context;
      const leafFn = fn as (
        leafIdx: number,
        addrOffset: number,
        context: Context,
        info: T
      ) => Uint8Array;
      const maxIdx = (1 << height) - 1;
      const stack = new Uint8Array(height * N);
      const authPath = new Uint8Array(height * N);
      for (let idx = 0; ; idx++) {
        const current = new Uint8Array(2 * N);
        const cur0 = current.subarray(0, N);
        const cur1 = current.subarray(N);
        const addrOffset = idx + idxOffset;
        cur1.set(leafFn(leafIdx, addrOffset, rawContext, info));
        let h = 0;
        for (let i = idx, o = idxOffset, l = leafIdx; ; h++, i >>>= 1, l >>>= 1, o >>>= 1) {
          if (h === height) return { root: cur1, authPath }; // Returns from here
          if ((i ^ l) === 1) authPath.subarray(h * N).set(cur1); // authPath.push(cur1)
          if ((i & 1) === 0 && idx < maxIdx) break;
          setAddr({ height: h + 1, index: (i >> 1) + (o >> 1) }, treeAddr);
          cur0.set(stack.subarray(h * N).subarray(0, N));
          cur1.set(rawContext.thashN(2, current, treeAddr));
        }
        stack.subarray(h * N).set(cur1); // stack.push(cur1)
      }
      // @ts-ignore
      throw new Error('Unreachable code path reached, report this error');
    };

  type LeafInfo = {
    wotsSig: Uint8Array;
    wotsSteps: Uint32Array;
    leafAddr: ADRS;
    pkAddr: ADRS;
  };
  const wotsTreehash = treehash(
    TREE_HEIGHT,
    (leafIdx: number, addrOffset: number, context: TArg<Context>, info: TArg<LeafInfo>) => {
      const rawContext = context as Context;
      const wotsPk = new Uint8Array(WOTS_LEN * N);
      // `keygen()` passes `leafIdx = ~0 >>> 0`, so no real XMSS leaf matches and this suppresses
      // WOTS signature capture while still hashing every chain to its public-key endpoint.
      const wotsKmask = addrOffset === leafIdx ? 0 : ~0 >>> 0;
      setAddr({ keypair: addrOffset }, info.leafAddr);
      setAddr({ keypair: addrOffset }, info.pkAddr);
      for (let i = 0; i < WOTS_LEN; i++) {
        const wotsK = info.wotsSteps[i] | wotsKmask;
        const pk = wotsPk.subarray(i * N, (i + 1) * N);
        setAddr({ chain: i, hash: 0, type: AddressType.WOTSPRF }, info.leafAddr);
        pk.set(rawContext.PRFaddr(info.leafAddr));
        setAddr({ type: AddressType.WOTS }, info.leafAddr);
        for (let k = 0; ; k++) {
          if (k === wotsK) info.wotsSig.subarray(i * N).set(pk); //wotsSig.push()
          if (k === W - 1) break;
          setAddr({ hash: k }, info.leafAddr);
          pk.set(rawContext.thash1(pk, info.leafAddr));
        }
      }
      return rawContext.thashN(WOTS_LEN, wotsPk, info.pkAddr);
    }
  );

  const forsTreehash = treehash(
    A,
    (_: number, addrOffset: number, context: TArg<Context>, forsLeafAddr: TArg<ForsLeafInfo>) => {
      const rawContext = context as Context;
      setAddr({ type: AddressType.FORSPRF, index: addrOffset }, forsLeafAddr);
      const prf = rawContext.PRFaddr(forsLeafAddr);
      setAddr({ type: AddressType.FORSTREE }, forsLeafAddr);
      return rawContext.thash1(prf, forsLeafAddr);
    }
  );

  // Fuse `xmss_sign` with the subtree-root computation needed by `ht_sign`, so one tree walk
  // yields both the WOTS/auth-path signature and the root that the next hypertree layer signs.
  const merkleSign = (
    context: TArg<Context>,
    wotsAddr: TArg<ADRS>,
    treeAddr: TArg<ADRS>,
    leafIdx: number,
    prevRoot: TArg<Uint8Array> = new Uint8Array(N)
  ): TRet<{ root: Uint8Array; sigWots: Uint8Array; sigAuth: Uint8Array }> => {
    setAddr({ type: AddressType.HASHTREE }, treeAddr);
    // State variables
    const info = {
      wotsSig: new Uint8Array(wotsCoder.bytesLen),
      wotsSteps: chainLengths(prevRoot),
      leafAddr: setAddr({ subtreeAddr: wotsAddr }),
      pkAddr: setAddr({ type: AddressType.WOTSPK, subtreeAddr: wotsAddr }),
    };
    const { root, authPath } = wotsTreehash(context, leafIdx, 0, treeAddr, info);
    return {
      root,
      sigWots: info.wotsSig.subarray(0, WOTS_LEN * N),
      sigAuth: authPath,
    } as TRet<{ root: Uint8Array; sigWots: Uint8Array; sigAuth: Uint8Array }>;
  };

  type ForsLeafInfo = ADRS;

  const computeRoot = (
    leaf: TArg<Uint8Array>,
    leafIdx: number,
    idxOffset: number,
    authPath: TArg<Uint8Array>,
    treeHeight: number,
    context: TArg<Context>,
    addr: TArg<ADRS>
  ) => {
    const rawContext = context as Context;
    const buffer = new Uint8Array(2 * N);
    const b0 = buffer.subarray(0, N);
    const b1 = buffer.subarray(N, 2 * N);
    // Algorithm 11 hashes `node || AUTH[k]` for even nodes and `AUTH[k] || node` for odd ones,
    // so reuse one `2N` buffer and just swap which half receives the sibling at each level.
    // `idxOffset` carries the subtree base for the shared FORS path, so `leafIdx + idxOffset`
    // tracks the same tree-global index updates that Algorithms 11 and 17 apply to ADRS.
    // First iter
    if ((leafIdx & 1) !== 0) {
      b1.set(leaf.subarray(0, N));
      b0.set(authPath.subarray(0, N));
    } else {
      b0.set(leaf.subarray(0, N));
      b1.set(authPath.subarray(0, N));
    }
    leafIdx >>>= 1;
    idxOffset >>>= 1;
    // Rest
    for (let i = 0; i < treeHeight - 1; i++, leafIdx >>= 1, idxOffset >>= 1) {
      setAddr({ height: i + 1, index: leafIdx + idxOffset }, addr);
      const a = authPath.subarray((i + 1) * N, (i + 2) * N);
      if ((leafIdx & 1) !== 0) {
        b1.set(rawContext.thashN(2, buffer, addr));
        b0.set(a);
      } else {
        buffer.set(rawContext.thashN(2, buffer, addr));
        b1.set(a);
      }
    }
    // Root
    setAddr({ height: treeHeight, index: leafIdx + idxOffset }, addr);
    return rawContext.thashN(2, buffer, addr);
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
      // ADRS.setLayerAddress(d − 1)
      const topTreeAddr = setAddr({ layer: D - 1 });
      const wotsAddr = setAddr({ layer: D - 1 });
      //PK.root ←_xmss node(SK.seed, 0, h′, PK.seed, ADRS)
      const { root } = merkleSign(context, wotsAddr, topTreeAddr, ~0 >>> 0);
      const publicKey = publicCoder.encode([publicSeed, root]);
      const secretKey = secretCoder.encode([secretSeed, secretPRF, publicKey]);
      context.clean();
      cleanBytes(secretSeed, secretPRF, root, wotsAddr, topTreeAddr);
      return {
        publicKey: publicKey as TRet<Uint8Array>,
        secretKey: secretKey as TRet<Uint8Array>,
      };
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
      const context = getContext(pkSeed, skSeed);
      // Generate randomizer
      const R = context.PRFmsg(skPRF, random, msg); // R ← PRFmsg(SK.prf, opt_rand, M)
      let { tree, leafIdx, md } = hashMessage(R, pk, msg, context);
      // Create FORS signatures
      const wotsAddr = setAddr({
        type: AddressType.WOTS,
        tree,
        keypair: leafIdx,
      });
      const roots = [];
      const forsLeaf = setAddr({ keypairAddr: wotsAddr });
      const forsTreeAddr = setAddr({ keypairAddr: wotsAddr });
      const indices = messageToIndices(md);
      const fors: [Uint8Array, Uint8Array][] = [];
      for (let i = 0; i < indices.length; i++) {
        const idxOffset = i << A;
        setAddr(
          {
            type: AddressType.FORSPRF,
            height: 0,
            index: indices[i] + idxOffset,
          },
          forsTreeAddr
        );
        const prf = context.PRFaddr(forsTreeAddr);
        setAddr({ type: AddressType.FORSTREE }, forsTreeAddr);
        const { root, authPath } = forsTreehash(
          context,
          indices[i],
          idxOffset,
          forsTreeAddr,
          forsLeaf
        );
        roots.push(root);
        fors.push([prf, authPath]);
      }
      const forsPkAddr = setAddr({
        type: AddressType.FORSPK,
        keypairAddr: wotsAddr,
      });
      const root = context.thashN(K, concatBytes(...roots), forsPkAddr);
      // WOTS signatures
      const treeAddr = setAddr({ type: AddressType.HASHTREE });
      const wots: [Uint8Array, Uint8Array][] = [];
      for (let i = 0; i < D; i++, tree >>= BigInt(TREE_HEIGHT)) {
        setAddr({ tree, layer: i }, treeAddr);
        setAddr({ subtreeAddr: treeAddr, keypair: leafIdx }, wotsAddr);
        const {
          sigWots,
          sigAuth,
          root: r,
        } = merkleSign(context, wotsAddr, treeAddr, leafIdx, root);
        root.set(r);
        cleanBytes(r);
        wots.push([sigWots, sigAuth]);
        leafIdx = Number(tree & getMaskBig(TREE_HEIGHT));
      }
      context.clean();
      const SIG = sigCoder.encode([R, fors, wots]);
      cleanBytes(R, random, treeAddr, wotsAddr, forsLeaf, forsTreeAddr, indices, roots);
      return SIG as TRet<Uint8Array>;
    },
    verify: (sig: TArg<Uint8Array>, msg: TArg<Uint8Array>, publicKey: TArg<Uint8Array>) => {
      const [pkSeed, pubRoot] = publicCoder.decode(publicKey);
      const [random, forsVec, wotsVec] = sigCoder.decode(sig);
      const pk = publicKey;
      if (sig.length !== sigCoder.bytesLen) return false;
      const context = getContext(pkSeed);
      let { tree, leafIdx, md } = hashMessage(random, pk, msg, context);
      const wotsAddr = setAddr({
        type: AddressType.WOTS,
        tree,
        keypair: leafIdx,
      });
      // FORS signature
      const roots = [];
      const forsTreeAddr = setAddr({
        type: AddressType.FORSTREE,
        keypairAddr: wotsAddr,
      });
      const indices = messageToIndices(md);
      for (let i = 0; i < forsVec.length; i++) {
        const [prf, authPath] = forsVec[i];
        const idxOffset = i << A;
        setAddr({ height: 0, index: indices[i] + idxOffset }, forsTreeAddr);
        const leaf = context.thash1(prf, forsTreeAddr);
        // Compute inplace, because we need all roots in same byte array
        roots.push(computeRoot(leaf, indices[i], idxOffset, authPath, A, context, forsTreeAddr));
      }
      const forsPkAddr = setAddr({
        type: AddressType.FORSPK,
        keypairAddr: wotsAddr,
      });
      let root = context.thashN(K, concatBytes(...roots), forsPkAddr); // root = thash()
      // WOTS signature
      const treeAddr = setAddr({ type: AddressType.HASHTREE });
      const wotsPkAddr = setAddr({ type: AddressType.WOTSPK });
      const wotsPk = new Uint8Array(WOTS_LEN * N);
      for (let i = 0; i < wotsVec.length; i++, tree >>= BigInt(TREE_HEIGHT)) {
        const [wots, sigAuth] = wotsVec[i];
        setAddr({ tree, layer: i }, treeAddr);
        setAddr({ subtreeAddr: treeAddr, keypair: leafIdx }, wotsAddr);
        setAddr({ keypairAddr: wotsAddr }, wotsPkAddr);
        const lengths = chainLengths(root);
        for (let i = 0; i < WOTS_LEN; i++) {
          setAddr({ chain: i }, wotsAddr);
          const steps = W - 1 - lengths[i];
          const start = lengths[i];
          const out = wotsPk.subarray(i * N);
          out.set(wots.subarray(i * N, (i + 1) * N));
          for (let j = start; j < start + steps && j < W; j++) {
            setAddr({ hash: j }, wotsAddr);
            out.set(context.thash1(out, wotsAddr));
          }
        }
        const leaf = context.thashN(WOTS_LEN, wotsPk, wotsPkAddr);
        root = computeRoot(leaf, leafIdx, 0, sigAuth, TREE_HEIGHT, context, treeAddr);
        leafIdx = Number(tree & getMaskBig(TREE_HEIGHT));
      }
      return equalBytes(root, pubRoot);
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

// FIPS 205 §11.1 SHAKE instantiation: this path hashes the full uncompressed address bytes,
// unlike the compressed 22-byte SHA2 path in §11.2.
const genShake =
  (): TRet<GetContext> =>
  (opts: SphincsOpts) =>
  (pubSeed: TArg<Uint8Array>, skSeed?: TArg<Uint8Array>): TRet<Context> => {
    const { N } = opts;
    const stats = { prf: 0, thash: 0, hmsg: 0, gen_message_random: 0 };
    // §11.1 prefixes PRF/F/H/T_l with `PK.seed`, so cache that absorbed prefix once and clone it
    // for each address-bound call instead of reabsorbing the same seed every time.
    const h0 = shake256.create({}).update(pubSeed);
    const h0tmp = h0.clone();
    const thash = (blocks: number, input: TArg<Uint8Array>, addr: TArg<ADRS>): TRet<Uint8Array> => {
      stats.thash++;
      return h0
        ._cloneInto(h0tmp)
        .update(addr)
        .update(input.subarray(0, blocks * N))
        .xof(N) as TRet<Uint8Array>;
    };
    return {
      PRFaddr: (addr: TArg<ADRS>): TRet<Uint8Array> => {
        if (!skSeed) throw new Error('no sk seed');
        stats.prf++;
        const res = h0._cloneInto(h0tmp).update(addr).update(skSeed).xof(N);
        return res as TRet<Uint8Array>;
      },
      PRFmsg: (
        skPRF: TArg<Uint8Array>,
        random: TArg<Uint8Array>,
        msg: TArg<Uint8Array>
      ): TRet<Uint8Array> => {
        stats.gen_message_random++;
        return shake256
          .create({})
          .update(skPRF)
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
        return shake256.create({}).update(R.subarray(0, N)).update(pk).update(m).xof(outLen);
      },
      thash1: thash.bind(null, 1),
      thashN: thash,
      clean: () => {
        h0.destroy();
        h0tmp.destroy();
        //console.log(stats);
      },
    } as TRet<Context>;
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
  (opts) =>
  (pub_seed: TArg<Uint8Array>, sk_seed?: TArg<Uint8Array>): TRet<Context> => {
    const { N } = opts;
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
    const h0ps = h0
      .create()
      .update(pub_seed)
      .update(new Uint8Array(h0.blockLen - N));
    const h1ps = h1
      .create()
      .update(pub_seed)
      .update(new Uint8Array(h1.blockLen - N));

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
      for (let counter = 0, o = out; o.length; counter++) {
        counterV.setUint32(0, counter, false);
        hash.create().update(seed).update(counterB).digestInto(o);
        o = o.subarray(hash.outputLen);
      }
      cleanBytes(out.subarray(length));
      return out.subarray(0, length) as TRet<Uint8Array>;
    }

    const thash =
      (_: ShaType, h: typeof h0ps, hTmp: typeof h0ps) =>
      (blocks: number, input: TArg<Uint8Array>, addr: TArg<ADRS>): TRet<Uint8Array> => {
        stats.thash++;
        const d = h
          ._cloneInto(hTmp as any)
          .update(addr)
          .update(input.subarray(0, blocks * N))
          .digest();
        return d.subarray(0, N) as TRet<Uint8Array>;
      };
    return {
      PRFaddr: (addr: TArg<ADRS>): TRet<Uint8Array> => {
        if (!sk_seed) throw new Error('No sk seed');
        stats.prf++;
        const res = h0ps
          ._cloneInto(h0tmp as any)
          .update(addr)
          .update(sk_seed)
          .digest()
          .subarray(0, N);
        return res as TRet<Uint8Array>;
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
        const seed = concatBytes(
          R.subarray(0, N),
          pk.subarray(0, N),
          h1.create().update(R.subarray(0, N)).update(pk).update(m).digest()
        );
        return mgf1(seed, outLen, h1);
      },
      thash1: thash(h0, h0ps, h0tmp).bind(null, 1),
      thashN: thash(h1, h1ps, h1tmp),
      clean: () => {
        h0ps.destroy();
        h1ps.destroy();
        h0tmp.destroy();
        h1tmp.destroy();
        //console.log(stats);
      },
    } as TRet<Context>;
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
