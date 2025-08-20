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
  type VerOpts,
} from './utils.ts';

/**
 * * N: Security parameter (in bytes). W: Winternitz parameter
 * * H: Hypertree height. D: Hypertree layers
 * * K: FORS trees numbers. A: FORS trees height
 */
export type SphincsOpts = {
  N: number;
  W: number;
  H: number;
  D: number;
  K: number;
  A: number;
  securityLevel: number;
};

export type SphincsHashOpts = {
  isCompressed?: boolean;
  getContext: GetContext;
};

/** Winternitz signature params. */
export const PARAMS: Record<string, SphincsOpts> = {
  '128f': { W: 16, N: 16, H: 66, D: 22, K: 33, A: 6, securityLevel: 128 },
  '128s': { W: 16, N: 16, H: 63, D: 7, K: 14, A: 12, securityLevel: 128 },
  '192f': { W: 16, N: 24, H: 66, D: 22, K: 33, A: 8, securityLevel: 192 },
  '192s': { W: 16, N: 24, H: 63, D: 7, K: 17, A: 14, securityLevel: 192 },
  '256f': { W: 16, N: 32, H: 68, D: 17, K: 35, A: 9, securityLevel: 256 },
  '256s': { W: 16, N: 32, H: 64, D: 8, K: 22, A: 14, securityLevel: 256 },
} as const;

const AddressType = {
  WOTS: 0,
  WOTSPK: 1,
  HASHTREE: 2,
  FORSTREE: 3,
  FORSPK: 4,
  WOTSPRF: 5,
  FORSPRF: 6,
} as const;

/** Address, byte array of size ADDR_BYTES */
export type ADRS = Uint8Array;

export type Context = {
  PRFaddr: (addr: ADRS) => Uint8Array;
  PRFmsg: (skPRF: Uint8Array, random: Uint8Array, msg: Uint8Array) => Uint8Array;
  Hmsg: (R: Uint8Array, pk: Uint8Array, m: Uint8Array, outLen: number) => Uint8Array;
  thash1: (input: Uint8Array, addr: ADRS) => Uint8Array;
  thashN: (blocks: number, input: Uint8Array, addr: ADRS) => Uint8Array;
  clean: () => void;
};
export type GetContext = (
  opts: SphincsOpts
) => (pub_seed: Uint8Array, sk_seed?: Uint8Array) => Context;

function hexToNumber(hex: string): bigint {
  if (typeof hex !== 'string') throw new Error('hex string expected, got ' + typeof hex);
  return BigInt(hex === '' ? '0' : '0x' + hex); // Big Endian
}

// BE: Big Endian, LE: Little Endian
function bytesToNumberBE(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex(bytes));
}

function numberToBytesBE(n: number | bigint, len: number): Uint8Array {
  return hexToBytes(n.toString(16).padStart(len * 2, '0'));
}

// Same as bitsCoder.decode, but maybe spec will change and unify with base2bBE.
const base2b = (outLen: number, b: number) => {
  const mask = getMask(b);
  return (bytes: Uint8Array) => {
    const baseB = new Uint32Array(outLen);
    for (let out = 0, pos = 0, bits = 0, total = 0; out < outLen; out++) {
      while (bits < b) {
        total = (total << 8) | bytes[pos++];
        bits += 8;
      }
      bits -= b;
      baseB[out] = (total >>> bits) & mask;
    }
    return baseB;
  };
};

function getMaskBig(bits: number) {
  return (1n << BigInt(bits)) - 1n; // 4 -> 0b1111
}

export type SphincsSigner = Signer & {
  internal: Signer;
  securityLevel: number;
  prehash: (hash: CHash) => Signer;
};

function gen(opts: SphincsOpts, hashOpts: SphincsHashOpts): SphincsSigner {
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

  const setAddr = (
    opts: {
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
    },
    addr: ADRS = new Uint8Array(ADDR_BYTES)
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
  const chainLengths = (msg: Uint8Array) => {
    const W1 = base2b(WOTS_LEN1, WOTS_LOGW)(msg);
    let csum = 0;
    for (let i = 0; i < W1.length; i++) csum += W - 1 - W1[i]; // ▷ Compute checksum
    csum <<= (8 - ((WOTS_LEN2 * WOTS_LOGW) % 8)) % 8; // csum ← csum ≪ ((8 − ((len2 · lg(w)) mod 8)) mod 8
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
  const hashMessage = (R: Uint8Array, pkSeed: Uint8Array, msg: Uint8Array, context: Context) => {
    const digest = context.Hmsg(R, pkSeed, msg, hashMsgCoder.bytesLen); // digest ← Hmsg(R, PK.seed, PK.root, M)
    const [md, tmpIdxTree, tmpIdxLeaf] = hashMsgCoder.decode(digest);
    const tree = bytesToNumberBE(tmpIdxTree) & getMaskBig(TREE_BITS);
    const leafIdx = Number(bytesToNumberBE(tmpIdxLeaf)) & getMask(LEAF_BITS);
    return { tree, leafIdx, md };
  };

  const treehash = <T>(
    height: number,
    fn: (leafIdx: number, addrOffset: number, context: Context, info: T) => Uint8Array
  ) =>
    function treehash_i(
      context: Context,
      leafIdx: number,
      idxOffset: number,
      treeAddr: ADRS,
      info: T
    ) {
      const maxIdx = (1 << height) - 1;
      const stack = new Uint8Array(height * N);
      const authPath = new Uint8Array(height * N);
      for (let idx = 0; ; idx++) {
        const current = new Uint8Array(2 * N);
        const cur0 = current.subarray(0, N);
        const cur1 = current.subarray(N);
        const addrOffset = idx + idxOffset;
        cur1.set(fn(leafIdx, addrOffset, context, info));
        let h = 0;
        for (let i = idx, o = idxOffset, l = leafIdx; ; h++, i >>>= 1, l >>>= 1, o >>>= 1) {
          if (h === height) return { root: cur1, authPath }; // Returns from here
          if ((i ^ l) === 1) authPath.subarray(h * N).set(cur1); // authPath.push(cur1)
          if ((i & 1) === 0 && idx < maxIdx) break;
          setAddr({ height: h + 1, index: (i >> 1) + (o >> 1) }, treeAddr);
          cur0.set(stack.subarray(h * N).subarray(0, N));
          cur1.set(context.thashN(2, current, treeAddr));
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
  const wotsTreehash = treehash(TREE_HEIGHT, (leafIdx, addrOffset, context, info: LeafInfo) => {
    const wotsPk = new Uint8Array(WOTS_LEN * N);
    const wotsKmask = addrOffset === leafIdx ? 0 : ~0 >>> 0;
    setAddr({ keypair: addrOffset }, info.leafAddr);
    setAddr({ keypair: addrOffset }, info.pkAddr);
    for (let i = 0; i < WOTS_LEN; i++) {
      const wotsK = info.wotsSteps[i] | wotsKmask;
      const pk = wotsPk.subarray(i * N, (i + 1) * N);
      setAddr({ chain: i, hash: 0, type: AddressType.WOTSPRF }, info.leafAddr);
      pk.set(context.PRFaddr(info.leafAddr));
      setAddr({ type: AddressType.WOTS }, info.leafAddr);
      for (let k = 0; ; k++) {
        if (k === wotsK) info.wotsSig.subarray(i * N).set(pk); //wotsSig.push()
        if (k === W - 1) break;
        setAddr({ hash: k }, info.leafAddr);
        pk.set(context.thash1(pk, info.leafAddr));
      }
    }
    return context.thashN(WOTS_LEN, wotsPk, info.pkAddr);
  });

  const forsTreehash = treehash(A, (_, addrOffset, context, forsLeafAddr: ForsLeafInfo) => {
    setAddr({ type: AddressType.FORSPRF, index: addrOffset }, forsLeafAddr);
    const prf = context.PRFaddr(forsLeafAddr);
    setAddr({ type: AddressType.FORSTREE }, forsLeafAddr);
    return context.thash1(prf, forsLeafAddr);
  });

  const merkleSign = (
    context: Context,
    wotsAddr: ADRS,
    treeAddr: ADRS,
    leafIdx: number,
    prevRoot: Uint8Array = new Uint8Array(N)
  ) => {
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
    };
  };

  type ForsLeafInfo = ADRS;

  const computeRoot = (
    leaf: Uint8Array,
    leafIdx: number,
    idxOffset: number,
    authPath: Uint8Array,
    treeHeight: number,
    context: Context,
    addr: ADRS
  ) => {
    const buffer = new Uint8Array(2 * N);
    const b0 = buffer.subarray(0, N);
    const b1 = buffer.subarray(N, 2 * N);
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
        b1.set(context.thashN(2, buffer, addr));
        b0.set(a);
      } else {
        buffer.set(context.thashN(2, buffer, addr));
        b1.set(a);
      }
    }
    // Root
    setAddr({ height: treeHeight, index: leafIdx + idxOffset }, addr);
    return context.thashN(2, buffer, addr);
  };

  const seedCoder = splitCoder('seed', N, N, N);
  const publicCoder = splitCoder('publicKey', N, N);
  const secretCoder = splitCoder('secretKey', N, N, publicCoder.bytesLen);
  const forsCoder = vecCoder(splitCoder('fors', N, N * A), K);
  const wotsCoder = vecCoder(splitCoder('wots', WOTS_LEN * N, TREE_HEIGHT * N), D);
  const sigCoder = splitCoder('signature', N, forsCoder, wotsCoder); // random || fors || wots
  const internal: Signer = {
    info: { type: 'internal-slh-dsa' },
    lengths: {
      publicKey: publicCoder.bytesLen,
      secretKey: secretCoder.bytesLen,
      signature: sigCoder.bytesLen,
      seed: seedCoder.bytesLen,
      signRand: N,
    },
    keygen(seed?: Uint8Array) {
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
      return { publicKey, secretKey };
    },
    getPublicKey: (secretKey: Uint8Array) => {
      const [_skSeed, _skPRF, pk] = secretCoder.decode(secretKey);
      return Uint8Array.from(pk);
    },
    sign: (msg: Uint8Array, sk: Uint8Array, opts: SigOpts = {}) => {
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
      return SIG;
    },
    verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array) => {
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
  };
  return {
    info: { type: 'slh-dsa' },
    internal,
    securityLevel: securityLevel,
    lengths: internal.lengths,
    keygen: internal.keygen,
    getPublicKey: internal.getPublicKey,
    sign: (msg: Uint8Array, secretKey: Uint8Array, opts: SigOpts = {}) => {
      validateSigOpts(opts);
      const M = getMessage(msg, opts.context);
      const res = internal.sign(M, secretKey, opts);
      cleanBytes(M);
      return res;
    },
    verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array, opts: VerOpts = {}) => {
      validateVerOpts(opts);
      return internal.verify(sig, getMessage(msg, opts.context), publicKey);
    },
    prehash: (hash: CHash) => {
      checkHash(hash, securityLevel);
      return {
        info: { type: 'hashslh-dsa' },
        lengths: internal.lengths,
        keygen: internal.keygen,
        getPublicKey: internal.getPublicKey,
        sign: (msg: Uint8Array, secretKey: Uint8Array, opts: SigOpts = {}) => {
          validateSigOpts(opts);
          const M = getMessagePrehash(hash, msg, opts.context);
          const res = internal.sign(M, secretKey, opts);
          cleanBytes(M);
          return res;
        },
        verify: (sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array, opts: VerOpts = {}) => {
          validateVerOpts(opts);
          return internal.verify(sig, getMessagePrehash(hash, msg, opts.context), publicKey);
        },
      };
    },
  };
}

const genShake =
  (): GetContext => (opts: SphincsOpts) => (pubSeed: Uint8Array, skSeed?: Uint8Array) => {
    const { N } = opts;
    const stats = { prf: 0, thash: 0, hmsg: 0, gen_message_random: 0 };
    const h0 = shake256.create({}).update(pubSeed);
    const h0tmp = h0.clone();
    const thash = (blocks: number, input: Uint8Array, addr: ADRS) => {
      stats.thash++;
      return h0
        ._cloneInto(h0tmp)
        .update(addr)
        .update(input.subarray(0, blocks * N))
        .xof(N);
    };
    return {
      PRFaddr: (addr: ADRS) => {
        if (!skSeed) throw new Error('no sk seed');
        stats.prf++;
        const res = h0._cloneInto(h0tmp).update(addr).update(skSeed).xof(N);
        return res;
      },
      PRFmsg: (skPRF: Uint8Array, random: Uint8Array, msg: Uint8Array) => {
        stats.gen_message_random++;
        return shake256.create({}).update(skPRF).update(random).update(msg).digest().subarray(0, N);
      },
      Hmsg: (R: Uint8Array, pk: Uint8Array, m: Uint8Array, outLen) => {
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
    };
  };

const SHAKE_SIMPLE = { getContext: genShake() };

/** SLH-DSA: 128-bit fast SHAKE version. */
export const slh_dsa_shake_128f: SphincsSigner = /* @__PURE__ */ gen(PARAMS['128f'], SHAKE_SIMPLE);
/** SLH-DSA: 128-bit short SHAKE version. */
export const slh_dsa_shake_128s: SphincsSigner = /* @__PURE__ */ gen(PARAMS['128s'], SHAKE_SIMPLE);
/** SLH-DSA: 192-bit fast SHAKE version. */
export const slh_dsa_shake_192f: SphincsSigner = /* @__PURE__ */ gen(PARAMS['192f'], SHAKE_SIMPLE);
/** SLH-DSA: 192-bit short SHAKE version. */
export const slh_dsa_shake_192s: SphincsSigner = /* @__PURE__ */ gen(PARAMS['192s'], SHAKE_SIMPLE);
/** SLH-DSA: 256-bit fast SHAKE version. */
export const slh_dsa_shake_256f: SphincsSigner = /* @__PURE__ */ gen(PARAMS['256f'], SHAKE_SIMPLE);
/** SLH-DSA: 256-bit short SHAKE version. */
export const slh_dsa_shake_256s: SphincsSigner = /* @__PURE__ */ gen(PARAMS['256s'], SHAKE_SIMPLE);

type ShaType = typeof sha256 | typeof sha512;
const genSha =
  (h0: ShaType, h1: ShaType): GetContext =>
  (opts) =>
  (pub_seed, sk_seed?) => {
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
    function mgf1(seed: Uint8Array, length: number, hash: ShaType) {
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
      return out.subarray(0, length);
    }

    const thash =
      (_: ShaType, h: typeof h0ps, hTmp: typeof h0ps) =>
      (blocks: number, input: Uint8Array, addr: ADRS) => {
        stats.thash++;
        const d = h
          ._cloneInto(hTmp as any)
          .update(addr)
          .update(input.subarray(0, blocks * N))
          .digest();
        return d.subarray(0, N);
      };
    return {
      PRFaddr: (addr: ADRS) => {
        if (!sk_seed) throw new Error('No sk seed');
        stats.prf++;
        const res = h0ps
          ._cloneInto(h0tmp as any)
          .update(addr)
          .update(sk_seed)
          .digest()
          .subarray(0, N);
        return res;
      },
      PRFmsg: (skPRF: Uint8Array, random: Uint8Array, msg: Uint8Array) => {
        stats.gen_message_random++;
        return hmac.create(h1, skPRF).update(random).update(msg).digest().subarray(0, N);
      },
      Hmsg: (R: Uint8Array, pk: Uint8Array, m: Uint8Array, outLen) => {
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
    };
  };

const SHA256_SIMPLE = {
  isCompressed: true,
  getContext: genSha(sha256, sha256),
};
const SHA512_SIMPLE = {
  isCompressed: true,
  getContext: genSha(sha256, sha512),
};

/** SLH-DSA: 128-bit fast SHA2 version. */
export const slh_dsa_sha2_128f: SphincsSigner = /* @__PURE__ */ gen(PARAMS['128f'], SHA256_SIMPLE);
/** SLH-DSA: 128-bit small SHA2 version. */
export const slh_dsa_sha2_128s: SphincsSigner = /* @__PURE__ */ gen(PARAMS['128s'], SHA256_SIMPLE);
/** SLH-DSA: 192-bit fast SHA2 version. */
export const slh_dsa_sha2_192f: SphincsSigner = /* @__PURE__ */ gen(PARAMS['192f'], SHA512_SIMPLE);
/** SLH-DSA: 192-bit small SHA2 version. */
export const slh_dsa_sha2_192s: SphincsSigner = /* @__PURE__ */ gen(PARAMS['192s'], SHA512_SIMPLE);
/** SLH-DSA: 256-bit fast SHA2 version. */
export const slh_dsa_sha2_256f: SphincsSigner = /* @__PURE__ */ gen(PARAMS['256f'], SHA512_SIMPLE);
/** SLH-DSA: 256-bit small SHA2 version. */
export const slh_dsa_sha2_256s: SphincsSigner = /* @__PURE__ */ gen(PARAMS['256s'], SHA512_SIMPLE);
