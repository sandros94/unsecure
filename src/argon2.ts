import type { DigestReturnAs } from "./hash.ts";
import { assertInteger } from "./_internal/assert.ts";
import { blake2b, createBlake2b } from "./_internal/blake2b.ts";
import { type BytesSource, describeValue, toBytes } from "./_internal/bytes.ts";
import { assertReturnAs, encodeBytes } from "./_internal/encoding.ts";
import { secureCompare } from "./compare.ts";
import { UnsecureError } from "./errors.ts";
import { secureRandomBytes } from "./random.ts";
import { base64Parse, base64Stringify } from "./utils/index.ts";

// #region Types

/**
 * Which Argon2 flavour to run.
 *
 * - `"argon2id"` — data-independent addressing for the first half-pass, data-dependent after.
 *   The RFC 9106 §4 default, and the right answer unless you know otherwise.
 * - `"argon2i"` — fully data-independent, side-channel resistant, weaker against time-memory
 *   trade-off attacks.
 * - `"argon2d"` — fully data-dependent, strongest against trade-off attacks, leaks memory access
 *   patterns. For settings with no side-channel exposure.
 */
export type Argon2Variant = "argon2id" | "argon2i" | "argon2d";

/** Cost parameters shared by every entry point. */
export interface Argon2Parameters {
  /**
   * Which flavour to run.
   *
   * @default "argon2id"
   */
  variant?: Argon2Variant;
  /**
   * Memory cost in kibibytes. Rounded down to a multiple of `4 * p` blocks, per RFC 9106 §3.1.
   *
   * @default 19456 (19 MiB, OWASP's argon2id recommendation)
   */
  m?: number;
  /**
   * Time cost — the number of passes over memory.
   *
   * @default 2
   */
  t?: number;
  /**
   * Parallelism — the number of lanes. Lanes are computed sequentially here; the parameter
   * still changes the result, so it must match what the tag was produced with.
   *
   * @default 1
   */
  p?: number;
  /**
   * Tag length in bytes. Minimum 4, per RFC 9106 §3.1.
   *
   * @default 32
   */
  length?: number;
  /**
   * Optional secret key `K` — a pepper. Never stored alongside the tag, so a leaked database
   * is not enough to mount an offline attack. Must be supplied again to verify.
   */
  secret?: string | BytesSource;
  /**
   * Optional associated data `X`. Bound into the tag but, like `secret`, not encoded in the
   * PHC string — supply it again to verify.
   */
  data?: string | BytesSource;
}

export interface Argon2Options extends Argon2Parameters {
  /**
   * Whether to output to HEX, Base64, Base64URL or Uint8Array.
   *
   * When not specified, mirrors the `password` input type:
   * - `string` password defaults to `'hex'`
   * - `BytesSource` password defaults to `'uint8array'`
   */
  returnAs?: DigestReturnAs;
}

export interface Argon2HashOptions extends Argon2Parameters {
  /**
   * The salt to use. Supply one only to reproduce a known tag — for stored passwords, letting
   * this default to fresh randomness is the point.
   *
   * @default 16 random bytes from `secureRandomBytes()`
   */
  salt?: string | BytesSource;
}

/** The `secret` / `data` inputs {@link argon2Hash} was called with, if any. */
export type Argon2VerifyOptions = Pick<Argon2Parameters, "secret" | "data">;

// #region Constants

/** The only version this module produces or accepts. `0x10` is refused rather than emulated. */
const _VERSION = 0x13;

/** RFC 9106 §3.1 type `y`. */
const _TYPE: Record<Argon2Variant, number> = { argon2d: 0, argon2i: 1, argon2id: 2 };

/** Whether a string names one of the three flavours. Anything else is refused by name. */
function _isVariant(value: string): value is Argon2Variant {
  return value === "argon2id" || value === "argon2i" || value === "argon2d";
}

/** The one wording for a flavour this module does not implement, wherever the name came from. */
function _unsupportedVariant(source: string, variant: string): UnsecureError {
  return new UnsecureError(
    "UNSUPPORTED",
    `${source}: unsupported argon2 variant ${JSON.stringify(variant)}.`,
  );
}

/** Fixed by the design, not a knob: four slices per pass. */
const _SLICES = 4;

/** 1024-byte block, held as 256 little-endian 32-bit halves. */
const _BLOCK = 256;

/** `H_0` carries every cost, tag length, and input length as a 32-bit word (RFC 9106 §3.1). */
const _MAX_UINT32 = 0xffff_ffff;

/** RFC 9106 §3.1 gives the lane count a 24-bit word of its own. */
const _MAX_UINT24 = 0xff_ffff;

/** OWASP's argon2id parameters, and RFC 9106 §3.1's recommended salt length. */
const _DEFAULT_M = 19_456;
const _DEFAULT_T = 2;
const _DEFAULT_P = 1;
const _DEFAULT_LENGTH = 32;
const _DEFAULT_SALT_LENGTH = 16;

/**
 * `$argon2id$v=19$m=…,t=…,p=…$salt$tag`, the PHC string format.
 *
 * The variant and version are captured rather than spelled out so that an unsupported value is
 * refused by name instead of looking like a syntax error. The version field is optional in the
 * format — a string without one predates `0x13` — so its absence is refused the same way.
 */
const _PHC =
  /^\$([a-z0-9]+)\$(?:v=(\d+)\$)?m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/;

// #region Compression

/** `G`'s working copy of `R`, reused across calls — every caller runs to completion. */
const _R = /* @__PURE__ */ new Uint32Array(_BLOCK);

/**
 * RFC 9106 §3.5 `GB`, on 64-bit word indices into {@link _R}.
 *
 * Each of the four steps is `x = x + y + 2 * trunc32(x) * trunc32(y)` (BlaMka) followed by an
 * XOR and a rotation. The 32x32 -> 64 product is the expensive part: `Math.imul` gives the exact
 * low half, and the high half is recovered from the double-precision product, whose absolute
 * error is under 2^10 and therefore vanishes once the exact low half is removed and the
 * remainder is scaled down by 2^32.
 */
function _mixBlock(a: number, b: number, c: number, d: number): void {
  let al = _R[2 * a];
  let ah = _R[2 * a + 1];
  let bl = _R[2 * b];
  let bh = _R[2 * b + 1];
  let cl = _R[2 * c];
  let ch = _R[2 * c + 1];
  let dl = _R[2 * d];
  let dh = _R[2 * d + 1];
  let ml = 0;
  let mh = 0;
  let sum = 0;
  let xl = 0;
  let xh = 0;

  // A = blamka(A, B); D = rotr64(D ^ A, 32) — a 32-bit rotation is a half swap.
  ml = Math.imul(al, bl);
  mh = (((al >>> 0) * (bl >>> 0) - (ml >>> 0)) / 0x1_0000_0000 + 0.5) | 0;
  sum = (al >>> 0) + (bl >>> 0) + ((ml << 1) >>> 0);
  ah = (ah + bh + ((mh << 1) | (ml >>> 31)) + ((sum / 0x1_0000_0000) | 0)) | 0;
  al = sum | 0;
  xl = dl ^ al;
  xh = dh ^ ah;
  dl = xh;
  dh = xl;

  // C = blamka(C, D); B = rotr64(B ^ C, 24)
  ml = Math.imul(cl, dl);
  mh = (((cl >>> 0) * (dl >>> 0) - (ml >>> 0)) / 0x1_0000_0000 + 0.5) | 0;
  sum = (cl >>> 0) + (dl >>> 0) + ((ml << 1) >>> 0);
  ch = (ch + dh + ((mh << 1) | (ml >>> 31)) + ((sum / 0x1_0000_0000) | 0)) | 0;
  cl = sum | 0;
  xl = bl ^ cl;
  xh = bh ^ ch;
  bl = (xl >>> 24) | (xh << 8);
  bh = (xh >>> 24) | (xl << 8);

  // A = blamka(A, B); D = rotr64(D ^ A, 16)
  ml = Math.imul(al, bl);
  mh = (((al >>> 0) * (bl >>> 0) - (ml >>> 0)) / 0x1_0000_0000 + 0.5) | 0;
  sum = (al >>> 0) + (bl >>> 0) + ((ml << 1) >>> 0);
  ah = (ah + bh + ((mh << 1) | (ml >>> 31)) + ((sum / 0x1_0000_0000) | 0)) | 0;
  al = sum | 0;
  xl = dl ^ al;
  xh = dh ^ ah;
  dl = (xl >>> 16) | (xh << 16);
  dh = (xh >>> 16) | (xl << 16);

  // C = blamka(C, D); B = rotr64(B ^ C, 63), which is a single-bit left rotation.
  ml = Math.imul(cl, dl);
  mh = (((cl >>> 0) * (dl >>> 0) - (ml >>> 0)) / 0x1_0000_0000 + 0.5) | 0;
  sum = (cl >>> 0) + (dl >>> 0) + ((ml << 1) >>> 0);
  ch = (ch + dh + ((mh << 1) | (ml >>> 31)) + ((sum / 0x1_0000_0000) | 0)) | 0;
  cl = sum | 0;
  xl = bl ^ cl;
  xh = bh ^ ch;
  bl = (xh >>> 31) | (xl << 1);
  bh = (xl >>> 31) | (xh << 1);

  _R[2 * a] = al;
  _R[2 * a + 1] = ah;
  _R[2 * b] = bl;
  _R[2 * b + 1] = bh;
  _R[2 * c] = cl;
  _R[2 * c + 1] = ch;
  _R[2 * d] = dl;
  _R[2 * d + 1] = dh;
}

/** RFC 9106 §3.5 permutation `P` over sixteen 64-bit word indices into {@link _R}. */
// prettier-ignore
function _permute(
  v0: number, v1: number, v2: number, v3: number, v4: number, v5: number, v6: number, v7: number,
  v8: number, v9: number, v10: number, v11: number, v12: number, v13: number, v14: number, v15: number,
): void {
  _mixBlock(v0, v4, v8, v12);
  _mixBlock(v1, v5, v9, v13);
  _mixBlock(v2, v6, v10, v14);
  _mixBlock(v3, v7, v11, v15);
  _mixBlock(v0, v5, v10, v15);
  _mixBlock(v1, v6, v11, v12);
  _mixBlock(v2, v7, v8, v13);
  _mixBlock(v3, v4, v9, v14);
}

/**
 * RFC 9106 §3.4 `B[out] = G(B[x], B[y])`, optionally XOR-ed into the block already at `out`
 * (which is what passes after the first do, for version `0x13`).
 *
 * `R = X ^ Y` is staged straight into the destination so neither source block has to be read
 * twice; the permuted copy lives in {@link _R} and is folded back in at the end.
 */
function _compress(
  memory: Uint32Array,
  x: number,
  y: number,
  out: number,
  xorWithPrevious: boolean,
): void {
  if (xorWithPrevious) {
    for (let i = 0; i < _BLOCK; i++) {
      const r = memory[x + i] ^ memory[y + i];
      _R[i] = r;
      memory[out + i] ^= r;
    }
  } else {
    for (let i = 0; i < _BLOCK; i++) {
      const r = memory[x + i] ^ memory[y + i];
      _R[i] = r;
      memory[out + i] = r;
    }
  }

  // Eight rows of sixteen consecutive words, then eight columns strided by sixteen.
  for (let i = 0; i < 128; i += 16) {
    // prettier-ignore
    _permute(
      i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7,
      i + 8, i + 9, i + 10, i + 11, i + 12, i + 13, i + 14, i + 15,
    );
  }
  for (let i = 0; i < 16; i += 2) {
    // prettier-ignore
    _permute(
      i, i + 1, i + 16, i + 17, i + 32, i + 33, i + 48, i + 49,
      i + 64, i + 65, i + 80, i + 81, i + 96, i + 97, i + 112, i + 113,
    );
  }

  for (let i = 0; i < _BLOCK; i++) memory[out + i] ^= _R[i];
}

// #region Core

/** Read a 1024-byte block into `memory` as little-endian words, independent of host endianness. */
function _readBlock(memory: Uint32Array, offset: number, bytes: Uint8Array): void {
  for (let i = 0; i < _BLOCK; i++) {
    const o = i * 4;
    memory[offset + i] =
      bytes[o] | (bytes[o + 1] << 8) | (bytes[o + 2] << 16) | (bytes[o + 3] << 24);
  }
}

/** The inverse of {@link _readBlock}. */
function _writeBlock(words: Uint32Array): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(_BLOCK * 4);
  for (let i = 0; i < _BLOCK; i++) _writeLE32(bytes, i * 4, words[i]);
  return bytes;
}

/** Write `value` as a little-endian 32-bit word. */
function _writeLE32(target: Uint8Array, offset: number, value: number): void {
  target[offset] = value & 0xff;
  target[offset + 1] = (value >>> 8) & 0xff;
  target[offset + 2] = (value >>> 16) & 0xff;
  target[offset + 3] = (value >>> 24) & 0xff;
}

/** RFC 9106 §3.3 variable-length hash `H'`. */
function _hashPrime(input: Uint8Array, length: number): Uint8Array<ArrayBuffer> {
  const prefix = new Uint8Array(4);
  _writeLE32(prefix, 0, length);

  if (length <= 64) return createBlake2b(length).update(prefix).update(input).digest();

  // Each intermediate V contributes only its first 32 bytes; the last one is emitted whole.
  const out = new Uint8Array(length);
  let v = createBlake2b(64).update(prefix).update(input).digest();
  out.set(v.subarray(0, 32));
  let position = 32;
  while (length - position > 64) {
    const next = blake2b(v);
    v.fill(0);
    v = next;
    out.set(v.subarray(0, 32), position);
    position += 32;
  }
  out.set(blake2b(v, length - position), position);
  v.fill(0);
  return out;
}

/** `floor(a * b / 2^32)` for two unsigned 32-bit values, exactly. See {@link _mixBlock}. */
function _mulHigh(a: number, b: number): number {
  const low = Math.imul(a, b) >>> 0;
  return (((a >>> 0) * (b >>> 0) - low) / 0x1_0000_0000 + 0.5) | 0;
}

/**
 * RFC 9106 §3.4.1.2 — map a pseudo-random 32-bit value onto a block index inside the reference
 * area, which is every block already computed that the current one is allowed to look at.
 */
function _indexAlpha(
  pass: number,
  slice: number,
  laneLength: number,
  segmentLength: number,
  index: number,
  random: number,
  sameLane: boolean,
): number {
  let area: number;
  if (pass === 0) {
    if (slice === 0) area = index - 1;
    else if (sameLane) area = slice * segmentLength + index - 1;
    else area = slice * segmentLength + (index === 0 ? -1 : 0);
  } else if (sameLane) {
    area = laneLength - segmentLength + index - 1;
  } else {
    area = laneLength - segmentLength + (index === 0 ? -1 : 0);
  }

  // Quadratic mapping: bias the pick towards recent blocks.
  const relative = area - 1 - _mulHigh(area, _mulHigh(random, random));
  const start = pass !== 0 && slice !== _SLICES - 1 ? (slice + 1) * segmentLength : 0;
  return (start + relative) % laneLength;
}

interface _Resolved {
  variant: Argon2Variant;
  m: number;
  t: number;
  p: number;
  length: number;
  secret: Uint8Array;
  data: Uint8Array;
}

function _resolve(parameters: Argon2Parameters): _Resolved {
  const {
    variant = "argon2id",
    m = _DEFAULT_M,
    t = _DEFAULT_T,
    p = _DEFAULT_P,
    length = _DEFAULT_LENGTH,
    secret,
    data,
  } = parameters;

  if (!_isVariant(variant)) throw _unsupportedVariant("argon2", variant);
  // `p` is checked first because it is what makes the lower bound on `m` a number.
  assertInteger("argon2", "p (parallelism)", p, 1, _MAX_UINT24);
  assertInteger("argon2", "m (memory, KiB)", m, 8 * p, _MAX_UINT32);
  assertInteger("argon2", "t (iterations)", t, 1, _MAX_UINT32);
  assertInteger("argon2", "length", length, 4, _MAX_UINT32);

  return {
    variant,
    m,
    t,
    p,
    length,
    secret: secret === undefined ? new Uint8Array(0) : toBytes(secret, "argon2"),
    data: data === undefined ? new Uint8Array(0) : toBytes(data, "argon2"),
  };
}

/** The whole of RFC 9106 §3.2, from `H_0` to the final tag. */
function _derive(
  password: Uint8Array,
  salt: Uint8Array,
  resolved: _Resolved,
): Uint8Array<ArrayBuffer> {
  const { variant, m, t, p, length, secret, data } = resolved;

  // Every input length goes into `H_0` as a 32-bit word; the salt also carries RFC 9106 §3.1's
  // 8-byte floor, below which two derivations stop being reliably distinct.
  const inputs = [
    ["password", password, 0],
    ["salt", salt, 8],
    ["secret", secret, 0],
    ["data", data, 0],
  ] as const;
  for (const [name, value, minimum] of inputs) {
    assertInteger("argon2", `${name} length`, value.length, minimum, _MAX_UINT32);
  }

  // H_0 = BLAKE2b-512(LE32(p) || LE32(T) || LE32(m) || LE32(t) || LE32(v) || LE32(y) ||
  //                   LE32(|P|) || P || LE32(|S|) || S || LE32(|K|) || K || LE32(|X|) || X)
  const word = new Uint8Array(4);
  const initial = createBlake2b(64);
  for (const value of [p, length, m, t, _VERSION, _TYPE[variant]]) {
    _writeLE32(word, 0, value);
    initial.update(word);
  }
  for (const [, value] of inputs) {
    _writeLE32(word, 0, value.length);
    initial.update(word).update(value);
  }

  // Two spare words after H_0 hold the LE32(0|1) || LE32(lane) suffix of the seed blocks.
  const h0 = new Uint8Array(72);
  h0.set(initial.digest());

  const blocks = 4 * p * Math.floor(m / (_SLICES * p));
  const laneLength = Math.floor(blocks / p);
  const segmentLength = Math.floor(laneLength / _SLICES);
  const memory = new Uint32Array(blocks * _BLOCK);

  for (let lane = 0; lane < p; lane++) {
    _writeLE32(h0, 68, lane);
    _writeLE32(h0, 64, 0);
    _readBlock(memory, _BLOCK * laneLength * lane, _hashPrime(h0, 1024));
    _writeLE32(h0, 64, 1);
    _readBlock(memory, _BLOCK * (laneLength * lane + 1), _hashPrime(h0, 1024));
  }

  // [address block | input block Z | zero block], laid out so `_compress` can address all three.
  const address = new Uint32Array(3 * _BLOCK);
  address[_BLOCK + 6] = blocks;
  address[_BLOCK + 8] = t;
  address[_BLOCK + 10] = _TYPE[variant];

  for (let pass = 0; pass < t; pass++) {
    address[_BLOCK + 0] = pass;
    for (let slice = 0; slice < _SLICES; slice++) {
      address[_BLOCK + 4] = slice;
      // §3.4.1.3: argon2id borrows argon2i's data-independent addressing for the first two
      // slices of the first pass only.
      const independent =
        variant === "argon2i" || (variant === "argon2id" && pass === 0 && slice < 2);

      for (let lane = 0; lane < p; lane++) {
        address[_BLOCK + 2] = lane;
        address[_BLOCK + 12] = 0;

        // The two seed blocks of each lane are already filled.
        const first = pass === 0 && slice === 0 ? 2 : 0;
        if (independent && pass === 0 && slice === 0) {
          address[_BLOCK + 12] += 1;
          _compress(address, _BLOCK, 2 * _BLOCK, 0, false);
          _compress(address, 0, 2 * _BLOCK, 0, false);
        }

        let current = lane * laneLength + slice * segmentLength + first;
        for (let index = first; index < segmentLength; index++, current++) {
          // Only the first block of a lane wraps, and only on passes after the first.
          const previous = current % laneLength ? current - 1 : current + laneLength - 1;

          let j1: number;
          let j2: number;
          if (independent) {
            // One address block covers 128 indices; refresh it when the segment crosses one.
            if (index % 128 === 0) {
              address[_BLOCK + 12] += 1;
              _compress(address, _BLOCK, 2 * _BLOCK, 0, false);
              _compress(address, 0, 2 * _BLOCK, 0, false);
            }
            j1 = address[2 * (index % 128)];
            j2 = address[2 * (index % 128) + 1];
          } else {
            j1 = memory[_BLOCK * previous];
            j2 = memory[_BLOCK * previous + 1];
          }

          const referenceLane = pass === 0 && slice === 0 ? lane : j2 % p;
          const referenceIndex = _indexAlpha(
            pass,
            slice,
            laneLength,
            segmentLength,
            index,
            j1,
            referenceLane === lane,
          );
          const reference = laneLength * referenceLane + referenceIndex;

          _compress(memory, _BLOCK * previous, _BLOCK * reference, _BLOCK * current, pass !== 0);
        }
      }
    }
  }

  // C = B[0][q-1] ^ … ^ B[p-1][q-1], then tag = H'(C).
  const final = new Uint32Array(_BLOCK);
  for (let lane = 0; lane < p; lane++) {
    const last = _BLOCK * (laneLength * lane + laneLength - 1);
    for (let i = 0; i < _BLOCK; i++) final[i] ^= memory[last + i];
  }
  const finalBytes = _writeBlock(final);
  const tag = _hashPrime(finalBytes, length);

  // Nothing derived from the password outlives the call: the collector makes no promise about
  // when it reclaims a buffer, and the module-level scratch would otherwise keep the last block
  // of the last derivation for as long as the module is loaded.
  memory.fill(0);
  address.fill(0);
  h0.fill(0);
  final.fill(0);
  finalBytes.fill(0);
  _R.fill(0);
  return tag;
}

// #region Public API

/**
 * Derive a tag with Argon2 (RFC 9106), in plain JavaScript — no WebAssembly, no native binding,
 * no Node built-ins. Runs anywhere `Uint8Array` does.
 *
 * This is the raw KDF. For storing and checking passwords use {@link argon2Hash} and
 * {@link argon2Verify}, which carry the parameters and the salt in the tag itself.
 *
 * The `async` signature is for symmetry with `hash()`: the derivation runs synchronously on the
 * calling thread until it completes, so `await` does not yield the event loop. Where the caller
 * shares a thread with other traffic, run it in a worker thread.
 *
 * When `returnAs` is not specified, the return type mirrors the `password` input:
 * - `string` password returns a hex `string`
 * - `BytesSource` password returns a `Uint8Array<ArrayBuffer>`
 *
 * @param password The secret. Can be a string or any `BytesSource`.
 * @param salt A unique, non-secret value, at least 8 bytes. 16 is recommended.
 * @param options Variant, cost parameters, optional `secret` / `data`, and output format.
 * @returns A Promise resolving to the tag.
 *
 * @throws {UnsecureError} `OUT_OF_RANGE` if a cost parameter, the tag length, or an input
 * length is outside its range; `UNSUPPORTED` if `variant` is not one of the three Argon2
 * flavours or `returnAs` is not a known encoding; `INVALID_TYPE` if `password`, `salt`,
 * `secret` or `data` is neither text nor bytes.
 *
 * @example
 * // Defaults: argon2id at OWASP's parameters, 32-byte tag
 * const tag = await argon2("correct horse battery staple", salt, { returnAs: "uint8array" });
 *
 * @example
 * // Argon2d, explicit cost, 64-byte key material
 * const key = await argon2(password, salt, {
 *   variant: "argon2d",
 *   m: 65536,
 *   t: 3,
 *   p: 4,
 *   length: 64,
 * });
 */
export async function argon2<T extends DigestReturnAs>(
  password: string | BytesSource,
  salt: string | BytesSource,
  options: Argon2Options & { returnAs: T },
): Promise<T extends "uint8array" | "bytes" ? Uint8Array<ArrayBuffer> : string>;
export async function argon2(
  password: string,
  salt: string | BytesSource,
  options?: Omit<Argon2Options, "returnAs">,
): Promise<string>;
export async function argon2(
  password: BytesSource,
  salt: string | BytesSource,
  options?: Omit<Argon2Options, "returnAs">,
): Promise<Uint8Array<ArrayBuffer>>;
export async function argon2(
  password: string | BytesSource,
  salt: string | BytesSource,
  options?: Omit<Argon2Options, "returnAs">,
): Promise<Uint8Array<ArrayBuffer> | string>;
export async function argon2(
  password: string | BytesSource,
  salt: string | BytesSource,
  options: Argon2Options = {},
): Promise<Uint8Array<ArrayBuffer> | string> {
  const { returnAs } = options;
  // Before the derivation, not after it: an unknown `returnAs` is a caller mistake, and
  // reporting it should not cost a full hash first.
  assertReturnAs(returnAs, "argon2");

  const isBufferInput = typeof password !== "string";
  const tag = _derive(toBytes(password, "argon2"), toBytes(salt, "argon2"), _resolve(options));
  const effectiveReturnAs = returnAs ?? (isBufferInput ? "uint8array" : "hex");
  return encodeBytes(tag, effectiveReturnAs, "argon2");
}

/**
 * Hash a password into a PHC string — `$argon2id$v=19$m=…,t=…,p=…$salt$tag` — with a fresh
 * random salt.
 *
 * The parameters travel with the tag, so raising the cost later does not invalidate what is
 * already stored: an old hash still verifies at the cost it was made with, and can be rewritten
 * on next use.
 *
 * Runs synchronously on the calling thread despite the `async` signature — see {@link argon2}.
 *
 * @param password The plaintext.
 * @param options Variant, cost parameters, optional `secret` / `data`, and an optional `salt`.
 * @returns A Promise resolving to the PHC string.
 *
 * @throws {UnsecureError} `OUT_OF_RANGE` if a cost parameter, the tag length, or a supplied
 * salt is outside its range; `UNSUPPORTED` if `variant` is not one of the three Argon2
 * flavours; `INVALID_TYPE` if `password`, `salt`, `secret` or `data` is neither text nor bytes.
 *
 * @example
 * const stored = await argon2Hash("correct horse battery staple");
 * // "$argon2id$v=19$m=19456,t=2,p=1$…$…"
 */
export async function argon2Hash(
  password: string | BytesSource,
  options: Argon2HashOptions = {},
): Promise<string> {
  const resolved = _resolve(options);
  const salt =
    options.salt === undefined
      ? secureRandomBytes(_DEFAULT_SALT_LENGTH)
      : toBytes(options.salt, "argon2");
  const tag = _derive(toBytes(password, "argon2"), salt, resolved);

  const { variant, m, t, p } = resolved;
  const saltText = base64Stringify(salt, { padding: false });
  const tagText = base64Stringify(tag, { padding: false });
  return `$${variant}$v=${_VERSION}$m=${m},t=${t},p=${p}$${saltText}$${tagText}`;
}

/**
 * Read one base64 field out of a PHC string, strictly.
 *
 * `_PHC` already constrains the alphabet, but not what the characters mean: a length one past a
 * whole group, or bits set beyond the final byte, is text no encoder produced. A lenient decode
 * answers such a string with `false`, which reads as "wrong password" and hides the corruption;
 * the strict codec calls it what it is. Padding is absent in this format and the strict decode
 * is padding-agnostic, so the fields are accepted as written.
 */
function _decodeField(field: string, source: string): Uint8Array<ArrayBuffer> {
  try {
    return base64Parse(field, { returnAs: "bytes" });
  } catch (error) {
    if (error instanceof UnsecureError && error.code === "MALFORMED") {
      throw new UnsecureError("MALFORMED", `${source}: malformed PHC string.`, { cause: error });
    }
    throw error;
  }
}

/** What a PHC string says, once it is known to be one this module can read. */
interface _Stored {
  variant: Argon2Variant;
  /** `0x10` when the string carries no `v=` field, which is what its absence means. */
  version: number;
  /** The `v=` field as written, or `undefined` — the two are reported differently. */
  versionField: string | undefined;
  m: number;
  t: number;
  p: number;
  salt: Uint8Array<ArrayBuffer>;
  tag: Uint8Array<ArrayBuffer>;
}

/**
 * Read a stored PHC string, or refuse it by name.
 *
 * Shared by {@link argon2Verify} and {@link argon2NeedsRehash} so both agree on exactly which
 * strings are readable; `source` is the function the caller wrote, which is what its message
 * has to say. The version is returned rather than judged: whether an old one is an error or an
 * answer depends on which of the two is asking.
 */
function _parsePhc(phc: string, source: string): _Stored {
  // A value that is not a string never claimed to be a PHC string, so it is a caller mistake
  // rather than a stored value in a shape nobody migrated.
  if (typeof phc !== "string") {
    throw new UnsecureError(
      "INVALID_TYPE",
      `${source}: expected a PHC string, got ${describeValue(phc)}.`,
    );
  }

  const parsed = _PHC.exec(phc);
  if (parsed === null) {
    throw new UnsecureError("MALFORMED", `${source}: malformed PHC string.`);
  }

  const [, variant, , m, t, p, salt, tag] = parsed;
  // An unmatched optional group is `undefined` at runtime whatever the array type says.
  const versionField: string | undefined = parsed[2];
  if (!_isVariant(variant)) throw _unsupportedVariant(source, variant);

  return {
    variant,
    version: versionField === undefined ? 0x10 : Number(versionField),
    versionField,
    m: Number(m),
    t: Number(t),
    p: Number(p),
    salt: _decodeField(salt, source),
    tag: _decodeField(tag, source),
  };
}

/**
 * Check a password against a PHC string produced by {@link argon2Hash}.
 *
 * Everything needed to reproduce the tag — variant, version, cost, salt, tag length — is read
 * back out of `phc` rather than from any default here, and the comparison runs through
 * {@link secureCompare} so it takes the same time whether the guess is close or not.
 *
 * A `phc` this module cannot have written is refused by throwing, not by returning `false`: a
 * stored value in an unknown format is a bug or a migration nobody performed, and answering
 * "wrong password" would hide it.
 *
 * Runs synchronously on the calling thread despite the `async` signature — see {@link argon2}.
 *
 * @param phc The stored PHC string.
 * @param password The plaintext offered.
 * @param options The `secret` / `data` the hash was produced with, if any.
 * @returns A Promise resolving to whether they match.
 *
 * @throws {UnsecureError} `MALFORMED` if `phc` is a string that is not a well-formed PHC
 * string; `UNSUPPORTED` if it names a variant or version this module does not implement;
 * `OUT_OF_RANGE` if the cost parameters or the salt it carries are outside their range;
 * `INVALID_TYPE` if `phc` is not a string, or `password`, `secret` or `data` is neither text
 * nor bytes.
 *
 * @example
 * if (!(await argon2Verify(user.passwordHash, submitted))) refuse();
 */
export async function argon2Verify(
  phc: string,
  password: string | BytesSource,
  options: Argon2VerifyOptions = {},
): Promise<boolean> {
  const { variant, version, versionField, m, t, p, salt, tag } = _parsePhc(phc, "argon2Verify");
  // A string with no `v=` field predates version 0x13, so it is refused by version rather than
  // by shape. Reproducing a tag under a version this module does not implement is not possible;
  // `argon2NeedsRehash` is where such a string gets an answer instead of a throw.
  if (version !== _VERSION) {
    const found = versionField === undefined ? `${version} (no v= field)` : versionField;
    throw new UnsecureError(
      "UNSUPPORTED",
      `argon2Verify: unsupported argon2 version ${found}; only 19 (0x13) is supported.`,
    );
  }

  const actual = _derive(
    toBytes(password, "argon2"),
    salt,
    _resolve({
      variant,
      m,
      t,
      p,
      length: tag.length,
      secret: options.secret,
      data: options.data,
    }),
  );

  return secureCompare(tag, actual);
}

/**
 * Whether a stored PHC string was produced with parameters other than the ones asked for.
 *
 * Call it after a successful {@link argon2Verify}, while the plaintext is still in hand, to
 * rewrite old hashes as their owners log in. With no `parameters` it answers "is this hash at
 * today's defaults?", resolving them exactly as {@link argon2Hash} would, so raising a default
 * is enough to start the migration.
 *
 * A version other than `0x13` is `true` rather than a throw: an old hash still verifies at the
 * cost it was made with, and needing to be replaced is the answer, not an error. A string this
 * module cannot read at all is refused the way {@link argon2Verify} refuses it.
 *
 * `secret` and `data` never travel in the string, so they are ignored here.
 *
 * @param phc The stored PHC string.
 * @param parameters The parameters a new hash would be written with.
 * @returns Whether the variant, cost, tag length or version differ from `parameters`.
 *
 * @throws {UnsecureError} `MALFORMED` if `phc` is a string that is not a well-formed PHC
 * string; `INVALID_TYPE` if it is not a string at all; `UNSUPPORTED` if it names a variant
 * this module does not implement; `OUT_OF_RANGE` if `parameters` carries a cost or tag length
 * outside its range.
 *
 * @example
 * if (await argon2Verify(user.passwordHash, submitted)) {
 *   if (argon2NeedsRehash(user.passwordHash)) {
 *     user.passwordHash = await argon2Hash(submitted);
 *   }
 * }
 */
export function argon2NeedsRehash(phc: string, parameters: Argon2Parameters = {}): boolean {
  const stored = _parsePhc(phc, "argon2NeedsRehash");
  if (stored.version !== _VERSION) return true;

  const wanted = _resolve({
    variant: parameters.variant,
    m: parameters.m,
    t: parameters.t,
    p: parameters.p,
    length: parameters.length,
  });

  return (
    stored.variant !== wanted.variant ||
    stored.m !== wanted.m ||
    stored.t !== wanted.t ||
    stored.p !== wanted.p ||
    stored.tag.length !== wanted.length
  );
}
