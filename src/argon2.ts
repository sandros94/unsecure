import type { DigestReturnAs } from "./hash.ts";
import { blake2b, createBlake2b } from "./_internal/blake2b.ts";
import { encodeBytes } from "./_internal/encoding.ts";
import { secureCompare } from "./compare.ts";
import { secureRandomBytes } from "./random.ts";
import { Base64, textEncoder } from "./utils/index.ts";

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
  secret?: string | BufferSource;
  /**
   * Optional associated data `X`. Bound into the tag but, like `secret`, not encoded in the
   * PHC string — supply it again to verify.
   */
  data?: string | BufferSource;
}

export interface Argon2Options extends Argon2Parameters {
  /**
   * Whether to output to HEX, Base64, Base64URL or Uint8Array.
   *
   * When not specified, mirrors the `password` input type:
   * - `string` password defaults to `'hex'`
   * - `BufferSource` password defaults to `'uint8array'`
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
  salt?: string | BufferSource;
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

/** Fixed by the design, not a knob: four slices per pass. */
const _SLICES = 4;

/** 1024-byte block, held as 256 little-endian 32-bit halves. */
const _BLOCK = 256;

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
 * refused by name instead of looking like a syntax error.
 */
const _PHC =
  /^\$([a-z0-9]+)\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/;

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
    v = blake2b(v);
    out.set(v.subarray(0, 32), position);
    position += 32;
  }
  out.set(blake2b(v, length - position), position);
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

function _toBytes(value: string | BufferSource): Uint8Array {
  if (typeof value === "string") return textEncoder.encode(value);
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  return new Uint8Array(value);
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

  if (!_isVariant(variant)) {
    throw new Error(`Unsupported argon2 variant: ${JSON.stringify(variant)}.`);
  }
  if (!Number.isInteger(p) || p < 1 || p >= 2 ** 24) {
    throw new RangeError("argon2: p (parallelism) must be an integer between 1 and 2^24 - 1.");
  }
  if (!Number.isInteger(m) || m < 8 * p) {
    throw new RangeError(
      `argon2: m (memory, KiB) must be an integer of at least 8 * p (${8 * p}).`,
    );
  }
  if (!Number.isInteger(t) || t < 1) {
    throw new RangeError("argon2: t (iterations) must be an integer of at least 1.");
  }
  if (!Number.isInteger(length) || length < 4) {
    throw new RangeError("argon2: length must be an integer of at least 4 bytes.");
  }

  return {
    variant,
    m,
    t,
    p,
    length,
    secret: secret === undefined ? new Uint8Array(0) : _toBytes(secret),
    data: data === undefined ? new Uint8Array(0) : _toBytes(data),
  };
}

/** The whole of RFC 9106 §3.2, from `H_0` to the final tag. */
function _derive(
  password: Uint8Array,
  salt: Uint8Array,
  resolved: _Resolved,
): Uint8Array<ArrayBuffer> {
  const { variant, m, t, p, length, secret, data } = resolved;

  if (salt.length < 8) {
    throw new RangeError("argon2: salt must be at least 8 bytes.");
  }

  // H_0 = BLAKE2b-512(LE32(p) || LE32(T) || LE32(m) || LE32(t) || LE32(v) || LE32(y) ||
  //                   LE32(|P|) || P || LE32(|S|) || S || LE32(|K|) || K || LE32(|X|) || X)
  const word = new Uint8Array(4);
  const initial = createBlake2b(64);
  for (const value of [p, length, m, t, _VERSION, _TYPE[variant]]) {
    _writeLE32(word, 0, value);
    initial.update(word);
  }
  for (const value of [password, salt, secret, data]) {
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
  return _hashPrime(_writeBlock(final), length);
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
 * - `BufferSource` password returns a `Uint8Array<ArrayBuffer>`
 *
 * @param password The secret. Can be a string or any BufferSource.
 * @param salt A unique, non-secret value, at least 8 bytes. 16 is recommended.
 * @param options Variant, cost parameters, optional `secret` / `data`, and output format.
 * @returns A Promise resolving to the tag.
 *
 * @throws {RangeError} If a cost parameter, the tag length, or the salt length is out of range.
 * @throws {Error} If `variant` is not one of the three Argon2 flavours.
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
  password: string | BufferSource,
  salt: string | BufferSource,
  options: Argon2Options & { returnAs: T },
): Promise<T extends "uint8array" | "bytes" ? Uint8Array<ArrayBuffer> : string>;
export async function argon2(
  password: string,
  salt: string | BufferSource,
  options?: Omit<Argon2Options, "returnAs">,
): Promise<string>;
export async function argon2(
  password: BufferSource,
  salt: string | BufferSource,
  options?: Omit<Argon2Options, "returnAs">,
): Promise<Uint8Array<ArrayBuffer>>;
export async function argon2(
  password: string | BufferSource,
  salt: string | BufferSource,
  options?: Omit<Argon2Options, "returnAs">,
): Promise<Uint8Array<ArrayBuffer> | string>;
export async function argon2(
  password: string | BufferSource,
  salt: string | BufferSource,
  options: Argon2Options = {},
): Promise<Uint8Array<ArrayBuffer> | string> {
  const isBufferInput = typeof password !== "string";
  const tag = _derive(_toBytes(password), _toBytes(salt), _resolve(options));
  const effectiveReturnAs = options.returnAs ?? (isBufferInput ? "uint8array" : "hex");
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
 * @throws {RangeError} If a cost parameter, the tag length, or a supplied salt is out of range.
 * @throws {Error} If `variant` is not one of the three Argon2 flavours.
 *
 * @example
 * const stored = await argon2Hash("correct horse battery staple");
 * // "$argon2id$v=19$m=19456,t=2,p=1$…$…"
 */
export async function argon2Hash(
  password: string | BufferSource,
  options: Argon2HashOptions = {},
): Promise<string> {
  const resolved = _resolve(options);
  const salt =
    options.salt === undefined ? secureRandomBytes(_DEFAULT_SALT_LENGTH) : _toBytes(options.salt);
  const tag = _derive(_toBytes(password), salt, resolved);

  const { variant, m, t, p } = resolved;
  const saltText = Base64.stringify(salt, { padding: false });
  const tagText = Base64.stringify(tag, { padding: false });
  return `$${variant}$v=${_VERSION}$m=${m},t=${t},p=${p}$${saltText}$${tagText}`;
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
 * @throws {SyntaxError} If `phc` is not a well-formed PHC string.
 * @throws {Error} If `phc` names a variant or version this module does not implement.
 *
 * @example
 * if (!(await argon2Verify(user.passwordHash, submitted))) refuse();
 */
export async function argon2Verify(
  phc: string,
  password: string | BufferSource,
  options: Argon2VerifyOptions = {},
): Promise<boolean> {
  const parsed = _PHC.exec(phc);
  if (parsed === null) {
    throw new SyntaxError("argon2Verify: malformed PHC string.");
  }

  const [, variant, version, m, t, p, salt, tag] = parsed;
  if (!_isVariant(variant)) {
    throw new Error(`Unsupported argon2 variant: ${JSON.stringify(variant)}.`);
  }
  if (Number(version) !== _VERSION) {
    throw new Error(`Unsupported argon2 version: ${version}. Only 19 (0x13) is supported.`);
  }

  // The alphabet is already constrained by `_PHC`, so a loose decode only tolerates the
  // padding that the PHC format requires be absent.
  const saltBytes = Base64.parse(salt, { loose: true, returnAs: "bytes" });
  const stored = Base64.parse(tag, { loose: true, returnAs: "bytes" });

  const actual = _derive(
    _toBytes(password),
    saltBytes,
    _resolve({
      variant,
      m: Number(m),
      t: Number(t),
      p: Number(p),
      length: stored.length,
      secret: options.secret,
      data: options.data,
    }),
  );

  return secureCompare(stored, actual);
}
