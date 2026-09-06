import { UnsecureError } from "../errors.ts";

/**
 * BLAKE2b (RFC 7693) in plain JavaScript.
 *
 * Web Crypto has no BLAKE2b, so `hash()` cannot reach it and this stays internal: it exists
 * because Argon2 (RFC 9106) is defined on top of it, and it is shaped for that caller —
 * synchronous, `Uint8Array` in and out, streaming `update()` so `H'` can feed a digest its
 * prefix without concatenating buffers.
 *
 * 64-bit words are kept as adjacent little-endian 32-bit halves in a `Uint32Array` (`w[2i]` low,
 * `w[2i + 1]` high) rather than as `BigInt`, which would be roughly two orders of magnitude
 * slower in the compression loop.
 */

/** RFC 7693 §2.6 IV, as low/high 32-bit halves. */
const _IV = /* @__PURE__ */ new Uint32Array([
  0xf3bc_c908, 0x6a09_e667, 0x84ca_a73b, 0xbb67_ae85, 0xfe94_f82b, 0x3c6e_f372, 0x5f1d_36f1,
  0xa54f_f53a, 0xade6_82d1, 0x510e_527f, 0x2b3e_6c1f, 0x9b05_688c, 0xfb41_bd6b, 0x1f83_d9ab,
  0x137e_2179, 0x5be0_cd19,
]);

/**
 * RFC 7693 §2.7 message schedule, pre-doubled into low-half indices of the message array.
 * Rounds 10 and 11 repeat rounds 0 and 1.
 */
const _SIGMA: Uint8Array = /* @__PURE__ */ (() => {
  // prettier-ignore
  const rows = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
  ];
  const table = new Uint8Array(12 * 16);
  for (let round = 0; round < 12; round++) {
    const row = rows[round % 10];
    for (let i = 0; i < 16; i++) table[round * 16 + i] = row[i] * 2;
  }
  return table;
})();

/** Compression scratch, reused across calls — every user of it runs to completion synchronously. */
const _V = /* @__PURE__ */ new Uint32Array(32);
const _M = /* @__PURE__ */ new Uint32Array(32);

/** `v[a] += (hi, lo)`, carrying into the high half. */
function _add(a: number, lo: number, hi: number): void {
  const sum = _V[a] + lo;
  _V[a] = sum;
  _V[a + 1] = _V[a + 1] + hi + (sum >= 0x1_0000_0000 ? 1 : 0);
}

/** RFC 7693 §3.1 mixing function `G`, on low-half indices into {@link _V} / {@link _M}. */
function _mix(a: number, b: number, c: number, d: number, x: number, y: number): void {
  _add(a, _V[b], _V[b + 1]);
  _add(a, _M[x], _M[x + 1]);

  // d = rotr64(d ^ a, 32) — a 32-bit rotation is a half swap.
  let lo = _V[d] ^ _V[a];
  let hi = _V[d + 1] ^ _V[a + 1];
  _V[d] = hi;
  _V[d + 1] = lo;

  _add(c, _V[d], _V[d + 1]);

  // b = rotr64(b ^ c, 24)
  lo = _V[b] ^ _V[c];
  hi = _V[b + 1] ^ _V[c + 1];
  _V[b] = (lo >>> 24) | (hi << 8);
  _V[b + 1] = (hi >>> 24) | (lo << 8);

  _add(a, _V[b], _V[b + 1]);
  _add(a, _M[y], _M[y + 1]);

  // d = rotr64(d ^ a, 16)
  lo = _V[d] ^ _V[a];
  hi = _V[d + 1] ^ _V[a + 1];
  _V[d] = (lo >>> 16) | (hi << 16);
  _V[d + 1] = (hi >>> 16) | (lo << 16);

  _add(c, _V[d], _V[d + 1]);

  // b = rotr64(b ^ c, 63), which is a single-bit left rotation.
  lo = _V[b] ^ _V[c];
  hi = _V[b + 1] ^ _V[c + 1];
  _V[b] = (hi >>> 31) | (lo << 1);
  _V[b + 1] = (lo >>> 31) | (hi << 1);
}

class _Blake2b {
  /** Chain value `h`, eight 64-bit words as low/high halves. */
  private readonly h = new Uint32Array(16);
  /** The 128-byte block being filled. */
  private readonly block = new Uint8Array(128);
  /** Bytes currently held in {@link block}. */
  private filled = 0;
  /** Byte counter `t`, low and high halves. */
  private counterLo = 0;
  private counterHi = 0;
  /** Digest length in bytes. */
  private readonly outLength: number;

  constructor(outLength: number, key?: Uint8Array) {
    this.outLength = outLength;
    const keyLength = key === undefined ? 0 : key.length;
    this.h.set(_IV);
    // Parameter block §2.5: digest length, key length, fanout 1, depth 1.
    this.h[0] ^= 0x0101_0000 ^ (keyLength << 8) ^ outLength;
    if (key !== undefined && keyLength > 0) {
      this.update(key);
      // A keyed hash consumes a whole zero-padded block before the message.
      this.filled = 128;
    }
  }

  update(data: Uint8Array): this {
    let offset = 0;
    while (offset < data.length) {
      // Only flush once more input is known to follow: the last block is the finalized one.
      if (this.filled === 128) {
        this._count(128);
        this._compress(false);
        this.filled = 0;
      }
      const take = Math.min(128 - this.filled, data.length - offset);
      this.block.set(data.subarray(offset, offset + take), this.filled);
      this.filled += take;
      offset += take;
    }
    return this;
  }

  digest(): Uint8Array<ArrayBuffer> {
    this._count(this.filled);
    this.block.fill(0, this.filled);
    this._compress(true);

    const out = new Uint8Array(this.outLength);
    // `h` already sits in little-endian order, so each byte is a shift out of its half.
    for (let i = 0; i < out.length; i++) out[i] = (this.h[i >>> 2] >>> ((i & 3) << 3)) & 0xff;

    // The state is single-use, so neither the chain value nor the last block needs to survive
    // the digest; the shared scratch would otherwise hold that block until the next call.
    this.h.fill(0);
    this.block.fill(0);
    _V.fill(0);
    _M.fill(0);
    return out;
  }

  private _count(bytes: number): void {
    this.counterLo += bytes;
    if (this.counterLo >= 0x1_0000_0000) {
      this.counterLo -= 0x1_0000_0000;
      this.counterHi += 1;
    }
  }

  private _compress(last: boolean): void {
    for (let i = 0; i < 16; i++) _V[i] = this.h[i];
    _V.set(_IV, 16);
    _V[24] ^= this.counterLo;
    _V[25] ^= this.counterHi;
    if (last) {
      _V[28] = ~_V[28];
      _V[29] = ~_V[29];
    }

    for (let i = 0; i < 32; i++) {
      const o = i << 2;
      _M[i] =
        this.block[o] |
        (this.block[o + 1] << 8) |
        (this.block[o + 2] << 16) |
        (this.block[o + 3] << 24);
    }

    for (let round = 0; round < 12; round++) {
      const s = round * 16;
      _mix(0, 8, 16, 24, _SIGMA[s], _SIGMA[s + 1]);
      _mix(2, 10, 18, 26, _SIGMA[s + 2], _SIGMA[s + 3]);
      _mix(4, 12, 20, 28, _SIGMA[s + 4], _SIGMA[s + 5]);
      _mix(6, 14, 22, 30, _SIGMA[s + 6], _SIGMA[s + 7]);
      _mix(0, 10, 20, 30, _SIGMA[s + 8], _SIGMA[s + 9]);
      _mix(2, 12, 22, 24, _SIGMA[s + 10], _SIGMA[s + 11]);
      _mix(4, 14, 16, 26, _SIGMA[s + 12], _SIGMA[s + 13]);
      _mix(6, 8, 18, 28, _SIGMA[s + 14], _SIGMA[s + 15]);
    }

    for (let i = 0; i < 16; i++) this.h[i] ^= _V[i] ^ _V[i + 16];
  }
}

/** An incremental BLAKE2b digest. Feed it with {@link Blake2bHasher.update}, close it once. */
export interface Blake2bHasher {
  /** Absorb more input. Returns `this` so calls chain. */
  update(data: Uint8Array): Blake2bHasher;
  /** Finalize and return `outLength` bytes. Call once — the state is not reusable afterwards. */
  digest(): Uint8Array<ArrayBuffer>;
}

/**
 * Create an incremental BLAKE2b digest.
 *
 * @param outLength Digest length in bytes, 1–64. @default 64
 * @param key Optional MAC key, up to 64 bytes.
 * @returns A hasher accepting `update()` calls followed by one `digest()`.
 *
 * @throws {UnsecureError} `OUT_OF_RANGE` If `outLength` or the key length is outside
 * 1–64 / 0–64.
 */
export function createBlake2b(outLength: number = 64, key?: Uint8Array): Blake2bHasher {
  if (!Number.isInteger(outLength) || outLength < 1 || outLength > 64) {
    throw new UnsecureError(
      "OUT_OF_RANGE",
      "blake2b: outLength must be an integer between 1 and 64.",
    );
  }
  if (key !== undefined && key.length > 64) {
    throw new UnsecureError("OUT_OF_RANGE", "blake2b: key must be at most 64 bytes.");
  }
  return new _Blake2b(outLength, key);
}

/**
 * One-shot BLAKE2b.
 *
 * @param data The message bytes.
 * @param outLength Digest length in bytes, 1–64. @default 64
 * @param key Optional MAC key, up to 64 bytes.
 * @returns The digest.
 *
 * @example
 * blake2b(new TextEncoder().encode("abc"), 64);
 */
export function blake2b(
  data: Uint8Array,
  outLength: number = 64,
  key?: Uint8Array,
): Uint8Array<ArrayBuffer> {
  return createBlake2b(outLength, key).update(data).digest();
}
