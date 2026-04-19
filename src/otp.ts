import type { DigestAlgorithm } from "./hash.ts";
import { hmac } from "./hmac.ts";
import { base32Encode, base32Decode } from "./internal/utils/base32.ts";
import { secureRandomBytes } from "./random.ts";
import { secureCompare } from "./compare.ts";

// #region Types

export interface HOTPOptions {
  /**
   * Hash algorithm.
   *
   * @default "SHA-1"
   */
  algorithm?: DigestAlgorithm;
  /**
   * Number of digits in the OTP code.
   *
   * @default 6
   */
  digits?: number;
}

export interface HOTPVerifyOptions extends HOTPOptions {
  /**
   * Number of counter values to check ahead of the given counter.
   *
   * @default 0
   */
  window?: number;
}

export interface TOTPOptions extends HOTPOptions {
  /**
   * Time step duration in seconds.
   *
   * @default 30
   */
  period?: number;
  /**
   * Unix timestamp in seconds. Defaults to the current time.
   * Useful for testing with deterministic values.
   */
  time?: number;
}

export interface TOTPVerifyOptions extends TOTPOptions {
  /**
   * Number of time steps to check in each direction (past and future).
   *
   * @default 1
   */
  window?: number;
}

export interface OTPAuthURIOptions {
  /** OTP type. */
  type: "hotp" | "totp";
  /** The secret key as raw bytes or a base32-encoded string. */
  secret: Uint8Array | string;
  /** Account name (e.g. user email). */
  account: string;
  /** Issuer name (e.g. service name). */
  issuer?: string;
  /** Hash algorithm. @default "SHA-1" */
  algorithm?: DigestAlgorithm;
  /** Number of digits. @default 6 */
  digits?: number;
  /** HOTP counter value (required when type is "hotp"). */
  counter?: number;
  /** TOTP time step in seconds (only for type "totp"). @default 30 */
  period?: number;
}

// #region Internal helpers

/** Convert a counter to an 8-byte big-endian buffer. */
function _counterToBytes(counter: number): Uint8Array<ArrayBuffer> {
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);
  return buf;
}

/** Dynamic truncation per RFC 4226 §5.3. */
function _dynamicTruncate(hmacResult: Uint8Array, digits: number): string {
  const offset = hmacResult[hmacResult.length - 1]! & 0x0f;
  const code =
    ((hmacResult[offset]! & 0x7f) << 24) |
    ((hmacResult[offset + 1]! & 0xff) << 16) |
    ((hmacResult[offset + 2]! & 0xff) << 8) |
    (hmacResult[offset + 3]! & 0xff);
  return (code % 10 ** digits).toString().padStart(digits, "0");
}

/** Resolve a secret to raw bytes. Strings are treated as base32. */
function _resolveSecret(secret: Uint8Array | string): Uint8Array<ArrayBuffer> {
  return typeof secret === "string"
    ? base32Decode(secret, { returnAs: "uint8array" })
    : (secret as Uint8Array<ArrayBuffer>);
}

/** Algorithm name mapping for otpauth URIs (no hyphens). */
const _URI_ALGORITHM_MAP: Record<DigestAlgorithm, string> = {
  "SHA-1": "SHA1",
  "SHA-256": "SHA256",
  "SHA-384": "SHA384",
  "SHA-512": "SHA512",
};

// #region HOTP

/**
 * Generate an HMAC-based One-Time Password (RFC 4226).
 *
 * @param secret The shared secret key (raw bytes or base32-encoded string).
 * @param counter The moving factor (counter value).
 * @param options Algorithm and digit options.
 * @returns The OTP code as a zero-padded string.
 *
 * @example
 * const code = await hotp(secretBytes, 0);
 * // "755224"
 */
export async function hotp(
  secret: Uint8Array | string,
  counter: number,
  options: HOTPOptions = {},
): Promise<string> {
  const { algorithm = "SHA-1", digits = 6 } = options;
  const secretBytes = _resolveSecret(secret);
  const mac = await hmac(secretBytes, _counterToBytes(counter), {
    algorithm,
    returnAs: "uint8array",
  });
  return _dynamicTruncate(mac, digits);
}

/**
 * Verify an HOTP code, optionally checking a window of counter values ahead.
 *
 * @param secret The shared secret key.
 * @param otp The OTP code to verify.
 * @param counter The expected counter value.
 * @param options Algorithm, digit, and window options.
 * @returns An object with `valid` and `delta` (counter offset that matched).
 *
 * @example
 * const { valid, delta } = await hotpVerify(secret, "287082", 0, { window: 5 });
 * // valid: true, delta: 1 (matched at counter 0 + 1)
 */
export async function hotpVerify(
  secret: Uint8Array | string,
  otp: string,
  counter: number,
  options: HOTPVerifyOptions = {},
): Promise<{ valid: boolean; delta: number }> {
  const { window = 0, ...hotpOpts } = options;
  for (let delta = 0; delta <= window; delta++) {
    const expected = await hotp(secret, counter + delta, hotpOpts);
    if (secureCompare(expected, otp)) {
      return { valid: true, delta };
    }
  }
  return { valid: false, delta: 0 };
}

// #region TOTP

/**
 * Generate a Time-based One-Time Password (RFC 6238).
 *
 * @param secret The shared secret key (raw bytes or base32-encoded string).
 * @param options Algorithm, digit, period, and time options.
 * @returns The OTP code as a zero-padded string.
 *
 * @example
 * const code = await totp(base32Secret);
 */
export async function totp(
  secret: Uint8Array | string,
  options: TOTPOptions = {},
): Promise<string> {
  const { period = 30, time, ...hotpOpts } = options;
  const t = time ?? Math.floor(Date.now() / 1000);
  const counter = Math.floor(t / period);
  return hotp(secret, counter, hotpOpts);
}

/**
 * Verify a TOTP code, checking a window of time steps in both directions.
 *
 * @param secret The shared secret key.
 * @param otp The OTP code to verify.
 * @param options Algorithm, digit, period, time, and window options.
 * @returns An object with `valid` and `delta` (time step offset that matched).
 *
 * @example
 * const { valid, delta } = await totpVerify(secret, userCode);
 * // delta: 0 = current step, -1 = previous, +1 = next
 */
export async function totpVerify(
  secret: Uint8Array | string,
  otp: string,
  options: TOTPVerifyOptions = {},
): Promise<{ valid: boolean; delta: number }> {
  const { period = 30, time, window = 1, ...hotpOpts } = options;
  const t = time ?? Math.floor(Date.now() / 1000);
  const counter = Math.floor(t / period);

  for (let delta = -window; delta <= window; delta++) {
    const expected = await hotp(secret, counter + delta, hotpOpts);
    if (secureCompare(expected, otp)) {
      return { valid: true, delta };
    }
  }
  return { valid: false, delta: 0 };
}

// #region Utilities

/**
 * Generate a cryptographically random OTP secret, returned as a
 * base32-encoded string (without padding).
 *
 * @param length Number of random bytes. @default 20 (160 bits, recommended for SHA-1)
 * @returns A base32-encoded secret string.
 *
 * @example
 * const secret = generateOTPSecret();
 * // "JBSWY3DPEHPK3PXP..."
 */
export function generateOTPSecret(length: number = 20): string {
  return base32Encode(secureRandomBytes(length)).replace(/=+$/, "");
}

/**
 * Build an `otpauth://` URI for provisioning OTP tokens via QR code.
 *
 * @param options URI configuration.
 * @returns The otpauth URI string.
 *
 * @example
 * const uri = otpauthURI({
 *   type: "totp",
 *   secret: base32Secret,
 *   account: "user@example.com",
 *   issuer: "MyApp",
 * });
 */
export function otpauthURI(options: OTPAuthURIOptions): string {
  const {
    type,
    secret,
    account,
    issuer,
    algorithm = "SHA-1",
    digits = 6,
    counter,
    period = 30,
  } = options;

  const secretB32 =
    typeof secret === "string"
      ? secret.replace(/=+$/, "")
      : base32Encode(secret as Uint8Array<ArrayBuffer>).replace(/=+$/, "");

  const label = issuer
    ? `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`
    : encodeURIComponent(account);

  const params = new URLSearchParams();
  params.set("secret", secretB32);
  if (issuer) params.set("issuer", issuer);
  params.set("algorithm", _URI_ALGORITHM_MAP[algorithm]);
  params.set("digits", String(digits));

  if (type === "hotp") {
    if (counter === undefined) {
      throw new Error("counter is required for HOTP URIs.");
    }
    params.set("counter", String(counter));
  } else {
    params.set("period", String(period));
  }

  return `otpauth://${type}/${label}?${params.toString()}`;
}
