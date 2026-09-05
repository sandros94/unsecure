import type { DigestAlgorithm } from "./hash.ts";
import { hmac } from "./hmac.ts";
import { normalizeAlgorithm } from "./_internal/algorithm.ts";
import { type BytesSource, toCryptoBytes } from "./_internal/bytes.ts";
import { assertInteger, showValue } from "./_internal/assert.ts";
import { base32Parse, base32Stringify } from "./utils/index.ts";
import { secureRandomBytes } from "./random.ts";
import { secureCompare } from "./compare.ts";

// #region Types

export interface HOTPOptions {
  /**
   * Hash algorithm. Matched case-insensitively.
   *
   * @default "SHA-1"
   */
  algorithm?: DigestAlgorithm;
  /**
   * Number of digits in the OTP code. An integer from 6 (RFC 4226 §5.3
   * minimum) to 8 (the ceiling authenticator apps agree on).
   *
   * @default 6
   */
  digits?: number;
}

export interface HOTPVerifyOptions extends HOTPOptions {
  /**
   * Number of counter values to check ahead of the given counter.
   * An integer >= 0.
   *
   * @default 0
   */
  window?: number;
}

export interface TOTPOptions extends HOTPOptions {
  /**
   * Time step duration in seconds. An integer >= 1.
   *
   * @default 30
   */
  period?: number;
  /**
   * Unix timestamp in seconds. Defaults to the current time.
   * Useful for testing with deterministic values. Any finite number; a
   * fractional value is floored.
   */
  time?: number;
}

export interface TOTPVerifyOptions extends TOTPOptions {
  /**
   * Number of time steps to check in each direction (past and future).
   * An integer >= 0.
   *
   * @default 1
   */
  window?: number;
}

export interface OTPAuthURIOptions {
  /** OTP type. */
  type: "hotp" | "totp";
  /** The secret key as raw bytes or a base32-encoded string. */
  secret: string | BytesSource;
  /** Account name (e.g. user email). */
  account: string;
  /** Issuer name (e.g. service name). */
  issuer?: string;
  /** Hash algorithm. @default "SHA-1" */
  algorithm?: DigestAlgorithm;
  /** Number of digits, 6 to 8. @default 6 */
  digits?: number;
  /** HOTP counter value, an integer >= 0 (required when type is "hotp"). */
  counter?: number;
  /** TOTP time step in seconds, an integer >= 1 (only for type "totp"). @default 30 */
  period?: number;
}

// #region Internal helpers

const DEFAULT_ALGORITHM: DigestAlgorithm = "SHA-1";
const DEFAULT_DIGITS = 6;
const DEFAULT_PERIOD = 30;

/** Convert a counter to an 8-byte big-endian buffer. */
function _counterToBytes(counter: number): Uint8Array<ArrayBuffer> {
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setUint32(0, Math.floor(counter / 0x1_00_00_00_00));
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

/**
 * The options every entry point shares, checked against their documented
 * ranges before anything is computed. Each function passes its own name so the
 * error names the call the caller wrote, not the internal that failed.
 */
function _baseOptions(
  source: string,
  options: HOTPOptions,
): { algorithm: DigestAlgorithm; digits: number } {
  const { algorithm = DEFAULT_ALGORITHM, digits = DEFAULT_DIGITS } = options;
  assertInteger(source, "digits", digits, 6, 8);
  return { algorithm: normalizeAlgorithm(algorithm, source), digits };
}

/**
 * Resolve a secret to raw ArrayBuffer-backed bytes. Strings are treated as
 * base32 and read leniently, since authenticator apps hand them out in groups
 * of lowercase letters. An empty result is a configuration bug — it would key
 * every code with nothing — so it throws rather than producing codes.
 */
function _resolveSecret(secret: string | BytesSource): Uint8Array<ArrayBuffer> {
  const bytes =
    typeof secret === "string"
      ? base32Parse(secret, { loose: true, returnAs: "bytes" })
      : toCryptoBytes(secret, "otp");
  if (bytes.length === 0) {
    throw new RangeError("otp: secret must not be empty.");
  }
  return bytes;
}

/** The counter → code core, run only once every input is known good. */
async function _code(
  secret: Uint8Array<ArrayBuffer>,
  counter: number,
  algorithm: DigestAlgorithm,
  digits: number,
): Promise<string> {
  const mac = await hmac(secret, _counterToBytes(counter), {
    algorithm,
    returnAs: "uint8array",
  });
  return _dynamicTruncate(mac, digits);
}

/**
 * The time step a TOTP code belongs to. The counter is derived here rather
 * than taken from the caller, so unlike {@link hotp} it is not range-checked:
 * a pre-epoch `time` yields a negative step, encoded the same way on both the
 * generate and the verify side.
 */
function _timeStep(source: string, time: number | undefined, period: number): number {
  assertInteger(source, "period", period, 1);
  const seconds = time ?? Math.floor(Date.now() / 1000);
  if (!Number.isFinite(seconds)) {
    throw new RangeError(
      `${source}: time must be a finite number of seconds, got ${showValue(seconds)}.`,
    );
  }
  return Math.floor(seconds / period);
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
 * @param secret The shared secret key (raw bytes or a base32-encoded string).
 * @param counter The moving factor (counter value), an integer >= 0.
 * @param options Algorithm and digit options.
 * @returns The OTP code as a zero-padded string.
 *
 * @throws {RangeError} If the secret is empty, or `counter`, `digits` or
 *                      `algorithm` is outside its documented range.
 *
 * @example
 * const code = await hotp(secretBytes, 0);
 * // "755224"
 */
export async function hotp(
  secret: string | BytesSource,
  counter: number,
  options: HOTPOptions = {},
): Promise<string> {
  const { algorithm, digits } = _baseOptions("hotp", options);
  assertInteger("hotp", "counter", counter, 0);
  return _code(_resolveSecret(secret), counter, algorithm, digits);
}

/**
 * Verify an HOTP code, optionally checking a window of counter values ahead.
 *
 * All `window + 1` HMACs are computed on every call, so how long a call takes
 * says nothing about which counter matched. `delta` is the nearest matching
 * step. Codes are single-use: persist `counter + delta + 1` after a successful
 * verification, or the same code keeps working.
 *
 * @param secret The shared secret key.
 * @param otp The OTP code to verify. A missing code (`null` / `undefined`) is invalid.
 * @param counter The expected counter value, an integer >= 0.
 * @param options Algorithm, digit, and window options.
 * @returns An object with `valid` and `delta` (counter offset that matched).
 *
 * @throws {RangeError} If the secret is empty, or `counter`, `digits`, `window`
 *                      or `algorithm` is outside its documented range.
 *
 * @example
 * const { valid, delta } = await hotpVerify(secret, "287082", 0, { window: 5 });
 * // valid: true, delta: 1 (matched at counter 0 + 1)
 */
export async function hotpVerify(
  secret: string | BytesSource,
  otp: string | null | undefined,
  counter: number,
  options: HOTPVerifyOptions = {},
): Promise<{ valid: boolean; delta: number }> {
  const { window = 0 } = options;
  const { algorithm, digits } = _baseOptions("hotpVerify", options);
  assertInteger("hotpVerify", "window", window, 0);
  // The window is walked by adding to the counter, so the far end of it has to
  // stay a safe integer too — past that, candidates lose precision and silently
  // repeat one another.
  assertInteger("hotpVerify", "counter", counter, 0, Number.MAX_SAFE_INTEGER - window);

  const secretBytes = _resolveSecret(secret);

  // Every candidate is computed and compared on every call. Returning at the
  // first match would make the number of HMACs — and so how long the call
  // takes — depend on which counter the code belonged to, which tells an
  // attacker how far the token has drifted.
  let valid = false;
  let delta = 0;
  for (let step = 0; step <= window; step++) {
    const matched = secureCompare(await _code(secretBytes, counter + step, algorithm, digits), otp);
    if (matched && !valid) {
      valid = true;
      delta = step;
    }
  }
  return { valid, delta };
}

// #region TOTP

/**
 * Generate a Time-based One-Time Password (RFC 6238).
 *
 * @param secret The shared secret key (raw bytes or a base32-encoded string).
 * @param options Algorithm, digit, period, and time options.
 * @returns The OTP code as a zero-padded string.
 *
 * @throws {RangeError} If the secret is empty, or `digits`, `period`, `time`
 *                      or `algorithm` is outside its documented range.
 *
 * @example
 * const code = await totp(base32Secret);
 */
export async function totp(
  secret: string | BytesSource,
  options: TOTPOptions = {},
): Promise<string> {
  const { algorithm, digits } = _baseOptions("totp", options);
  const counter = _timeStep("totp", options.time, options.period ?? DEFAULT_PERIOD);
  return _code(_resolveSecret(secret), counter, algorithm, digits);
}

/**
 * Verify a TOTP code, checking a window of time steps in both directions.
 *
 * All `2 * window + 1` HMACs are computed on every call, so how long a call
 * takes says nothing about which step matched. `delta` is the nearest matching
 * step (the past wins a tie). Codes are single-use per RFC 6238 §5.2: persist
 * the accepted step and refuse it a second time, or a code stays valid for the
 * rest of its window.
 *
 * @param secret The shared secret key.
 * @param otp The OTP code to verify. A missing code (`null` / `undefined`) is invalid.
 * @param options Algorithm, digit, period, time, and window options.
 * @returns An object with `valid` and `delta` (time step offset that matched).
 *
 * @throws {RangeError} If the secret is empty, or `digits`, `period`, `time`,
 *                      `window` or `algorithm` is outside its documented range.
 *
 * @example
 * const { valid, delta } = await totpVerify(secret, userCode);
 * // delta: 0 = current step, -1 = previous, +1 = next
 */
export async function totpVerify(
  secret: string | BytesSource,
  otp: string | null | undefined,
  options: TOTPVerifyOptions = {},
): Promise<{ valid: boolean; delta: number }> {
  const { window = 1 } = options;
  const { algorithm, digits } = _baseOptions("totpVerify", options);
  assertInteger("totpVerify", "window", window, 0);
  const counter = _timeStep("totpVerify", options.time, options.period ?? DEFAULT_PERIOD);

  const secretBytes = _resolveSecret(secret);

  // Nearest step first, the past ahead of the future at equal distance, so a
  // code that matches more than one step reports the closest one. As in
  // `hotpVerify`, the whole window runs whether or not anything matched.
  const steps: Array<number> = [0];
  for (let step = 1; step <= window; step++) steps.push(-step, step);

  let valid = false;
  let delta = 0;
  for (const step of steps) {
    const matched = secureCompare(await _code(secretBytes, counter + step, algorithm, digits), otp);
    if (matched && !valid) {
      valid = true;
      delta = step;
    }
  }
  return { valid, delta };
}

// #region Utilities

/**
 * Generate a cryptographically random OTP secret, returned as a
 * base32-encoded string (without padding).
 *
 * @param length Number of random bytes, an integer >= 1.
 *               @default 20 (160 bits, recommended for SHA-1)
 * @returns A base32-encoded secret string.
 *
 * @throws {RangeError} If `length` is not an integer >= 1.
 *
 * @example
 * const secret = generateOTPSecret();
 * // "JBSWY3DPEHPK3PXP..."
 */
export function generateOTPSecret(length: number = 20): string {
  assertInteger("generateOTPSecret", "length", length, 1);
  return base32Stringify(secureRandomBytes(length), { padding: false });
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
  const { type, secret, account, issuer, counter, period = DEFAULT_PERIOD } = options;
  const { algorithm, digits } = _baseOptions("otpauthURI", options);

  const secretB32 =
    typeof secret === "string"
      ? secret.replace(/=+$/, "")
      : base32Stringify(secret, { padding: false });

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
      throw new Error("otpauthURI: counter is required for HOTP URIs.");
    }
    assertInteger("otpauthURI", "counter", counter, 0);
    params.set("counter", String(counter));
  } else {
    assertInteger("otpauthURI", "period", period, 1);
    params.set("period", String(period));
  }

  return `otpauth://${type}/${label}?${params.toString()}`;
}
