import type { DigestAlgorithm } from "./hash.ts";
import { hmac, importHmacKey } from "./hmac.ts";
import { normalizeAlgorithm } from "./_internal/algorithm.ts";
import { type BytesSource, toCryptoBytes } from "./_internal/bytes.ts";
import { assertHmacKey, isCryptoKey } from "./_internal/key.ts";
import { assertInteger, showValue } from "./_internal/assert.ts";
import { base32Parse, base32Stringify } from "./utils/index.ts";
import { secureRandomBytes } from "./random.ts";
import { secureCompare } from "./compare.ts";
import { UnsecureError } from "./errors.ts";

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
   * Unix timestamp in seconds. Omit it for the current time — only an absent
   * option takes the default. Useful for testing with deterministic values.
   * Any finite number; a fractional value is floored.
   */
  time?: number;
}

export interface TOTPVerifyOptions extends TOTPOptions {
  /**
   * Number of time steps to check in each direction (past and future).
   * An integer >= 0. The derived step plus the window must stay within the
   * safe integer range.
   *
   * @default 1
   */
  window?: number;
  /**
   * The time step of the last code this secret was accepted for. Every
   * candidate at or before it is refused, so an accepted code cannot be
   * replayed for the rest of its window and an older captured code cannot
   * be played after a newer one (RFC 6238 §5.2). Persist `step` from a
   * successful result and pass it back here on the next verification.
   * An integer >= 0.
   */
  lastAccepted?: number;
}

/**
 * What {@link hotpVerify} reports. On success `counter` is the absolute
 * counter that matched: persist `counter + 1` as the next expected value
 * (RFC 4226 §7.2), or the same code keeps working.
 */
export type HOTPVerifyResult =
  | { valid: true; delta: number; counter: number }
  | { valid: false; delta: 0; counter?: undefined };

/**
 * What {@link totpVerify} reports. On success `step` is the absolute time
 * step that matched: persist it and pass it back as `lastAccepted`, or the
 * same code keeps working for the rest of its window.
 */
export type TOTPVerifyResult =
  | { valid: true; delta: number; step: number }
  | { valid: false; delta: 0; step?: undefined };

export interface OTPAuthURIOptions {
  /** OTP type. */
  type: "hotp" | "totp";
  /** The secret key as raw bytes or a base32-encoded string. */
  secret: string | BytesSource;
  /** Account name (e.g. user email). */
  account: string;
  /** Issuer name (e.g. service name). A non-empty string; omit it for none. */
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
/* @__NO_SIDE_EFFECTS__ */
function _counterToBytes(counter: number): Uint8Array<ArrayBuffer> {
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setUint32(0, Math.floor(counter / 0x1_00_00_00_00));
  view.setUint32(4, counter >>> 0);
  return buf;
}

/** Dynamic truncation per RFC 4226 §5.3. */
/* @__NO_SIDE_EFFECTS__ */
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
/* @__NO_SIDE_EFFECTS__ */
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
 * every code with nothing — so it throws rather than producing codes. Each
 * caller passes its own name, so the error names the call the caller wrote.
 */
/* @__NO_SIDE_EFFECTS__ */
function _resolveSecret(source: string, secret: string | BytesSource): Uint8Array<ArrayBuffer> {
  const bytes =
    typeof secret === "string"
      ? base32Parse(secret, { loose: true, returnAs: "bytes" })
      : toCryptoBytes(secret, source);
  if (bytes.length === 0) {
    throw new UnsecureError("OUT_OF_RANGE", `${source}: secret must not be empty.`);
  }
  return bytes;
}

/**
 * Resolve a secret to the one signing key a call uses for every candidate.
 *
 * A verify walks its whole window, and importing the same secret once per
 * step is the cost of a shape, not of the work: one import serves all of
 * them. A caller who imported the key themselves passes it straight through —
 * checked against the algorithm the call was asked for, since a key carries
 * its own hash and the two disagreeing would produce codes for a digest the
 * caller did not choose.
 */
/* @__NO_SIDE_EFFECTS__ */
async function _resolveKey(
  source: string,
  secret: string | BytesSource | CryptoKey,
  algorithm: DigestAlgorithm,
): Promise<CryptoKey> {
  if (isCryptoKey(secret)) {
    assertHmacKey(secret, algorithm, source);
    return secret;
  }
  return importHmacKey(_resolveSecret(source, secret), { algorithm });
}

/** The counter → code core, run only once every input is known good. */
/* @__NO_SIDE_EFFECTS__ */
async function _code(key: CryptoKey, counter: number, digits: number): Promise<string> {
  const mac = await hmac(key, _counterToBytes(counter), { returnAs: "uint8array" });
  return _dynamicTruncate(mac, digits);
}

/**
 * The time step a TOTP code belongs to. The counter is derived here rather
 * than taken from the caller, so unlike {@link hotp} it is not range-checked:
 * a pre-epoch `time` yields a negative step, encoded the same way on both the
 * generate and the verify side.
 */
/* @__NO_SIDE_EFFECTS__ */
function _timeStep(source: string, time: number | undefined, period: number): number {
  assertInteger(source, "period", period, 1);
  // Only an absent `time` means "now": `null` is a value the caller passed,
  // and defaulting on it would silently generate a code for another instant.
  const seconds = time === undefined ? Math.floor(Date.now() / 1000) : time;
  if (!Number.isFinite(seconds)) {
    throw new UnsecureError(
      "OUT_OF_RANGE",
      `${source}: time must be a finite number of seconds, got ${showValue(seconds)}.`,
    );
  }
  return Math.floor(seconds / period);
}

/**
 * The label is the only free text in a URI, and `encodeURIComponent` turns
 * anything into a string — an object would be provisioned as "[object Object]"
 * and a missing account as "undefined", both of which scan.
 */
function _assertLabelText(name: string, value: unknown): asserts value is string {
  if (typeof value !== "string") {
    throw new UnsecureError(
      "INVALID_TYPE",
      `otpauthURI: ${name} must be a string, got ${showValue(value)}.`,
    );
  }
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
 * @param secret The shared secret key: raw bytes, a base32-encoded string, or an
 *               HMAC `CryptoKey` from `importHmacKey` whose hash is `algorithm`.
 * @param counter The moving factor (counter value), an integer >= 0.
 * @param options Algorithm and digit options.
 * @returns The OTP code as a zero-padded string.
 *
 * @throws {UnsecureError} `OUT_OF_RANGE` if the secret is empty, is a key that
 *                         cannot sign HMAC or whose hash is not `algorithm`, or if
 *                         `counter` or `digits` is outside its documented range;
 *                         `UNSUPPORTED` for an unknown `algorithm`.
 *
 * @example
 * const code = await hotp(secretBytes, 0);
 * // "755224"
 */
/* @__NO_SIDE_EFFECTS__ */
export async function hotp(
  secret: string | BytesSource | CryptoKey,
  counter: number,
  options: HOTPOptions = {},
): Promise<string> {
  const { algorithm, digits } = _baseOptions("hotp", options);
  assertInteger("hotp", "counter", counter, 0);
  return _code(await _resolveKey("hotp", secret, algorithm), counter, digits);
}

/**
 * Verify an HOTP code, optionally checking a window of counter values ahead.
 *
 * All `window + 1` HMACs are computed on every call, from one imported key, so
 * how long a call takes says nothing about which counter matched. `delta` is the
 * nearest matching step. Codes are single-use: `counter` is the server's own
 * state, so candidates before it are never checked, and the result's `counter`
 * is the one to advance past — persist `counter + 1`, or the same code keeps
 * working.
 *
 * @param secret The shared secret key: raw bytes, a base32-encoded string, or an
 *               HMAC `CryptoKey` from `importHmacKey` whose hash is `algorithm`.
 *               It is imported once, and every candidate in the window is signed
 *               with that one key.
 * @param otp The OTP code to verify. A missing code (`null` / `undefined`) is invalid.
 * @param counter The expected counter value, an integer >= 0.
 * @param options Algorithm, digit, and window options.
 * @returns `valid`, `delta` (offset from `counter` that matched) and, on
 *          success, the absolute `counter` that matched.
 *
 * @throws {UnsecureError} `OUT_OF_RANGE` if the secret is empty, is a key that
 *                         cannot sign HMAC or whose hash is not `algorithm`, or if
 *                         `counter`, `digits` or `window` is outside its documented
 *                         range; `UNSUPPORTED` for an unknown `algorithm`.
 *
 * @example
 * const result = await hotpVerify(secret, "287082", user.counter, { window: 5 });
 * // { valid: true, delta: 1, counter: 1 }
 * if (result.valid) await store.setCounter(user.id, result.counter + 1);
 */
/* @__NO_SIDE_EFFECTS__ */
export async function hotpVerify(
  secret: string | BytesSource | CryptoKey,
  otp: string | null | undefined,
  counter: number,
  options: HOTPVerifyOptions = {},
): Promise<HOTPVerifyResult> {
  const { window = 0 } = options;
  const { algorithm, digits } = _baseOptions("hotpVerify", options);
  assertInteger("hotpVerify", "window", window, 0);
  // The window is walked by adding to the counter, so the far end of it has to
  // stay a safe integer too — past that, candidates lose precision and silently
  // repeat one another.
  assertInteger("hotpVerify", "counter", counter, 0, Number.MAX_SAFE_INTEGER - window);

  const key = await _resolveKey("hotpVerify", secret, algorithm);

  // Every candidate is computed and compared on every call. Returning at the
  // first match would make the number of HMACs — and so how long the call
  // takes — depend on which counter the code belonged to, which tells an
  // attacker how far the token has drifted.
  let valid = false;
  let delta = 0;
  for (let step = 0; step <= window; step++) {
    const matched = secureCompare(await _code(key, counter + step, digits), otp);
    if (matched && !valid) {
      valid = true;
      delta = step;
    }
  }
  return valid ? { valid, delta, counter: counter + delta } : { valid, delta: 0 };
}

// #region TOTP

/**
 * Generate a Time-based One-Time Password (RFC 6238).
 *
 * @param secret The shared secret key: raw bytes, a base32-encoded string, or an
 *               HMAC `CryptoKey` from `importHmacKey` whose hash is `algorithm`.
 * @param options Algorithm, digit, period, and time options.
 * @returns The OTP code as a zero-padded string.
 *
 * @throws {UnsecureError} `OUT_OF_RANGE` if the secret is empty, is a key that
 *                         cannot sign HMAC or whose hash is not `algorithm`, or if
 *                         `digits`, `period` or `time` is outside its documented
 *                         range; `UNSUPPORTED` for an unknown `algorithm`.
 *
 * @example
 * const code = await totp(base32Secret);
 */
/* @__NO_SIDE_EFFECTS__ */
export async function totp(
  secret: string | BytesSource | CryptoKey,
  options: TOTPOptions = {},
): Promise<string> {
  const { period = DEFAULT_PERIOD, time } = options;
  const { algorithm, digits } = _baseOptions("totp", options);
  const counter = _timeStep("totp", time, period);
  return _code(await _resolveKey("totp", secret, algorithm), counter, digits);
}

/**
 * Verify a TOTP code, checking a window of time steps in both directions.
 *
 * All `2 * window + 1` HMACs are computed on every call, from one imported key,
 * so how long a call takes says nothing about which step matched. `delta` is the
 * nearest matching step (the past wins a tie). Codes are single-use per RFC 6238
 * §5.2: pass the `step` of the last success back as `lastAccepted` and every
 * candidate at or before it is refused, so a captured code cannot be replayed for
 * the rest of its window. Without `lastAccepted` nothing is refused — the library
 * holds no state, so that part has to travel with the user record.
 *
 * @param secret The shared secret key: raw bytes, a base32-encoded string, or an
 *               HMAC `CryptoKey` from `importHmacKey` whose hash is `algorithm`.
 *               It is imported once, and every candidate in the window is signed
 *               with that one key.
 * @param otp The OTP code to verify. A missing code (`null` / `undefined`) is invalid.
 * @param options Algorithm, digit, period, time, window and `lastAccepted` options.
 * @returns `valid`, `delta` (time step offset that matched) and, on success,
 *          the absolute `step` that matched.
 *
 * @throws {UnsecureError} `OUT_OF_RANGE` if the secret is empty, is a key that
 *                         cannot sign HMAC or whose hash is not `algorithm`, or if
 *                         `digits`, `period`, `time`, `window` or `lastAccepted` is
 *                         outside its documented range — `time` included when the
 *                         window would run past the safe integer range;
 *                         `UNSUPPORTED` for an unknown `algorithm`.
 *
 * @example
 * const result = await totpVerify(secret, userCode, { lastAccepted: user.lastOtpStep });
 * // { valid: true, delta: 0, step: 56666666 } — or { valid: false, delta: 0 } for a replay
 * if (result.valid) await store.setLastOtpStep(user.id, result.step);
 */
/* @__NO_SIDE_EFFECTS__ */
export async function totpVerify(
  secret: string | BytesSource | CryptoKey,
  otp: string | null | undefined,
  options: TOTPVerifyOptions = {},
): Promise<TOTPVerifyResult> {
  const { window = 1, period = DEFAULT_PERIOD, time, lastAccepted } = options;
  const { algorithm, digits } = _baseOptions("totpVerify", options);
  assertInteger("totpVerify", "window", window, 0);
  if (lastAccepted !== undefined) assertInteger("totpVerify", "lastAccepted", lastAccepted, 0);
  const counter = _timeStep("totpVerify", time, period);
  // The window is walked by adding to the derived step, so both ends of it
  // have to stay safe integers — past that, candidates lose precision and
  // silently repeat one another.
  if (Math.abs(counter) + window > Number.MAX_SAFE_INTEGER) {
    throw new UnsecureError(
      "OUT_OF_RANGE",
      `totpVerify: time must leave every step of the window a safe integer, got ${showValue(time)}.`,
    );
  }

  const key = await _resolveKey("totpVerify", secret, algorithm);

  // Nearest step first, the past ahead of the future at equal distance, so a
  // code that matches more than one step reports the closest one. As in
  // `hotpVerify`, the whole window runs whether or not anything matched.
  const steps: Array<number> = [0];
  for (let step = 1; step <= window; step++) steps.push(-step, step);

  let valid = false;
  let delta = 0;
  for (const step of steps) {
    const candidate = counter + step;
    const matched = secureCompare(await _code(key, candidate, digits), otp);
    // A step at or before the last accepted one is spent. Its code is still
    // computed and compared so the call costs the same; it just cannot count.
    const fresh = lastAccepted === undefined || candidate > lastAccepted;
    if (matched && fresh && !valid) {
      valid = true;
      delta = step;
    }
  }
  return valid ? { valid, delta, step: counter + delta } : { valid, delta: 0 };
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
 * @throws {UnsecureError} `OUT_OF_RANGE` if `length` is not an integer >= 1.
 *
 * @example
 * const secret = generateOTPSecret();
 * // "JBSWY3DPEHPK3PXP..."
 */
/* @__NO_SIDE_EFFECTS__ */
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
 * @throws {UnsecureError} `UNSUPPORTED` if `type` is a string other than `"hotp"`
 *                         or `"totp"`; `INVALID_TYPE` if `type`, `account` or
 *                         `issuer` is not a string; `OUT_OF_RANGE` if the secret,
 *                         `account` or `issuer` is empty, if a HOTP `counter` is
 *                         missing, or if a numeric option is out of range.
 *
 * @example
 * const uri = otpauthURI({
 *   type: "totp",
 *   secret: base32Secret,
 *   account: "user@example.com",
 *   issuer: "MyApp",
 * });
 */
/* @__NO_SIDE_EFFECTS__ */
export function otpauthURI(options: OTPAuthURIOptions): string {
  const { type, secret, account, issuer, counter, period = DEFAULT_PERIOD } = options;
  if (type !== "hotp" && type !== "totp") {
    // A string the library does not know is a name outside the supported set;
    // anything else never was a name at all.
    throw new UnsecureError(
      typeof type === "string" ? "UNSUPPORTED" : "INVALID_TYPE",
      `otpauthURI: type must be "hotp" or "totp", got ${showValue(type)}.`,
    );
  }
  _assertLabelText("account", account);
  if (account.length === 0) {
    throw new UnsecureError("OUT_OF_RANGE", "otpauthURI: account must not be empty.");
  }
  if (issuer !== undefined) {
    _assertLabelText("issuer", issuer);
    // "" is not "no issuer": it would be dropped from both the label and the
    // query, provisioning a token under a name the caller never chose.
    // `undefined` is how a caller says there is none.
    if (issuer.length === 0) {
      throw new UnsecureError("OUT_OF_RANGE", "otpauthURI: issuer must not be empty.");
    }
  }
  const { algorithm, digits } = _baseOptions("otpauthURI", options);

  // Whatever shape the secret arrives in, the URI carries the canonical
  // unpadded base32 of the same bytes: scanners read the string literally, so
  // the grouped lowercase form a caller may be holding has to be normalized.
  const secretB32 = base32Stringify(_resolveSecret("otpauthURI", secret), { padding: false });

  const label =
    issuer === undefined
      ? encodeURIComponent(account)
      : `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;

  // The Key URI format is a URI, not a form body: a space is "%20", never "+",
  // which is what `URLSearchParams` would write.
  const params = [`secret=${encodeURIComponent(secretB32)}`];
  if (issuer !== undefined) params.push(`issuer=${encodeURIComponent(issuer)}`);
  params.push(`algorithm=${encodeURIComponent(_URI_ALGORITHM_MAP[algorithm])}`);
  params.push(`digits=${digits}`);

  if (type === "hotp") {
    if (counter === undefined) {
      throw new UnsecureError("OUT_OF_RANGE", "otpauthURI: counter is required for HOTP URIs.");
    }
    assertInteger("otpauthURI", "counter", counter, 0);
    params.push(`counter=${counter}`);
  } else {
    assertInteger("otpauthURI", "period", period, 1);
    params.push(`period=${period}`);
  }

  return `otpauth://${type}/${label}?${params.join("&")}`;
}
