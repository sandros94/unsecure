import type { DigestAlgorithm, DigestOptions, DigestReturnAs } from "./hash.ts";
import { assertReturnAs, decodeBytes, encodeBytes } from "./_internal/encoding.ts";
import { normalizeAlgorithm } from "./_internal/algorithm.ts";
import { type BytesSource, toCryptoBytes } from "./_internal/bytes.ts";
import { assertHmacKey, isCryptoKey } from "./_internal/key.ts";
import { viaWebCrypto } from "./_internal/platform.ts";
import { secureCompare } from "./compare.ts";
import { UnsecureError } from "./errors.ts";

export type HMACOptions = DigestOptions;

/**
 * Import a secret once, as an HMAC signing key.
 *
 * Every `hmac()` call that is handed raw bytes imports them again; a server
 * that signs or verifies on every request can do that work at startup instead
 * and pass the key from then on. The key is non-extractable and can only
 * sign — it carries the secret without handing it back.
 *
 * The hash is fixed at import time: a key made here works only with the
 * algorithm it was made for.
 *
 * @param secret The HMAC secret key. A string or any `BytesSource`. Must not be empty.
 * @param options The `algorithm` the key will sign with (default `"SHA-256"`).
 * @returns A Promise that resolves to a non-extractable HMAC key with the `sign` usage.
 *
 * @throws {UnsecureError} `OUT_OF_RANGE` if `secret` is empty; `UNSUPPORTED` if
 *                         `algorithm` is not one the library knows; `INVALID_TYPE`
 *                         if `secret` is neither text nor bytes; `PLATFORM` if the
 *                         runtime's Web Crypto refuses.
 *
 * @example
 * const key = await importHmacKey(process.env.WEBHOOK_SECRET);
 * // ...once per request, with no import of its own:
 * const valid = await hmacVerify(key, body, signature);
 */
/* @__NO_SIDE_EFFECTS__ */
export async function importHmacKey(
  secret: string | BytesSource,
  options: { algorithm?: DigestAlgorithm } = {},
): Promise<CryptoKey> {
  const algorithm = normalizeAlgorithm(options.algorithm ?? "SHA-256", "hmac");
  const keyBytes = toCryptoBytes(secret, "hmac");
  // A secret that failed to load is a deployment bug, not a wrong signature:
  // it must fail loudly here rather than silently key every MAC with nothing.
  if (keyBytes.length === 0) {
    throw new UnsecureError("OUT_OF_RANGE", "hmac: secret must not be empty.");
  }
  return viaWebCrypto("hmac", "importKey", () =>
    crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: algorithm }, false, ["sign"]),
  );
}

/**
 * Compute an HMAC signature for the given data using a secret key.
 *
 * When `returnAs` is not specified, the return type mirrors the `data` input:
 * - `string` data returns a hex `string`
 * - `BytesSource` data returns a `Uint8Array<ArrayBuffer>`
 *
 * Use the `returnAs` option to explicitly override the output format.
 *
 * @param secret The HMAC secret key: a string, any `BytesSource`, or a `CryptoKey`
 *               from {@link importHmacKey}, which is used as-is. Must not be empty.
 * @param data The data to sign. A string or any `BytesSource`.
 * @param options Configuration options (algorithm, returnAs). With a `CryptoKey`
 *                secret, `algorithm` may only restate the hash the key carries.
 * @returns A Promise that resolves to the HMAC signature.
 *
 * @throws {UnsecureError} `OUT_OF_RANGE` if `secret` is empty, or is a key that
 *                         cannot sign HMAC or whose hash `algorithm` disagrees
 *                         with; `UNSUPPORTED` if `algorithm` or `returnAs` is not
 *                         one the library knows; `INVALID_TYPE` if `secret` or
 *                         `data` is neither text nor bytes; `PLATFORM` if the
 *                         runtime's Web Crypto refuses.
 *
 * @example
 * // Sign a string — returns hex by default
 * const sig = await hmac('my-secret', 'hello world');
 *
 * // Sign with SHA-512 and return as base64
 * const sig64 = await hmac('my-secret', payload, { algorithm: 'SHA-512', returnAs: 'base64' });
 *
 * @example
 * // Webhook verification
 * const valid = await hmacVerify(webhookSecret, requestBody, request.headers.get('x-signature'));
 *
 * @example
 * // Import the secret once, sign many times
 * const key = await importHmacKey(webhookSecret, { algorithm: 'SHA-512' });
 * const sig = await hmac(key, payload);
 */
export async function hmac<T extends DigestReturnAs>(
  secret: string | BytesSource | CryptoKey,
  data: string | BytesSource,
  options: HMACOptions & { returnAs: T },
): Promise<T extends "uint8array" | "bytes" ? Uint8Array<ArrayBuffer> : string>;
export async function hmac(
  secret: string | BytesSource | CryptoKey,
  data: string,
  options?: Omit<HMACOptions, "returnAs">,
): Promise<string>;
export async function hmac(
  secret: string | BytesSource | CryptoKey,
  data: BytesSource,
  options?: Omit<HMACOptions, "returnAs">,
): Promise<Uint8Array<ArrayBuffer>>;
export async function hmac(
  secret: string | BytesSource | CryptoKey,
  data: string | BytesSource,
  options?: Omit<HMACOptions, "returnAs">,
): Promise<Uint8Array<ArrayBuffer> | string>;
/* @__NO_SIDE_EFFECTS__ */
export async function hmac(
  secret: string | BytesSource | CryptoKey,
  data: string | BytesSource,
  options: HMACOptions = {},
): Promise<Uint8Array<ArrayBuffer> | string> {
  const { returnAs } = options;
  assertReturnAs(returnAs, "hmac");

  // A key the caller already holds is used as-is: that is the whole point of
  // passing one, and re-importing it is not possible anyway.
  const cryptoKey = isCryptoKey(secret)
    ? (assertHmacKey(secret, options.algorithm, "hmac"), secret)
    : await importHmacKey(secret, options);

  const isBufferInput = typeof data !== "string";
  const dataBytes = toCryptoBytes(data, "hmac");

  const signature = new Uint8Array(
    await viaWebCrypto("hmac", "sign", () => crypto.subtle.sign("HMAC", cryptoKey, dataBytes)),
  );

  const effectiveReturnAs = returnAs ?? (isBufferInput ? "uint8array" : "hex");

  return encodeBytes(signature, effectiveReturnAs, "hmac");
}

/**
 * Verify an HMAC signature in constant time.
 *
 * Computes the expected MAC and compares raw bytes with {@link secureCompare}.
 * A `BytesSource` signature is compared as-is. A string signature is decoded
 * strictly with the codec named by `options.returnAs` — the format {@link hmac}
 * would have produced with the same options — so the same options object serves
 * both calls.
 *
 * Untrusted input never throws: a `null` / `undefined` signature, one whose
 * text is not a canonical encoding, or one that is not text or bytes at all,
 * simply fails to verify. An empty `secret` or an unsupported `algorithm` still
 * throws, because those describe the server, not the request.
 *
 * @param secret The HMAC secret key: a string, any `BytesSource`, or a `CryptoKey`
 *               from {@link importHmacKey}. Must not be empty.
 * @param data The data that was signed.
 * @param signature The signature to verify against, in the format named by `returnAs`.
 * @param options Configuration options. `algorithm` must match the one used to sign;
 *                `returnAs` names the format of a string `signature` (`hex` by default,
 *                which is also how a string is read when `returnAs` asks for bytes).
 * @returns A Promise that resolves to `true` if the signature is valid.
 *
 * @throws {UnsecureError} `OUT_OF_RANGE` if `secret` is empty, or is a key that
 *                         cannot sign HMAC or whose hash `algorithm` disagrees
 *                         with; `UNSUPPORTED` if `algorithm` or `returnAs` is not
 *                         one the library knows; `PLATFORM` if the runtime's Web
 *                         Crypto refuses.
 *
 * @example
 * // Verify a webhook signature (hex format, the default)
 * const valid = await hmacVerify(secret, body, request.headers.get('x-signature'));
 *
 * @example
 * // Verify a base64-encoded signature
 * const valid = await hmacVerify(secret, body, expectedBase64Sig, { returnAs: 'base64' });
 */
/* @__NO_SIDE_EFFECTS__ */
export async function hmacVerify(
  secret: string | BytesSource | CryptoKey,
  data: string | BytesSource,
  signature: string | BytesSource | null | undefined,
  options?: HMACOptions,
): Promise<boolean> {
  // Checked here, not only on the path that decodes text: a `returnAs` the
  // library does not know is a caller mistake whatever the signature is.
  assertReturnAs(options?.returnAs, "hmac");
  const computed = await hmac(secret, data, { ...options, returnAs: "uint8array" });

  let received: string | BytesSource | null | undefined = signature;
  if (typeof signature === "string") {
    try {
      received = decodeBytes(signature, options?.returnAs, "hmac");
    } catch (error) {
      // Malformed text is a failed verification; a `returnAs` the library does
      // not know is a caller mistake and keeps its usual error.
      if (!(error instanceof UnsecureError) || error.code !== "MALFORMED") throw error;
      received = undefined;
    }
  }

  return secureCompare(computed, received);
}
