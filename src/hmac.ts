import type { DigestOptions, DigestReturnAs } from "./hash.ts";
import { assertReturnAs, decodeBytes, encodeBytes } from "./_internal/encoding.ts";
import { normalizeAlgorithm } from "./_internal/algorithm.ts";
import { type BytesSource, toCryptoBytes } from "./_internal/bytes.ts";
import { secureCompare } from "./compare.ts";

export type HMACOptions = DigestOptions;

/**
 * Compute an HMAC signature for the given data using a secret key.
 *
 * When `returnAs` is not specified, the return type mirrors the `data` input:
 * - `string` data returns a hex `string`
 * - `BytesSource` data returns a `Uint8Array<ArrayBuffer>`
 *
 * Use the `returnAs` option to explicitly override the output format.
 *
 * @param secret The HMAC secret key. A string or any `BytesSource`. Must not be empty.
 * @param data The data to sign. A string or any `BytesSource`.
 * @param options Configuration options (algorithm, returnAs).
 * @returns A Promise that resolves to the HMAC signature.
 *
 * @throws {RangeError} If `secret` is empty, or `algorithm` is not a supported digest.
 * @throws {TypeError} If `secret` or `data` is neither text nor bytes.
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
 */
export async function hmac<T extends DigestReturnAs>(
  secret: string | BytesSource,
  data: string | BytesSource,
  options: HMACOptions & { returnAs: T },
): Promise<T extends "uint8array" | "bytes" ? Uint8Array<ArrayBuffer> : string>;
export async function hmac(
  secret: string | BytesSource,
  data: string,
  options?: Omit<HMACOptions, "returnAs">,
): Promise<string>;
export async function hmac(
  secret: string | BytesSource,
  data: BytesSource,
  options?: Omit<HMACOptions, "returnAs">,
): Promise<Uint8Array<ArrayBuffer>>;
export async function hmac(
  secret: string | BytesSource,
  data: string | BytesSource,
  options?: Omit<HMACOptions, "returnAs">,
): Promise<Uint8Array<ArrayBuffer> | string>;
export async function hmac(
  secret: string | BytesSource,
  data: string | BytesSource,
  options: HMACOptions = {},
): Promise<Uint8Array<ArrayBuffer> | string> {
  const { returnAs } = options;
  assertReturnAs(returnAs, "hmac");
  const algorithm = normalizeAlgorithm(options.algorithm ?? "SHA-256", "hmac");

  const keyBytes = toCryptoBytes(secret, "hmac");
  // A secret that failed to load is a deployment bug, not a wrong signature:
  // it must fail loudly here rather than silently key every MAC with nothing.
  if (keyBytes.length === 0) {
    throw new RangeError("hmac: secret must not be empty.");
  }
  const isBufferInput = typeof data !== "string";
  const dataBytes = toCryptoBytes(data, "hmac");

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: algorithm },
    false,
    ["sign"],
  );

  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, dataBytes));

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
 * @param secret The HMAC secret key. Must not be empty.
 * @param data The data that was signed.
 * @param signature The signature to verify against, in the format named by `returnAs`.
 * @param options Configuration options. `algorithm` must match the one used to sign;
 *                `returnAs` names the format of a string `signature` (`hex` by default,
 *                which is also how a string is read when `returnAs` asks for bytes).
 * @returns A Promise that resolves to `true` if the signature is valid.
 *
 * @throws {RangeError} If `secret` is empty, or `algorithm` is not a supported digest.
 *
 * @example
 * // Verify a webhook signature (hex format, the default)
 * const valid = await hmacVerify(secret, body, request.headers.get('x-signature'));
 *
 * @example
 * // Verify a base64-encoded signature
 * const valid = await hmacVerify(secret, body, expectedBase64Sig, { returnAs: 'base64' });
 */
export async function hmacVerify(
  secret: string | BytesSource,
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
      if (!(error instanceof SyntaxError)) throw error;
      received = undefined;
    }
  }

  return secureCompare(computed, received);
}
