import type { DigestOptions, DigestReturnAs } from "./hash.ts";
import { encodeBytes } from "./_internal/encoding.ts";
import { textEncoder } from "./utils/index.ts";
import { secureCompare } from "./compare.ts";

export type HMACOptions = DigestOptions;

/**
 * Compute an HMAC signature for the given data using a secret key.
 *
 * When `returnAs` is not specified, the return type mirrors the `data` input:
 * - `string` data returns a hex `string`
 * - `BufferSource` data returns a `Uint8Array<ArrayBuffer>`
 *
 * Use the `returnAs` option to explicitly override the output format.
 *
 * @param secret The HMAC secret key. Can be a string or any BufferSource.
 * @param data The data to sign. Can be a string or any BufferSource.
 * @param options Configuration options (algorithm, returnAs).
 * @returns A Promise that resolves to the HMAC signature.
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
 * const expected = request.headers['x-hub-signature-256'].replace('sha256=', '');
 * const valid = await hmacVerify(webhookSecret, requestBody, expected);
 */
export async function hmac<T extends DigestReturnAs>(
  secret: string | BufferSource,
  data: string | BufferSource,
  options: HMACOptions & { returnAs: T },
): Promise<T extends "uint8array" | "bytes" ? Uint8Array<ArrayBuffer> : string>;
export async function hmac(
  secret: string | BufferSource,
  data: string,
  options?: Omit<HMACOptions, "returnAs">,
): Promise<string>;
export async function hmac(
  secret: string | BufferSource,
  data: BufferSource,
  options?: Omit<HMACOptions, "returnAs">,
): Promise<Uint8Array<ArrayBuffer>>;
export async function hmac(
  secret: string | BufferSource,
  data: string | BufferSource,
  options?: Omit<HMACOptions, "returnAs">,
): Promise<Uint8Array<ArrayBuffer> | string>;
export async function hmac(
  secret: string | BufferSource,
  data: string | BufferSource,
  options: HMACOptions = {},
): Promise<Uint8Array<ArrayBuffer> | string> {
  const { algorithm = "SHA-256", returnAs } = options;

  const keyBuffer = typeof secret === "string" ? textEncoder.encode(secret) : secret;
  const isBufferInput = typeof data !== "string";
  const dataBuffer = isBufferInput ? data : textEncoder.encode(data);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBuffer,
    { name: "HMAC", hash: algorithm },
    false,
    ["sign"],
  );

  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, dataBuffer));

  const effectiveReturnAs = returnAs ?? (isBufferInput ? "uint8array" : "hex");

  return encodeBytes(signature, effectiveReturnAs, "hmac");
}

/**
 * Verify an HMAC signature in constant time.
 *
 * Computes the expected HMAC using the same options, then uses {@link secureCompare}
 * to prevent timing attacks. The `signature` must be in the same format that
 * {@link hmac} would produce for the given options.
 *
 * @param secret The HMAC secret key.
 * @param data The data that was signed.
 * @param signature The signature to verify against.
 * @param options Configuration options (algorithm, returnAs). Must match those used to produce the signature.
 * @returns A Promise that resolves to `true` if the signature is valid.
 *
 * @example
 * // Verify a webhook signature (hex format, the default)
 * const valid = await hmacVerify(secret, body, expectedHexSignature);
 *
 * @example
 * // Verify a base64-encoded signature
 * const valid = await hmacVerify(secret, body, expectedBase64Sig, { returnAs: 'base64' });
 */
export async function hmacVerify(
  secret: string | BufferSource,
  data: string | BufferSource,
  signature: string | Uint8Array,
  options?: HMACOptions,
): Promise<boolean> {
  const computed = await hmac(secret, data, options);
  return secureCompare(computed, signature);
}
