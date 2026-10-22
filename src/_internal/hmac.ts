import { normalizeAlgorithm } from "./algorithm.ts";
import { type BytesSource, toCryptoBytes } from "./bytes.ts";
import { viaWebCrypto } from "./platform.ts";
import { UnsecureError } from "../errors.ts";
import type { DigestAlgorithm } from "../hash.ts";

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

/** Sign `data` with an HMAC key already checked for the job; `source` names the caller in a `PLATFORM` error. */
/* @__NO_SIDE_EFFECTS__ */
export async function hmacSign(
  key: CryptoKey,
  data: Uint8Array<ArrayBuffer>,
  source: string,
): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(
    await viaWebCrypto(source, "sign", () => crypto.subtle.sign("HMAC", key, data)),
  );
}
