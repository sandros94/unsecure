// #region docs
import { hkdf, importHkdfKey } from "unsecure/hkdf";
import { importHmacKey } from "unsecure/hmac";

const rootSecret = process.env.APP_ROOT_SECRET;
if (!rootSecret) throw new Error("APP_ROOT_SECRET is not set");

// Imported once. Every derivation below reuses it.
const root = await importHkdfKey(rootSecret);

/** 32 bytes for one purpose. A different label gives an unrelated key. */
export function derive(purpose: string): Promise<Uint8Array<ArrayBuffer>> {
  return hkdf(root, { salt: "acme-app", info: `acme/${purpose}/v1` });
}

/** Signs session cookies. */
export const cookieKey: CryptoKey = await importHmacKey(await derive("session-cookie"));

/** Encrypts uploaded files with AES-GCM. */
export const fileKey: CryptoKey = await crypto.subtle.importKey(
  "raw",
  await derive("file-encryption"),
  "AES-GCM",
  false,
  ["encrypt", "decrypt"],
);
// #endregion
