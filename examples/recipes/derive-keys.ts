// #region docs
import { hkdf, importHkdfKey } from "unsecure/hkdf";
import { importHmacKey } from "unsecure/hmac";
import { base64Parse } from "unsecure/utils";

// 32 random bytes as base64url, from your secret manager, never the database
const secret = process.env.APP_ROOT_SECRET;
if (!secret) throw new Error("APP_ROOT_SECRET is not set");
const rootBytes = base64Parse(secret, { alphabet: "base64url", returnAs: "bytes" });
// hkdf accepts a short or empty root secret, so check the length yourself
if (rootBytes.length < 32) throw new Error("APP_ROOT_SECRET must hold 32 random bytes");

// Imported once: every derivation below reuses it
const root = await importHkdfKey(rootBytes);

/** 32 bytes for one purpose. Bump the version to rotate that key alone. */
function derive(purpose: string): Promise<Uint8Array<ArrayBuffer>> {
  return hkdf(root, { info: `acme-notes/${purpose}/v1` });
}

/** Signs session cookies. */
export const cookieKey: CryptoKey = await importHmacKey(await derive("session-cookie"));
/** Signs CSRF tokens. A leaked cookie key cannot forge these. */
export const csrfKey: CryptoKey = await importHmacKey(await derive("csrf-token"));
/** Signs expiring download links. */
export const downloadKey: CryptoKey = await importHmacKey(await derive("download-link"));
// #endregion
