// #region docs
import { UnsecureError } from "unsecure/errors";
import { base32Parse, base32Stringify, base64Parse, base64Stringify } from "unsecure/utils";

/** 32 random bytes as cookie-safe text: URL-safe alphabet, no padding. */
export function encodeSessionId(id: Uint8Array): string {
  return base64Stringify(id, { alphabet: "base64url" });
}

/** The bytes back, or `null` for anything but that exact spelling. */
export function decodeSessionId(cookie: string | undefined): Uint8Array | null {
  if (cookie === undefined) return null;
  try {
    const id = base64Parse(cookie, { alphabet: "base64url", padding: false, returnAs: "bytes" });
    return id.length === 32 ? id : null;
  } catch (error) {
    if (error instanceof UnsecureError && error.code === "MALFORMED") return null;
    throw error;
  }
}
// #endregion

// #region loose
/**
 * A 15-byte license key, printed as 24 Crockford base32 characters in
 * groups, that a person types back in any case, with spaces or dashes.
 * Loose decoding drops what it cannot read, so check the length, then keep
 * only the canonical spelling.
 */
export function normalizeLicenseKey(typed: string): string | null {
  const key = base32Parse(typed, { alphabet: "crockford", loose: true, returnAs: "bytes" });
  if (key.length !== 15) return null;
  return base32Stringify(key, { alphabet: "crockford" });
}
// #endregion
