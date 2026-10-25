// #region docs
import { UnsecureError } from "unsecure/errors";
import { base64Parse } from "unsecure/utils";

/** An uploaded avatar sent as base64, or `null` when the text isn't base64. */
export function readAvatar(text: string): Uint8Array | null {
  try {
    return base64Parse(text, { returnAs: "bytes" });
  } catch (error) {
    // 0.2: if (error instanceof SyntaxError) return null;
    if (error instanceof UnsecureError && error.code === "MALFORMED") return null;
    throw error;
  }
}
// #endregion
