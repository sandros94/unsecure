export type DigestAlgorithm = "SHA-256" | "SHA-384" | "SHA-512";
export type DigestReturnAs = "hex" | "base64" | "b64" | "base64url" | "b64url" | "uint8array" | "bytes";

export interface DigestOptions {
  /**
   * The hashing algorithm to use.
   *
   * @default 'SHA-256'
   */
  algorithm?: DigestAlgorithm;
  /**
   * Whether to output to HEX, Base64, Base64URL or Uint8Array
   *
   * @default 'hex'
   */
  returnAs?: DigestReturnAs;
}
