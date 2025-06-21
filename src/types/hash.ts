export type DigestAlgorithm = "SHA-256" | "SHA-384" | "SHA-512";

export interface DigestOptions {
  /**
   * The hashing algorithm to use.
   *
   * @default 'SHA-256'
   */
  algorithm?: DigestAlgorithm;
  /**
   * Whether to output to string or Uint8Array
   *
   * @default true
   */
  asString?: boolean;
}
