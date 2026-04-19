export * from "./base32.ts";
export * from "./base64.ts";
export * from "./hex.ts";

/**
 * Output-shape option shared by `hexDecode`, `base64Decode`, `base64UrlDecode`,
 * and `base32Decode`. Decoders mirror their input type when this is omitted:
 * `string` input decodes to `string`, `Uint8Array` input decodes to `Uint8Array`.
 *
 * `"bytes"` is an alias for `"uint8array"`.
 */
export type DecodeReturnAs = "string" | "uint8array" | "bytes";

export const textEncoder: TextEncoder = /* @__PURE__ */ new TextEncoder();
export const textDecoder: TextDecoder = /* @__PURE__ */ new TextDecoder();
