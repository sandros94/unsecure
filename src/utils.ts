export * from "./internal/utils/base32.ts";
export * from "./internal/utils/base64.ts";
export * from "./internal/utils/hex.ts";

export const textEncoder: TextEncoder = /* @__PURE__ */ new TextEncoder();
export const textDecoder: TextDecoder = /* @__PURE__ */ new TextDecoder();
