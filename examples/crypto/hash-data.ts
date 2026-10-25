// #region docs
import { hash } from "unsecure/hash";

/** The same body always gets the same tag, and any change gives a new one. */
export async function etag(body: string): Promise<string> {
  return `"${await hash(body, { returnAs: "base64url" })}"`;
}

export async function serve(request: Request, body: string): Promise<Response> {
  const tag = await etag(body);
  if (request.headers.get("if-none-match") === tag) {
    return new Response(null, { status: 304, headers: { etag: tag } });
  }
  return new Response(body, {
    headers: { "etag": tag, "content-type": "application/json" },
  });
}
// #endregion

// #region checksum
/** Checks a download against the SHA-256 checksum its publisher lists. */
export async function matchesChecksum(file: Uint8Array, published: string): Promise<boolean> {
  const digest = await hash(file, { returnAs: "hex" });
  return digest === published.trim().toLowerCase();
}
// #endregion
