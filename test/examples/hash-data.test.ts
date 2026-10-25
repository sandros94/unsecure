import { describe, expect, it } from "vitest";
import { hash } from "unsecure/hash";
import { etag, matchesChecksum, serve } from "../../examples/crypto/hash-data.ts";

const body = JSON.stringify({ id: "inv_2041", total: 129.5, currency: "EUR" });

describe("examples/crypto/hash-data", () => {
  it("gives the same body the same tag and a changed body a new one", async () => {
    expect(await etag(body)).toBe(await etag(body));
    expect(await etag(body)).not.toBe(await etag(body.replace("129.5", "129.6")));
    expect(await etag(body)).toMatch(/^"[\w-]{43}"$/);
  });

  it("answers 304 when the client already holds this version", async () => {
    const first = await serve(new Request("https://acme.example/invoices/2041"), body);
    expect(first.status).toBe(200);
    const tag = first.headers.get("etag")!;

    const again = new Request("https://acme.example/invoices/2041", {
      headers: { "if-none-match": tag },
    });
    expect((await serve(again, body)).status).toBe(304);
    expect((await serve(again, body.replace("EUR", "USD"))).status).toBe(200);
  });

  it("matches a published checksum whatever its case or surrounding whitespace", async () => {
    const file = new TextEncoder().encode("release tarball contents");
    const published = (await hash(file, { returnAs: "hex" })).toUpperCase();
    expect(await matchesChecksum(file, ` ${published}\n`)).toBe(true);
    expect(await matchesChecksum(file.slice(1), published)).toBe(false);
  });

  it("mirrors the input type when returnAs is omitted", async () => {
    expect(await hash("hello world")).toBe(
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    );
    expect(await hash(new TextEncoder().encode("hello world"))).toBeInstanceOf(Uint8Array);
  });

  it("throws for the failure rows of the page", async () => {
    await expect(hash(42 as unknown as string)).rejects.toMatchObject({ code: "INVALID_TYPE" });
    await expect(hash("x", { algorithm: "MD5" as "SHA-256" })).rejects.toMatchObject({
      code: "UNSUPPORTED",
    });
    await expect(hash("x", { returnAs: "base32" as "hex" })).rejects.toMatchObject({
      code: "UNSUPPORTED",
    });
    expect(await hash("x", { algorithm: "sha-256" as "SHA-256" })).toBe(await hash("x"));
  });
});
