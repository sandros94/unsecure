import { describe, expect, it } from "vitest";
import {
  type TokenRow,
  type TokenStore,
  authenticate,
  issueToken,
} from "../../../examples/recipes/api-tokens.ts";

function memoryStore(): TokenStore & { rows: TokenRow[] } {
  const rows: TokenRow[] = [];
  return {
    rows,
    insertToken: async (row) => {
      rows.push({ id: `tok_${rows.length + 1}`, ...row });
    },
    findByDigest: async (digest) => rows.find((row) => row.digest === digest),
  };
}

describe("examples/recipes/api-tokens", () => {
  it("issues a prefixed token and stores only its SHA-256 digest", async () => {
    const store = memoryStore();
    const token = await issueToken(store, "usr_ada", "CI deploys");
    expect(token).toMatch(/^acme_pat_[A-Za-z0-9]{32}$/);
    expect(store.rows).toHaveLength(1);
    expect(store.rows[0]!.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(store.rows)).not.toContain(token.slice(9));
  });

  it("finds the row by digest for a valid bearer token", async () => {
    const store = memoryStore();
    const token = await issueToken(store, "usr_ada", "CI deploys");
    expect(await authenticate(store, `Bearer ${token}`)).toMatchObject({ userId: "usr_ada" });
    expect(await authenticate(store, `bearer ${token}`)).toMatchObject({ userId: "usr_ada" });
  });

  it("refuses missing, malformed, unknown and expired tokens", async () => {
    const store = memoryStore();
    const token = await issueToken(store, "usr_ada", "CI deploys");
    expect(await authenticate(store, null)).toBeNull();
    expect(await authenticate(store, token)).toBeNull();
    expect(await authenticate(store, `Basic ${token}`)).toBeNull();
    expect(await authenticate(store, `Bearer ${token} extra`)).toBeNull();
    expect(await authenticate(store, "Bearer ghp_0123456789abcdefghijklmnop")).toBeNull();
    expect(await authenticate(store, `Bearer ${token.slice(0, -1)}x`)).toBeNull();

    store.rows[0]!.expiresAt = new Date(Date.now() - 1000);
    expect(await authenticate(store, `Bearer ${token}`)).toBeNull();
  });

  it("refuses the row a broken query returns for a different token", async () => {
    const store = memoryStore();
    await issueToken(store, "usr_ada", "CI deploys");
    const other = await issueToken(store, "usr_grace", "Nightly backup");
    store.rows.pop();
    // A query that lost its WHERE clause returns the first row for any digest
    store.findByDigest = async () => store.rows[0];
    expect(await authenticate(store, `Bearer ${other}`)).toBeNull();
  });
});
