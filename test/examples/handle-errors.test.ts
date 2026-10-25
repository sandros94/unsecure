import { describe, expect, it, vi } from "vitest";
import { UnsecureError } from "unsecure/errors";
import { base64Stringify } from "unsecure/utils";
import { errorResponse, listOrders } from "../../examples/safety/handle-errors.ts";

function orderStore() {
  return { page: vi.fn(async () => ({ orders: [] })) };
}

function get(cursor?: string): Request {
  const url = new URL("https://shop.example.com/orders");
  if (cursor !== undefined) url.searchParams.set("cursor", cursor);
  return new Request(url);
}

describe("examples/safety/handle-errors", () => {
  it("reads a valid cursor, or none", async () => {
    const store = orderStore();
    const cursor = base64Stringify('{"after":"ord_1042"}', { alphabet: "base64url" });
    expect((await listOrders(get(cursor), store)).status).toBe(200);
    expect(store.page).toHaveBeenLastCalledWith({ after: "ord_1042" });
    expect((await listOrders(get(), store)).status).toBe(200);
    expect(store.page).toHaveBeenLastCalledWith(undefined);
  });

  it("answers 400 for every cursor the client got wrong", async () => {
    const store = orderStore();
    const bad = [
      "not base64!",
      base64Stringify("{oops", { alphabet: "base64url" }),
      base64Stringify(new Uint8Array([0xff, 0xfe]), { alphabet: "base64url" }),
      base64Stringify('{"after":1042}', { alphabet: "base64url" }),
      base64Stringify("null", { alphabet: "base64url" }),
    ];
    for (const cursor of bad) expect((await listOrders(get(cursor), store)).status).toBe(400);
    expect(store.page).not.toHaveBeenCalled();
  });

  it("lets a server-side failure through to the fallback", async () => {
    const store = { page: vi.fn(async () => Promise.reject(new Error("database down"))) };
    await expect(listOrders(get(), store)).rejects.toThrow("database down");
  });

  it("maps PLATFORM to 503 and logs the cause", () => {
    const cause = new DOMException("refused", "NotSupportedError");
    const log = vi.fn();
    const response = errorResponse(
      new UnsecureError("PLATFORM", "hash: the runtime's Web Crypto refused digest.", { cause }),
      log,
    );
    expect(response.status).toBe(503);
    expect(log).toHaveBeenCalledWith(expect.objectContaining({ code: "PLATFORM", cause }));
  });

  it("maps every other error to 500", () => {
    const log = vi.fn();
    expect(
      errorResponse(new UnsecureError("OUT_OF_RANGE", "hmac: secret must not be empty."), log)
        .status,
    ).toBe(500);
    expect(errorResponse(new TypeError("x is undefined"), log).status).toBe(500);
  });
});
