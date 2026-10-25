import { describe, expect, it, vi } from "vitest";
import { hmac, hmacVerify, importHmacKey } from "unsecure/hmac";

const SECRET = "whsec_9f8a7d6c5b4e3f2a1b0c9d8e7f6a5b4c";

async function load() {
  vi.stubEnv("WEBHOOK_SECRET", SECRET);
  return import("../../examples/crypto/sign-messages.ts");
}

function delivery(body: string, signature?: string): Request {
  return new Request("https://acme.example/webhooks/billing", {
    method: "POST",
    body,
    headers: signature === undefined ? {} : { "x-webhook-signature": signature },
  });
}

const body = JSON.stringify({ type: "invoice.paid", invoice: "inv_2041" });

/** A handler the refused deliveries must never reach. */
async function refuse(): Promise<void> {
  throw new Error("a refused delivery reached the handler");
}

describe("examples/crypto/sign-messages", () => {
  it("accepts a delivery signed with the shared secret", async () => {
    const { receiveDelivery, signDelivery } = await load();
    const header = (await signDelivery(body)).get("x-webhook-signature")!;
    expect(header).toMatch(/^sha256=[0-9a-f]{64}$/);
    expect(header.slice(7)).toBe(await hmac(SECRET, body));
    const events: unknown[] = [];
    const handle = async (event: unknown) => {
      events.push(event);
    };
    expect((await receiveDelivery(delivery(body, header), handle)).status).toBe(204);
    expect(events).toEqual([JSON.parse(body)]);
  });

  it("refuses a changed body, a missing header and garbage alike, without throwing", async () => {
    const { receiveDelivery, signDelivery } = await load();
    const header = (await signDelivery(body)).get("x-webhook-signature")!;
    const reformatted = JSON.stringify(JSON.parse(body), null, 2);
    expect((await receiveDelivery(delivery(reformatted, header), refuse)).status).toBe(401);
    expect((await receiveDelivery(delivery(body), refuse)).status).toBe(401);
    expect((await receiveDelivery(delivery(body, "sha256=not-hex"), refuse)).status).toBe(401);
    expect((await receiveDelivery(delivery(body, header.slice(7)), refuse)).status).toBe(401);
  });

  it("returns false for untrusted signatures and throws for configuration", async () => {
    expect(await hmacVerify(SECRET, body, null)).toBe(false);
    expect(await hmacVerify(SECRET, body, 12_345 as unknown as string)).toBe(false);
    const base64 = await hmac(SECRET, body, { returnAs: "base64" });
    expect(await hmacVerify(SECRET, body, base64)).toBe(false);
    expect(await hmacVerify(SECRET, body, base64, { returnAs: "base64" })).toBe(true);

    await expect(hmacVerify(undefined as unknown as string, body, base64)).rejects.toMatchObject({
      code: "INVALID_TYPE",
    });
    await expect(hmacVerify("", body, base64)).rejects.toMatchObject({ code: "OUT_OF_RANGE" });
    const key = await importHmacKey(SECRET);
    await expect(hmacVerify(key, body, base64, { algorithm: "SHA-512" })).rejects.toMatchObject({
      code: "OUT_OF_RANGE",
    });
    await expect(hmac(SECRET, body, { algorithm: "MD5" as "SHA-256" })).rejects.toMatchObject({
      code: "UNSUPPORTED",
    });
  });
});
