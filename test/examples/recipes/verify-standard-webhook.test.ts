import { afterEach, describe, expect, it, vi } from "vitest";
import { hmac } from "unsecure/hmac";
import { secureRandomBytes } from "unsecure/random";
import { base64Stringify } from "unsecure/utils";

const KEY_BYTES = secureRandomBytes(24);
const SECRET = `whsec_${base64Stringify(KEY_BYTES)}`;
const BODY = JSON.stringify({ type: "invoice.paid", data: { id: "inv_1347" } });
const ID = "msg_2KWPBgLlAfxdpx2AI54pPJ85f4W";

async function load(secret: string | undefined) {
  vi.resetModules();
  vi.stubEnv("STANDARD_WEBHOOK_SECRET", secret);
  return import("../../../examples/recipes/verify-standard-webhook.ts");
}

const now = () => String(Math.floor(Date.now() / 1000));

/** Signs with the decoded key bytes, as a Standard Webhooks sender does. */
async function sign(key: Uint8Array, timestamp: string, body = BODY) {
  const signed = `${ID}.${timestamp}.${body}`;
  return `v1,${await hmac(key, new TextEncoder().encode(signed), { returnAs: "base64" })}`;
}

function delivery(timestamp: string, signature: string, body = BODY): Request {
  return new Request("https://api.example.com/webhooks/billing", {
    method: "POST",
    body,
    headers: {
      "content-type": "application/json",
      "webhook-id": ID,
      "webhook-timestamp": timestamp,
      "webhook-signature": signature,
    },
  });
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/recipes/verify-standard-webhook", () => {
  it("accepts a fresh delivery signed with the decoded secret", async () => {
    const { handleStandardWebhook, received } = await load(SECRET);
    const t = now();
    expect((await handleStandardWebhook(delivery(t, await sign(KEY_BYTES, t)))).status).toBe(204);
    expect(received).toEqual([JSON.parse(BODY)]);
  });

  it("accepts a delivery where one of several signatures matches", async () => {
    const { handleStandardWebhook } = await load(SECRET);
    const t = now();
    const rotated = `${await sign(secureRandomBytes(24), t)} ${await sign(KEY_BYTES, t)}`;
    expect((await handleStandardWebhook(delivery(t, rotated))).status).toBe(204);
  });

  it("refuses a signature keyed with the secret string instead of its bytes", async () => {
    const { handleStandardWebhook } = await load(SECRET);
    const t = now();
    const wrong = `v1,${await hmac(SECRET, `${ID}.${t}.${BODY}`, { returnAs: "base64" })}`;
    expect((await handleStandardWebhook(delivery(t, wrong))).status).toBe(401);
  });

  it("refuses stale, mismatched and tampered deliveries with the same 401", async () => {
    const { handleStandardWebhook, received } = await load(SECRET);
    const t = now();
    const old = String(Number(t) - 600);
    const requests = [
      delivery(old, await sign(KEY_BYTES, old)),
      delivery(t, await sign(KEY_BYTES, String(Number(t) - 1))),
      delivery(t, await sign(KEY_BYTES, t), BODY.replace("1347", "1348")),
      delivery(t, "v1,not base64"),
    ];
    for (const request of requests) {
      const response = await handleStandardWebhook(request);
      expect(response.status).toBe(401);
      expect(await response.text()).toBe("Invalid signature");
    }
    expect(received).toEqual([]);
  });

  it("fails at start-up when the secret is unset, empty or not base64", async () => {
    await expect(load(undefined)).rejects.toThrow("STANDARD_WEBHOOK_SECRET is not set");
    await expect(load("whsec_")).rejects.toMatchObject({ code: "OUT_OF_RANGE" });
    await expect(load("whsec_not base64!")).rejects.toMatchObject({ code: "MALFORMED" });
  });
});
