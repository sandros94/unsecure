import { afterEach, describe, expect, it, vi } from "vitest";
import { hmac } from "unsecure/hmac";

const SECRET = "whk_7f3c9a1e5b2d4f6a8c0e1b3d5f7a9c2e";
const BODY = JSON.stringify({ action: "opened", issue: { number: 1347 } });

async function load(secret: string | undefined) {
  vi.resetModules();
  vi.stubEnv("WEBHOOK_SECRET", secret);
  return import("../../../examples/recipes/verify-webhook.ts");
}

function delivery(body: string, headers: Record<string, string>): Request {
  return new Request("https://api.example.com/webhooks/github", {
    method: "POST",
    body,
    headers: { "content-type": "application/json", ...headers },
  });
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("examples/recipes/verify-webhook", () => {
  it("accepts a signed body and queues the parsed event", async () => {
    const { handleWebhook, received } = await load(SECRET);
    const signature = `sha256=${await hmac(SECRET, BODY)}`;
    const response = await handleWebhook(delivery(BODY, { "x-hub-signature-256": signature }));
    expect(response.status).toBe(204);
    expect(received).toEqual([JSON.parse(BODY)]);
  });

  it("refuses a tampered body, a missing header, a missing prefix and garbage alike", async () => {
    const { handleWebhook, received } = await load(SECRET);
    const hex = await hmac(SECRET, BODY);
    const cases: Array<[string, Record<string, string>]> = [
      [BODY.replace("1347", "1348"), { "x-hub-signature-256": `sha256=${hex}` }],
      [BODY, {}],
      [BODY, { "x-hub-signature-256": hex }],
      [BODY, { "x-hub-signature-256": "sha256=not-hex-at-all" }],
      // Re-serialized JSON is not the bytes that were signed
      [JSON.stringify(JSON.parse(BODY), null, 2), { "x-hub-signature-256": `sha256=${hex}` }],
    ];
    for (const [body, headers] of cases) {
      const response = await handleWebhook(delivery(body, headers));
      expect(response.status).toBe(401);
      expect(await response.text()).toBe("Invalid signature");
    }
    expect(received).toEqual([]);
  });

  it("fails at start-up when the secret is unset or empty", async () => {
    await expect(load(undefined)).rejects.toThrow("WEBHOOK_SECRET is not set");
    await expect(load("")).rejects.toThrow("WEBHOOK_SECRET is not set");
  });
});
