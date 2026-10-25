import { describe, expect, it, vi } from "vitest";
import { hmac } from "unsecure/hmac";

const SECRET = "whsec-7f3a9c1e5b2d4f6a8c0e";
const BODY = JSON.stringify({ action: "opened", number: 1347 });

function delivery(headers: Record<string, string>): Request {
  return new Request("https://api.example.com/webhooks/github", {
    method: "POST",
    headers,
    body: BODY,
  });
}

describe("examples/getting-started/verify-webhook", () => {
  it("accepts a signed delivery and refuses a forged, missing or garbled one", async () => {
    vi.stubEnv("GITHUB_WEBHOOK_SECRET", SECRET);
    const { receiveWebhook } = await import("../../examples/getting-started/verify-webhook.ts");
    const signature = await hmac(SECRET, BODY);
    const forged = await hmac("another-secret", BODY);

    expect(
      (await receiveWebhook(delivery({ "x-hub-signature-256": `sha256=${signature}` }))).status,
    ).toBe(204);
    expect(
      (await receiveWebhook(delivery({ "x-hub-signature-256": `sha256=${forged}` }))).status,
    ).toBe(401);
    expect((await receiveWebhook(delivery({}))).status).toBe(401);
    expect(
      (await receiveWebhook(delivery({ "x-hub-signature-256": "sha256=not-hex" }))).status,
    ).toBe(401);
    expect((await receiveWebhook(delivery({ "x-hub-signature-256": signature }))).status).toBe(401);
  });
});

describe("examples/getting-started/verify-webhook without a secret", () => {
  it("fails at start-up, not on the first request", async () => {
    vi.resetModules();
    vi.stubEnv("GITHUB_WEBHOOK_SECRET", "");
    await expect(import("../../examples/getting-started/verify-webhook.ts")).rejects.toThrow(
      "GITHUB_WEBHOOK_SECRET is not set",
    );
  });
});
