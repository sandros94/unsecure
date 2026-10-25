import { hmacVerify, importHmacKey } from "unsecure/hmac";
import { randomJitter } from "unsecure/random";

/** Events whose signature checked out, in the order they arrived. */
export const received: unknown[] = [];

/** The same refusal as in verify-webhook.ts. */
async function refuse(): Promise<Response> {
  await randomJitter(10, 50);
  return new Response("Invalid signature", { status: 401 });
}

// #region docs
import { base64Parse, textDecoder, textEncoder } from "unsecure/utils";

// "whsec_" + base64: the key is the decoded bytes, not the string
const secret = process.env.STANDARD_WEBHOOK_SECRET;
if (!secret) throw new Error("STANDARD_WEBHOOK_SECRET is not set");
const key = await importHmacKey(base64Parse(secret.replace(/^whsec_/, ""), { returnAs: "bytes" }));

export async function handleStandardWebhook(request: Request): Promise<Response> {
  const body = new Uint8Array(await request.arrayBuffer());
  const id = request.headers.get("webhook-id");
  const timestamp = request.headers.get("webhook-timestamp");
  // A captured request replays with a valid signature: refuse old ones too
  const age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (!id || !timestamp || !(age <= 5 * 60)) return refuse();

  // Signed content: "<id>.<timestamp>." followed by the body bytes
  const prefix = textEncoder.encode(`${id}.${timestamp}.`);
  const signed = new Uint8Array(prefix.length + body.length);
  signed.set(prefix);
  signed.set(body, prefix.length);
  // One "v1,<base64>" entry per secret the provider signs with
  const entries = request.headers.get("webhook-signature")?.split(" ") ?? [];
  const results = await Promise.all(
    entries.map(
      async (entry) =>
        entry.startsWith("v1,") && hmacVerify(key, signed, entry.slice(3), { returnAs: "base64" }),
    ),
  );
  if (!results.includes(true)) return refuse();

  // #hide Parse and queue the event, as above
  received.push(JSON.parse(textDecoder.decode(body)));
  // #endhide
  return new Response(null, { status: 204 });
}
// #endregion
