/** Events whose signature checked out, in the order they arrived. */
export const received: unknown[] = [];

// #region docs
import { hmacVerify, importHmacKey } from "unsecure/hmac";
import { randomJitter } from "unsecure/random";
import { textDecoder } from "unsecure/utils";

const secret = process.env.WEBHOOK_SECRET;
if (!secret) throw new Error("WEBHOOK_SECRET is not set");
const key = await importHmacKey(secret);

/** Every failed check answers alike, after a random pause. */
async function refuse(): Promise<Response> {
  await randomJitter(10, 50);
  return new Response("Invalid signature", { status: 401 });
}

export async function handleWebhook(request: Request): Promise<Response> {
  // The signature covers the exact bytes the provider sent
  const body = new Uint8Array(await request.arrayBuffer());
  const header = request.headers.get("x-hub-signature-256");
  const signature = header?.startsWith("sha256=") ? header.slice(7) : null;
  if (!(await hmacVerify(key, body, signature))) return refuse();

  // #hide The body is now trusted: parse it and queue the event
  received.push(JSON.parse(textDecoder.decode(body)));
  // #endhide
  return new Response(null, { status: 204 });
}
// #endregion
