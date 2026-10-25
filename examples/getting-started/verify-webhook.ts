// #region docs
import { hmacVerify, importHmacKey } from "unsecure/hmac";

const secret = process.env.GITHUB_WEBHOOK_SECRET;
if (!secret) throw new Error("GITHUB_WEBHOOK_SECRET is not set");
const key = await importHmacKey(secret);

export async function receiveWebhook(request: Request): Promise<Response> {
  const body = await request.arrayBuffer();
  const header = request.headers.get("x-hub-signature-256");
  const signature = header?.startsWith("sha256=") ? header.slice(7) : null;

  if (!(await hmacVerify(key, body, signature))) {
    return new Response("Invalid signature", { status: 401 });
  }
  // #hide Parse `body` and handle the event.
  return new Response(null, { status: 204 });
  // #endhide
}
// #endregion
