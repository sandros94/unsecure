// #region docs
import { hmac, hmacVerify, importHmacKey } from "unsecure/hmac";

const secret = process.env.WEBHOOK_SECRET;
if (!secret) throw new Error("WEBHOOK_SECRET is not set");

const key = await importHmacKey(secret);

/** Headers for an outgoing delivery, signed over the exact body you send. */
export async function signDelivery(body: string): Promise<Headers> {
  const signature = await hmac(key, body);
  return new Headers({ "x-webhook-signature": `sha256=${signature}` });
}

type Handler = (event: unknown) => Promise<void>;
/** Hands the event on only when its signature matches the raw bytes. */
export async function receiveDelivery(request: Request, handle: Handler): Promise<Response> {
  const body = await request.arrayBuffer();
  const header = request.headers.get("x-webhook-signature");
  const signature = header?.startsWith("sha256=") ? header.slice(7) : null;
  if (!(await hmacVerify(key, body, signature))) {
    return new Response("Invalid signature", { status: 401 });
  }
  await handle(JSON.parse(new TextDecoder().decode(body)));
  return new Response(null, { status: 204 });
}
// #endregion
