// #region docs
import { UnsecureError } from "unsecure/errors";
import { safeJsonParse } from "unsecure/sanitize";
import { base64Parse } from "unsecure/utils";

// #hide Cursor and OrderStore are your application's own types.
interface Cursor {
  after: string;
}

interface OrderStore {
  page(cursor: Cursor | undefined): Promise<{ orders: unknown[]; next?: string }>;
}
// #endhide

/** `GET /orders?cursor=…`, where the cursor is base64url-encoded JSON. */
export async function listOrders(request: Request, store: OrderStore): Promise<Response> {
  const raw = new URL(request.url).searchParams.get("cursor");
  let cursor: Cursor | undefined;
  if (raw !== null) {
    try {
      cursor = safeJsonParse<Cursor>(base64Parse(raw, { alphabet: "base64url" }));
    } catch (error) {
      // MALFORMED is the one code this text can cause. Anything else is a
      // bug on the server, so it goes on to the fallback handler.
      if (!(error instanceof UnsecureError) || error.code !== "MALFORMED") throw error;
    }
    if (typeof cursor?.after !== "string") {
      return Response.json({ error: "Invalid cursor." }, { status: 400 });
    }
  }
  return Response.json(await store.page(cursor));
}
// #endregion

// #region fallback
/** The last stop for an error no route handled. */
export function errorResponse(error: unknown, log: (entry: object) => void): Response {
  if (!(error instanceof UnsecureError)) {
    log({ error });
    return Response.json({ error: "Internal error." }, { status: 500 });
  }
  // `cause` holds the runtime's own error, when there is one.
  log({ code: error.code, message: error.message, cause: error.cause });
  switch (error.code) {
    case "PLATFORM": {
      return Response.json({ error: "Try again later." }, { status: 503 });
    }
    default: {
      return Response.json({ error: "Internal error." }, { status: 500 });
    }
  }
}
// #endregion
