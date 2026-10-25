// #region docs
import { UnsecureError } from "unsecure/errors";
import { safeJsonParse } from "unsecure/sanitize";

export async function createComment(request: Request): Promise<Response> {
  let comment: unknown;
  try {
    comment = safeJsonParse(await request.text());
  } catch (error) {
    if (error instanceof UnsecureError && error.code === "MALFORMED") {
      return Response.json({ error: "The body is not valid JSON." }, { status: 400 });
    }
    throw error;
  }
  // #hide Check `comment` against your schema, then store it.
  return Response.json(comment, { status: 201 });
  // #endhide
}
// #endregion
