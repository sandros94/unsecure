// #region docs
import { UnsecureError } from "unsecure/errors";
import { safeJsonParse, sanitizeObject, sanitizeObjectCopy } from "unsecure/sanitize";

// #hide Settings and SettingsStore are your application's own types.
interface Settings {
  theme?: "light" | "dark";
  language?: string;
}

interface SettingsStore {
  update(userId: string, patch: Settings): Promise<Settings>;
}
// #endhide

export async function updateSettings(
  request: Request,
  userId: string,
  store: SettingsStore,
): Promise<Response> {
  let patch: unknown;
  try {
    patch = safeJsonParse(await request.text());
  } catch (error) {
    if (error instanceof UnsecureError && error.code === "MALFORMED") {
      return Response.json({ error: "The body is not valid JSON." }, { status: 400 });
    }
    throw error;
  }
  if (typeof patch !== "object" || patch === null || Array.isArray(patch)) {
    return Response.json({ error: "Expected a JSON object." }, { status: 422 });
  }
  return Response.json(await store.update(userId, patch as Settings));
}
// #endregion

// #region middleware
/** For a framework that already parsed the body: strip the keys in place. */
export function sanitizeBody(req: { body?: unknown }, _res: unknown, next: () => void): void {
  if (typeof req.body === "object" && req.body !== null) {
    sanitizeObject(req.body as Record<string, unknown>);
  }
  next();
}
// #endregion

// #region copy
interface Job {
  id: string;
  runAt: Date;
  payload: Record<string, unknown>;
}

/**
 * A job message from a worker thread. Every listener receives the same
 * object, so copy it instead of changing it. `Date` values survive the
 * message, so they are allowed through as they are.
 */
export function readJob(message: unknown): Job {
  return sanitizeObjectCopy(message, { allowlist: [Date] }) as Job;
}
// #endregion
