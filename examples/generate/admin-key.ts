import { secureCompare } from "unsecure/compare";

// #region docs
/** The key operators send in the `X-Admin-Key` header. */
const adminKey = process.env.ADMIN_API_KEY;

// An unset key would refuse every request without saying why.
if (!adminKey) throw new Error("ADMIN_API_KEY is not set");

export function isAdmin(request: Request): boolean {
  // Your value first, the request's second. A missing header is `null`.
  return secureCompare(adminKey, request.headers.get("x-admin-key"));
}
// #endregion
