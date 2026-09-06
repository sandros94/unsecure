/**
 * What kind of mistake an {@link UnsecureError} reports.
 *
 * This is the complete set for this release, so a `switch` over it is
 * exhaustive today. A later minor may add a member — keep a default branch, or
 * a new code will fall through unhandled.
 *
 * - `INVALID_TYPE` — a value of the wrong JavaScript type, or nothing where a
 *   value is required.
 * - `OUT_OF_RANGE` — the right type, outside its documented domain: a number
 *   past its bounds, an empty secret, an alphabet that is not 32 distinct
 *   ASCII characters, no character set selected.
 * - `MALFORMED` — text that is not what it claims to be: a non-canonical
 *   encoding, decoded bytes that are not valid UTF-8, JSON that does not parse.
 * - `UNSUPPORTED` — a name outside the set the library accepts: a digest
 *   algorithm, a `returnAs`, an `otpauthURI` `type`.
 * - `FROZEN` — a dangerous key cannot be removed because the object holding it
 *   is frozen or sealed.
 * - `PLATFORM` — the runtime's Web Crypto refused an operation the library had
 *   already validated; `cause` carries the platform error.
 */
export type UnsecureErrorCode =
  | "INVALID_TYPE"
  | "OUT_OF_RANGE"
  | "MALFORMED"
  | "UNSUPPORTED"
  | "FROZEN"
  | "PLATFORM";

/**
 * Everything this library throws.
 *
 * `message` says what was found and where; `code` is the machine-readable
 * version of the same judgement, and is what a caller should branch on. A
 * failure that came from outside the library — the runtime's Web Crypto, or
 * `JSON.parse` — carries the original in `cause`.
 *
 * @example
 * try {
 *   await hmacVerify(secret, body, signature);
 * } catch (error) {
 *   if (!(error instanceof UnsecureError)) throw error;
 *   switch (error.code) {
 *     case "OUT_OF_RANGE": {
 *       // The secret failed to load: a deployment problem, not a bad request.
 *       return respond(500);
 *     }
 *     case "PLATFORM": {
 *       return respond(503, { cause: error.cause });
 *     }
 *     default: {
 *       return respond(400, { reason: error.code });
 *     }
 *   }
 * }
 */
export class UnsecureError extends Error {
  readonly code: UnsecureErrorCode;

  constructor(code: UnsecureErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "UnsecureError";
    this.code = code;
  }
}
