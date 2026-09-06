import { expect } from "vitest";
import { type UnsecureErrorCode, UnsecureError } from "../src/errors.ts";

/**
 * Assert that a call fails the library's way: an {@link UnsecureError} whose
 * `code` is `code`, and whose message contains `message` when one is given (a
 * string is a substring, matching what `toThrow` accepts).
 *
 * A thunk is called and asserted synchronously; a promise is awaited, so an
 * async call is passed as `expectUnsecureError(hash(bad), "UNSUPPORTED")`. The
 * error is returned for any further assertion — `cause`, most often.
 */
export function expectUnsecureError(
  subject: () => unknown,
  code: UnsecureErrorCode,
  message?: string | RegExp,
): UnsecureError;
export function expectUnsecureError(
  subject: Promise<unknown>,
  code: UnsecureErrorCode,
  message?: string | RegExp,
): Promise<UnsecureError>;
export function expectUnsecureError(
  subject: (() => unknown) | Promise<unknown>,
  code: UnsecureErrorCode,
  message?: string | RegExp,
): UnsecureError | Promise<UnsecureError> {
  if (typeof subject === "function") {
    try {
      subject();
    } catch (error) {
      return _assertUnsecureError(error, code, message);
    }
    expect.unreachable(`expected an UnsecureError with code ${code}, nothing was thrown`);
  }
  return subject.then(
    () => expect.unreachable(`expected an UnsecureError with code ${code}, nothing was thrown`),
    (error: unknown) => _assertUnsecureError(error, code, message),
  );
}

function _assertUnsecureError(
  error: unknown,
  code: UnsecureErrorCode,
  message: string | RegExp | undefined,
): UnsecureError {
  expect(error).toBeInstanceOf(UnsecureError);
  const unsecureError = error as UnsecureError;
  expect(unsecureError.code).toBe(code);
  if (typeof message === "string") expect(unsecureError.message).toContain(message);
  else if (message !== undefined) expect(unsecureError.message).toMatch(message);
  return unsecureError;
}
