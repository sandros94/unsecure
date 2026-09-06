# UnsecureError

Everything the library throws is an `UnsecureError`. One class, one code set, one subpath (`unsecure/errors`, also re-exported from the barrel). A native `TypeError`, `RangeError` or `SyntaxError` escaping from `unsecure` is a bug — report it.

## Signature

```ts
type UnsecureErrorCode =
  "INVALID_TYPE" | "OUT_OF_RANGE" | "MALFORMED" | "UNSUPPORTED" | "FROZEN" | "PLATFORM";

class UnsecureError extends Error {
  readonly name: "UnsecureError";
  readonly code: UnsecureErrorCode;
  readonly cause?: unknown;
  constructor(code: UnsecureErrorCode, message: string, options?: { cause?: unknown });
}
```

`message` names the function, the value it judged, and what it expected — `"hkdf: length must be an integer between 1 and 8160, got 0."`. `code` is the same judgement, machine-readable; branch on it rather than on message text. `cause` is set only when the failure came from outside the library.

## Codes

| Code           | Meaning                                                                                                              | Raised by                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| -------------- | -------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `INVALID_TYPE` | A value of the wrong JavaScript type, or nothing where a value is required.                                          | `secureCompare` (`expected`), `hash` / `hmac` / `hmacVerify` / `hkdf` (`secret`, `data`, `ikm`, `salt`, `info`, a non-string `algorithm`), the OTP functions (a non-byte `secret`, `otpauthURI`'s non-string `type` / `account` / `issuer`), `secureGenerate` (`timestamp`), `SecureRandomGenerator.next` (`ignore`), `uuidv7` and `createUUIDv7Generator().next` (`timestamp`), `uuidv7Timestamp` (a non-string argument), every codec `stringify` / `parse`                                                                                                                            |
| `OUT_OF_RANGE` | The right type, outside its documented domain.                                                                       | `secureCompare` (`strict` with an empty `expected`), `hmac` / `hmacVerify` (empty secret), `hkdf` (`length`), every OTP numeric option plus an empty secret, account, issuer or a missing HOTP `counter`, `secureGenerate` (`length`, no character set selected, no room after the timestamp prefix, a character in two sets, an invalid `Date`), `secureRandomNumber` / `secureRandomBytes` / `randomJitter` / `SecureRandomGenerator.next`, `uuidv7` (a timestamp outside `[0, 2^48 - 1]`), `base32Parse` / `base32Stringify` (an `alphabet` that is not 32 distinct ASCII characters) |
| `MALFORMED`    | Text that is not what it claims to be.                                                                               | `hexParse` / `base64Parse` / `base32Parse` on anything but a canonical encoding, or when the decoded bytes are not valid UTF-8; `safeJsonParse` on JSON that does not parse; `uuidv7Timestamp` on a string that is not a canonical UUIDv7                                                                                                                                                                                                                                                                                                                                                |
| `UNSUPPORTED`  | A name outside the set the library accepts.                                                                          | Any function taking `algorithm` (`hash`, `hmac`, `hmacVerify`, `hkdf`, `hotp`, `hotpVerify`, `totp`, `totpVerify`, `otpauthURI`), any function taking `returnAs`, and `otpauthURI` for a `type` string other than `"hotp"` or `"totp"`                                                                                                                                                                                                                                                                                                                                                   |
| `FROZEN`       | A dangerous key cannot be removed because the object holding it is frozen or sealed.                                 | `sanitizeObject`, and `safeJsonParse` through it                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `PLATFORM`     | The runtime's Web Crypto refused an operation the library had already validated. `cause` carries the platform error. | `hash`, `hmac`, `hmacVerify`, `hkdf`, and the OTP functions built on them                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |

The union is complete for this release. A later minor may add a code, so keep a `default` branch in any `switch` over it.

## Examples

```ts
import { UnsecureError } from "unsecure/errors";
import { hmacVerify } from "unsecure/hmac";

try {
  const valid = await hmacVerify(secret, body, request.headers.get("x-signature"));
  return valid ? handle(body) : respond(403);
} catch (error) {
  if (!(error instanceof UnsecureError)) throw error;
  switch (error.code) {
    case "OUT_OF_RANGE": {
      // An empty secret: the deployment is misconfigured, the request is fine.
      return respond(500);
    }
    case "PLATFORM": {
      // `error.cause` is the runtime's own failure.
      return respond(503);
    }
    default: {
      return respond(400, { reason: error.code });
    }
  }
}
```

```ts
// The codecs report where the text stopped being canonical.
import { UnsecureError, base64Parse } from "unsecure";

try {
  base64Parse(untrusted);
} catch (error) {
  if (error instanceof UnsecureError && error.code === "MALFORMED") {
    return respond(400, { reason: error.message });
  }
  throw error;
}
```

## What throws and what does not

Verification functions never throw for untrusted input. `secureCompare`, `hmacVerify`, `hotpVerify` and `totpVerify` return `false` (or `{ valid: false }`) for a missing, malformed or wrong-typed value from the wire — a `null` header, a signature that is not canonical hex, a code that is not a string. They throw only for something the caller controls: an empty secret, an unsupported algorithm, an out-of-range window.

So a `catch` around a verify is about your own configuration, never about the request.

## Pitfall: matching on message text

```ts
// ❌ Breaks whenever the wording improves
if (error.message.includes("must not be empty")) { ... }

// ✅ Codes are the contract
if (error instanceof UnsecureError && error.code === "OUT_OF_RANGE") { ... }
```

## Pitfall: exhaustive switches without a default

The code union is documented as growable. A `switch` with no `default` compiles today and silently does nothing the day a code is added.

```ts
// ✅ Unknown codes still get an answer
switch (error.code) {
  case "MALFORMED":
    return respond(400);
  default:
    return respond(500);
}
```

## Pitfall: losing `cause`

`PLATFORM` errors and `safeJsonParse`'s `MALFORMED` carry the original failure in `cause`. Log it — the library's message says which operation the runtime refused, `cause` says why.
