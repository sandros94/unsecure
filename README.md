# unsecure

[![npm version](https://npmx.dev/api/registry/badge/version/unsecure?name=true)](https://npmx.dev/package/unsecure)
[![npm downloads](https://npmx.dev/api/registry/badge/downloads/unsecure)](https://npmx.dev/package/unsecure)
[![bundle size](https://npmx.dev/api/registry/badge/size/unsecure)](https://npmx.dev/package/unsecure)

`unsecure` is a collection of runtime-agnostic cryptographically-secure utilities. (ba dum tss 🥁)

Zero dependencies, built on the Web Crypto API, one module per subpath so a CDN import ships only what you use, and one typed error for everything that can go wrong.

**Documentation: [unsecure.s94.dev](https://unsecure.s94.dev)**

## Install

```sh
# ✨ Auto-detect (supports npm, yarn, pnpm, deno and bun)
npx nypm install unsecure
```

Runs on Node.js ^22.12 or >=24, and on any runtime with Web Crypto (Bun, Deno, Cloudflare Workers, browsers).

## A taste

```ts
import { argon2Hash, argon2Verify, hmacVerify, totpVerify, uuidv7 } from "unsecure";

// Store and check a password (argon2id, OWASP defaults, PHC string)
const stored = await argon2Hash(plaintext);
const ok = await argon2Verify(stored, submitted);

// Verify a webhook signature in constant time; a missing header is `false`, never a throw
const valid = await hmacVerify(secret, body, request.headers.get("x-signature"));

// Check a 2FA code; replay is refused when you pass back the last accepted step
const result = await totpVerify(secret, code, { lastAccepted: user.lastOtpStep });

// A time-ordered identifier
const id = uuidv7();
```

Every module is also its own entry point:

```js
import { hkdf } from "https://esm.sh/unsecure/hkdf";
import { base64Parse } from "https://esm.sh/unsecure/utils";
```

## What's inside

| Module                                                      | Functions                                                                                                                    | Docs                                                          |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `unsecure/hash`, `unsecure/hmac`                            | `hash`, `hmac`, `hmacVerify`, `importHmacKey`                                                                                | [Hashing & MAC](https://unsecure.s94.dev/hashing)             |
| `unsecure/hkdf`                                             | `hkdf`, `importHkdfKey`                                                                                                      | [Key derivation](https://unsecure.s94.dev/key-derivation)     |
| `unsecure/argon2`                                           | `argon2`, `argon2Hash`, `argon2Verify`, `argon2NeedsRehash`                                                                  | [Password hashing](https://unsecure.s94.dev/password-hashing) |
| `unsecure/otp`                                              | `hotp`, `hotpVerify`, `totp`, `totpVerify`, `generateOTPSecret`, `otpauthURI`                                                | [One-time passwords](https://unsecure.s94.dev/otp)            |
| `unsecure/uuid`                                             | `uuidv4`, `uuidv7`, `createUUIDv7Generator`, `uuidv7Timestamp`, `isUUIDv4`, `isUUIDv7`                                       | [UUID](https://unsecure.s94.dev/uuid)                         |
| `unsecure/generate`, `unsecure/compare`, `unsecure/entropy` | `secureGenerate`, `secureCompare`, `entropy`                                                                                 | [Secrets](https://unsecure.s94.dev/secrets)                   |
| `unsecure/sanitize`                                         | `sanitizeObject`, `sanitizeObjectCopy`, `safeJsonParse`                                                                      | [Sanitize](https://unsecure.s94.dev/sanitize)                 |
| `unsecure/random`                                           | `createSecureRandomGenerator`, `secureRandomNumber`, `secureRandomBytes`, `secureShuffle`, `randomJitter`                    | [Random](https://unsecure.s94.dev/random)                     |
| `unsecure/utils`                                            | `hexStringify` / `hexParse`, `base64Stringify` / `base64Parse`, `base32Stringify` / `base32Parse`, `Hex`, `Base64`, `Base32` | [Codecs](https://unsecure.s94.dev/codecs)                     |
| `unsecure/errors`                                           | `UnsecureError`                                                                                                              | [Errors](https://unsecure.s94.dev/errors)                     |

## The contract

- Everything the library throws is an `UnsecureError` with a machine-readable `code`; branch on the code, not the message.
- Verification functions (`secureCompare`, `hmacVerify`, `hotpVerify`, `totpVerify`, `argon2Verify`) never throw on untrusted input. They return `false`; a throw means your own configuration is wrong.
- Decoding is strict and canonical by default, inputs are range-checked at the boundary, and behavior is identical on every runtime and backend.

Upgrading from an earlier release? The docs keep the [migration guides](https://unsecure.s94.dev/getting-started/migration).

## Development

<details>

<summary>local development</summary>

- Clone this repository
- Install latest LTS version of [Node.js](https://nodejs.org/en/)
- Enable [Corepack](https://github.com/nodejs/corepack) using `corepack enable`
- Install dependencies using `pnpm install`
- Run the test suite using `pnpm test`

</details>

## Credits

Inspired by [DeepSource Corp work](https://github.com/DeepSourceCorp/shifty).

## License

Published under the [MIT](https://github.com/sandros94/unsecure/blob/main/LICENSE) license.
Made by [community](https://github.com/sandros94/unsecure/graphs/contributors) 💛
<br><br>
<a href="https://github.com/sandros94/unsecure/graphs/contributors">
<img src="https://contrib.rocks/image?repo=sandros94/unsecure" />
</a>
