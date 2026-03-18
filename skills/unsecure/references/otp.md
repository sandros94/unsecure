# OTP (HOTP / TOTP)

RFC 4226 (HOTP) and RFC 6238 (TOTP) one-time password generation and verification, built on top of [`hmac()`](./hmac.md). Secrets can be raw `Uint8Array` or base32-encoded strings.

All verification functions use `secureCompare()` internally for constant-time checks.

## generateOTPSecret()

Generates a cryptographically random OTP secret, returned as a base32-encoded string (without padding).

```ts
import { generateOTPSecret } from "unsecure";

const secret = generateOTPSecret(); // 20 bytes, base32 string (ideal for SHA-1)
const secret256 = generateOTPSecret(32); // 32 bytes (ideal for SHA-256)
const secret512 = generateOTPSecret(64); // 64 bytes (ideal for SHA-512)
```

## hotp() / hotpVerify()

HMAC-based One-Time Passwords (RFC 4226).

**Options:**

- `algorithm`: `"SHA-1"` (default), `"SHA-256"`, `"SHA-384"`, `"SHA-512"`
- `digits`: number of digits (default `6`)
- `window` (verify only): counter values to check ahead (default `0`)

```ts
import { hotp, hotpVerify } from "unsecure";

const code = await hotp(secret, 0); // "755224"
const code8 = await hotp(secret, 0, { digits: 8 }); // 8-digit code

const { valid, delta } = await hotpVerify(secret, "287082", 0, { window: 5 });
// valid: true, delta: 1 means it matched at counter + 1
```

## totp() / totpVerify()

Time-based One-Time Passwords (RFC 6238).

**Options:**

- `algorithm`: `"SHA-1"` (default), `"SHA-256"`, `"SHA-384"`, `"SHA-512"`
- `digits`: number of digits (default `6`)
- `period`: time step in seconds (default `30`)
- `time`: Unix timestamp in seconds (defaults to current time; useful for testing)
- `window` (verify only): time steps to check in each direction (default `1`)

```ts
import { totp, totpVerify } from "unsecure";

const code = await totp(secret); // current time step

// Verify with ±1 window (default)
const { valid, delta } = await totpVerify(secret, userInputCode);
// delta: 0 = current, -1 = previous step, +1 = next step

// Custom period and algorithm
const code2 = await totp(secret, { period: 60, algorithm: "SHA-256" });

// Deterministic testing
const code3 = await totp(secret, { time: 1234567890 });
```

## otpauthURI()

Builds an `otpauth://` URI for provisioning OTP tokens via QR code.

```ts
import { otpauthURI } from "unsecure";

const uri = otpauthURI({
  type: "totp",
  secret: base32Secret,
  account: "user@example.com",
  issuer: "MyApp",
});
// "otpauth://totp/MyApp:user%40example.com?secret=...&issuer=MyApp&algorithm=SHA1&digits=6&period=30"

// HOTP (counter is required)
const hotpUri = otpauthURI({
  type: "hotp",
  secret: secret,
  account: "user@example.com",
  counter: 0,
});
```

## Use Case: TOTP Two-Factor Authentication Flow

```ts
import { generateOTPSecret, otpauthURI, totpVerify } from "unsecure";

// Setup: generate secret and QR code URI
function setup2FA(userEmail: string) {
  const secret = generateOTPSecret(); // 20 bytes for SHA-1
  const uri = otpauthURI({
    type: "totp",
    secret,
    account: userEmail,
    issuer: "MyApp",
  });
  // Store `secret` securely in database for this user
  // Return `uri` to frontend to render as QR code
  return { secret, uri };
}

// Verify: check user-submitted code
async function verify2FA(storedSecret: string, userCode: string) {
  const { valid } = await totpVerify(storedSecret, userCode);
  return valid;
}
```

## Pitfall: Mismatched OTP Secret Sizes

The RFC recommends secrets at least as long as the hash output.

```ts
// ❌ 20-byte secret with SHA-512 (should be 64 bytes)
const code = await totp(generateOTPSecret(), { algorithm: "SHA-512" });

// ✅ Match secret size to algorithm
const code1 = await totp(generateOTPSecret(20)); // SHA-1 (default)
const code256 = await totp(generateOTPSecret(32), { algorithm: "SHA-256" });
const code512 = await totp(generateOTPSecret(64), { algorithm: "SHA-512" });
```

## Pitfall: Storing OTP Secrets as Raw Bytes in JSON

```ts
// ❌ Uint8Array doesn't serialize cleanly to JSON
JSON.stringify({ secret: secretBytes }); // [object Object] or weird array

// ✅ Use generateOTPSecret() which returns base32 string
const secret = generateOTPSecret(); // "JBSWY3DPEHPK3PXP..."
JSON.stringify({ secret }); // works perfectly

// ✅ OTP functions accept both base32 strings and Uint8Array
await totp(secret); // string: auto-decoded from base32
```

## Pitfall: HOTP Without Counter Tracking

HOTP requires tracking the counter server-side. If you don't increment after successful verification, the same code works forever.

```ts
// ❌ Never updating the counter
const { valid } = await hotpVerify(secret, code, storedCounter, { window: 5 });

// ✅ Update counter on success
const { valid, delta } = await hotpVerify(secret, code, storedCounter, { window: 5 });
if (valid) {
  storedCounter += delta + 1; // advance past the matched counter
  // persist storedCounter to database
}
```
