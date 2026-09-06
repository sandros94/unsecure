import { UnsecureError } from "../errors.ts";

/**
 * Run one Web Crypto call, reporting a refusal as the library's own error.
 *
 * Everything a caller controls is checked before any of these run, so a
 * rejection here is the runtime declining an operation the library already
 * considers well-formed — a digest disabled by policy, a hardened context, a
 * partial implementation. The platform's own failure travels on as `cause`,
 * since it is the only thing that says why.
 */
/* @__NO_SIDE_EFFECTS__ */
export async function viaWebCrypto<T>(
  source: string,
  operation: string,
  call: () => Promise<T>,
): Promise<T> {
  try {
    return await call();
  } catch (error) {
    throw new UnsecureError(
      "PLATFORM",
      `${source}: the runtime's Web Crypto refused ${operation}.`,
      {
        cause: error,
      },
    );
  }
}
