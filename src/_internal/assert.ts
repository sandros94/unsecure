import { describeValue } from "./bytes.ts";
import { UnsecureError } from "../errors.ts";

/**
 * Name a caller value in an error message: the value itself when a reader can
 * act on it, its type when the value would be noise — an object prints as
 * `[object Object]`, and a byte container is usually secret material.
 */
/* @__NO_SIDE_EFFECTS__ */
export function showValue(value: unknown): string {
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (typeof value === "string") return JSON.stringify(value);
  return describeValue(value);
}

/**
 * Check a numeric option against the range it is documented with, at the
 * boundary that owns it. Every bounded number in the library is a safe integer
 * in a fixed range, so one check keeps both the wording and what counts as
 * valid identical across modules. `max` is left open when the only real limit
 * is the safe-integer range.
 */
export function assertInteger(
  source: string,
  name: string,
  value: number,
  min: number,
  max: number = Number.MAX_SAFE_INTEGER,
): void {
  if (Number.isSafeInteger(value) && value >= min && value <= max) return;
  const range =
    max === Number.MAX_SAFE_INTEGER
      ? `an integer >= ${min}`
      : `an integer between ${min} and ${max}`;
  throw new UnsecureError(
    "OUT_OF_RANGE",
    `${source}: ${name} must be ${range}, got ${showValue(value)}.`,
  );
}
