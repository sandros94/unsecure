/**
 * Copy an options bag's own properties onto a `null` prototype, so a polluted
 * `Object.prototype` can never stand in for an option the caller left out.
 * Call it first in every function that reads an options bag.
 *
 * @internal Shared with downstream libraries; not part of the public contract.
 * @example
 * const options = ownOptions(input);
 * const { algorithm = "SHA-256" } = options;
 */
/* @__NO_SIDE_EFFECTS__ */
export function ownOptions<T extends object>(options: T | undefined | null): T {
  return options === undefined || options === null
    ? (NO_OPTIONS as T)
    : (Object.assign(Object.create(null), options) as T);
}

/**
 * The empty options bag: frozen, `null`-prototyped, safe as a default parameter.
 *
 * @internal Shared with downstream libraries; not part of the public contract.
 * @example
 * function parse(text: string, options: ParseOptions = NO_OPTIONS) {}
 */
export const NO_OPTIONS: Readonly<Record<never, never>> = /* @__PURE__ */ Object.freeze(
  Object.create(null) as Record<never, never>,
);
