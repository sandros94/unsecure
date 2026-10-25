/**
 * An options bag as the caller wrote it: its own properties on a `null`
 * prototype. An ordinary `{}` inherits from `Object.prototype`, so a key the
 * caller left out reads through the prototype chain — a property a polluted
 * prototype carries would silently become a setting. Every public function
 * resolves its bag through here first; internal callers pass {@link NONE} or a
 * constant built the same way.
 */
/* @__NO_SIDE_EFFECTS__ */
export function own<T extends object>(options: T | undefined | null): T {
  return options === undefined || options === null
    ? (NONE as T)
    : (Object.assign(Object.create(null), options) as T);
}

/** The empty bag: a frozen `null`-prototype object every default parameter can share. */
export const NONE: Readonly<Record<never, never>> = /* @__PURE__ */ Object.freeze(
  Object.create(null) as Record<never, never>,
);
