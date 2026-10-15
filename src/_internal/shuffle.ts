/**
 * One Fisher-Yates step: a uniformly chosen element of `array[start, end)` is
 * swapped into `array[start]` and returned. Run for every `start` it shuffles
 * the whole array; run once per call it draws one card and leaves the rest
 * undrawn, which is what a deck needs.
 */
export function _drawInPlace<T>(
  array: T[],
  start: number,
  end: number,
  next: (max: number) => number,
): T {
  const j = start + next(end - start);
  const value = array[j]!;
  array[j] = array[start]!;
  array[start] = value;
  return value;
}
