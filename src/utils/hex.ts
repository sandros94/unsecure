import { textEncoder, textDecoder } from "./";

/* Hex encoding function */
export function hexEncode(data: Uint8Array | string): string {
  const encodedData =
    data instanceof Uint8Array ? data : textEncoder.encode(data);

  // @ts-expect-error check if toHex is available
  if (Uint8Array.prototype.toHex) {
    // @ts-expect-error
    return encodedData.toHex();
  }

  return Array.prototype.map
    .call(encodedData, (x: number) => ("00" + x.toString(16)).slice(-2))
    .join("");
}

/* Hex decoding function */
export function hexDecode(str: string | undefined): string;
export function hexDecode<T extends boolean | undefined>(
  str?: string | undefined,
  toString?: T,
): T extends false ? Uint8Array : string;
export function hexDecode(
  str?: string | undefined,
  toString?: boolean | undefined,
): Uint8Array | string {
  const decodeToString = toString !== false;

  if (!str) {
    return decodeToString ? "" : new Uint8Array(0);
  }

  // @ts-expect-error check if fromHex is available
  const data: Uint8Array = Uint8Array.fromHex
    ? // @ts-expect-error
      Uint8Array.fromHex(str)
    : fromHexString(str);

  return decodeToString ? textDecoder.decode(data) : data;
}

function fromHexString(hexString: string) {
  const match = hexString.match(/.{1,2}/g);
  if (!match) return new Uint8Array(0);

  return Uint8Array.from(match.map((byte) => Number.parseInt(byte, 16)));
}
