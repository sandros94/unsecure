// The bundler's JS API is a build-time tool, so this one test file reaches for
// Node's path helpers; nothing in `src` may. The reference is file-local, so
// the rest of the project still typechecks without Node's globals.
/// <reference types="node" />
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { rolldown } from "rolldown";

/**
 * The README promises that importing one function ships one function: no
 * codec a caller did not ask for, no shared random buffer behind a call that
 * fills its own bytes. `sideEffects: false` and the `@__PURE__` annotations
 * are what make that true, and nothing but a bundler can tell whether they
 * still do — a stray top-level call or an import moved to the wrong module
 * breaks it silently and only shows up in someone's shipped bytes.
 *
 * Each row bundles a single named import from `src` — not from `dist`, so the
 * test needs no prior build — minifies it, and asserts two things: the byte
 * size is at or under its ceiling, and the markers listed with it are absent.
 *
 * The ceiling is the size measured when the row was written, plus 15%, rounded
 * up to the next 100 bytes; the measurement is in the comment beside it. A
 * deliberate change that grows a bundle is a one-line diff: re-measure, and
 * update both the ceiling and the comment in the same edit.
 */

const SRC = fileURLToPath(new URL("../src/", import.meta.url));

/** Rolldown is fast, but a cold CI worker resolving a native binding is not. */
const TIMEOUT = 60_000;

/**
 * Strings that survive minification, so they can be asserted absent: an
 * alphabet the codec is built around, or a property name read off a global.
 * Mangled local identifiers cannot be used for this — these can.
 */
const MARKERS = {
  base32: "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
  base32Crockford: "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
  base64: "abcdefghijklmnopqrstuvwxyz0123456789",
  base64Decode: "fromBase64",
  base64Encode: "toBase64",
  hexDecode: "fromHex",
  hexEncode: "toHex",
  /** The shared generator's batching buffer, `new Uint32Array(256)`. */
  randomBuffer: "Uint32Array",
  randomBytes: "getRandomValues",
  digest: "digest",
  importKey: "importKey",
  deriveBits: "deriveBits",
  hkdf: "HKDF",
  errorClass: "UnsecureError",
} as const;

const CODECS = [
  MARKERS.base32,
  MARKERS.base32Crockford,
  MARKERS.base64,
  MARKERS.base64Decode,
  MARKERS.base64Encode,
  MARKERS.hexDecode,
  MARKERS.hexEncode,
];

const BASE32 = [MARKERS.base32, MARKERS.base32Crockford];
const BASE64 = [MARKERS.base64, MARKERS.base64Decode, MARKERS.base64Encode];
const HEX = [MARKERS.hexDecode, MARKERS.hexEncode];

interface Entry {
  /** The single name imported from the module. */
  name: string;
  /** The module, relative to `src`. */
  module: string;
  /** Minified bytes this import may not exceed. */
  ceiling: number;
  /** Strings that must not appear in the bundle. */
  absent: ReadonlyArray<string>;
}

const ENTRIES: ReadonlyArray<Entry> = [
  // measured 949
  {
    name: "secureCompare",
    module: "compare.ts",
    ceiling: 1100,
    absent: [...CODECS, MARKERS.randomBuffer, MARKERS.randomBytes, MARKERS.importKey],
  },
  // measured 1009 — the only public function that throws nothing
  {
    name: "entropy",
    module: "entropy.ts",
    ceiling: 1200,
    absent: [...CODECS, MARKERS.errorClass, MARKERS.randomBytes],
  },
  // measured 3087
  {
    name: "secureGenerate",
    module: "generate.ts",
    ceiling: 3600,
    absent: [...CODECS, MARKERS.importKey],
  },
  // measured 6767 — hex and base64 come with `returnAs`, base32 does not
  {
    name: "hash",
    module: "hash.ts",
    ceiling: 7800,
    absent: [...BASE32, MARKERS.randomBuffer, MARKERS.randomBytes, MARKERS.importKey],
  },
  // measured 7753
  {
    name: "hkdf",
    module: "hkdf.ts",
    ceiling: 9000,
    absent: [...BASE32, MARKERS.randomBuffer, MARKERS.randomBytes, MARKERS.digest],
  },
  // measured 7669
  {
    name: "hmac",
    module: "hmac.ts",
    ceiling: 8900,
    absent: [
      ...BASE32,
      MARKERS.randomBuffer,
      MARKERS.randomBytes,
      MARKERS.digest,
      MARKERS.deriveBits,
      MARKERS.hkdf,
    ],
  },
  // measured 10243 — base32 is here because OTP secrets are base32 text
  {
    name: "hotp",
    module: "otp.ts",
    ceiling: 11800,
    absent: [MARKERS.randomBuffer, MARKERS.randomBytes, MARKERS.deriveBits, MARKERS.hkdf],
  },
  // measured 730 — fills its own bytes, so the shared generator stays behind
  {
    name: "secureRandomBytes",
    module: "random.ts",
    ceiling: 900,
    absent: [...CODECS, MARKERS.randomBuffer, MARKERS.importKey],
  },
  // measured 919
  {
    name: "sanitizeObject",
    module: "sanitize.ts",
    ceiling: 1100,
    absent: [...CODECS, MARKERS.randomBytes, MARKERS.importKey],
  },
  // measured 3545 — hex only: a UUID is printed as hex
  {
    name: "uuidv7",
    module: "uuid.ts",
    ceiling: 4100,
    absent: [...BASE32, ...BASE64, MARKERS.randomBuffer, MARKERS.importKey],
  },
  // measured 1910
  {
    name: "hexParse",
    module: "utils/index.ts",
    ceiling: 2200,
    absent: [...BASE32, ...BASE64, MARKERS.randomBytes],
  },
  // measured 3053 — parse only, so even the encoder half stays behind
  {
    name: "base64Parse",
    module: "utils/index.ts",
    ceiling: 3600,
    absent: [...BASE32, ...HEX, MARKERS.base64Encode, MARKERS.randomBytes],
  },
  // measured 3552
  {
    name: "base32Parse",
    module: "utils/index.ts",
    ceiling: 4100,
    absent: [...BASE64, ...HEX, MARKERS.randomBytes],
  },
  // measured 108 — the error class on its own is a constructor and a field
  {
    name: "UnsecureError",
    module: "errors.ts",
    ceiling: 200,
    absent: [...CODECS, MARKERS.randomBytes, MARKERS.importKey],
  },
];

/** The id of the generated entry, `\0`-prefixed so nothing tries to read it. */
const VIRTUAL_ENTRY = "\0unsecure-bundle-entry";

/**
 * Bundle one named import and return the minified code. `console.log` is what
 * keeps the import alive: an unused one is exactly what tree-shaking removes,
 * which would measure nothing.
 */
async function bundleImport(entry: Entry): Promise<string> {
  const source = `import { ${entry.name} } from ${JSON.stringify(path.join(SRC, entry.module))};
console.log(${entry.name});
`;
  const build = await rolldown({
    input: VIRTUAL_ENTRY,
    platform: "neutral",
    treeshake: true,
    logLevel: "silent",
    plugins: [
      {
        name: "virtual-entry",
        resolveId: (id) => (id === VIRTUAL_ENTRY ? id : null),
        load: (id) => (id === VIRTUAL_ENTRY ? source : null),
      },
    ],
  });
  try {
    const { output } = await build.generate({ format: "esm", minify: true });
    return output
      .filter((chunk) => chunk.type === "chunk")
      .map((chunk) => chunk.code)
      .join("");
  } finally {
    await build.close();
  }
}

describe("tree-shaking", () => {
  for (const entry of ENTRIES) {
    it(
      `ships ${entry.name} in at most ${entry.ceiling} bytes, and nothing else`,
      async () => {
        const code = await bundleImport(entry);
        const size = new TextEncoder().encode(code).length;
        expect(
          size,
          `${entry.name} bundles to ${size} bytes; re-measure and update the row if the growth is deliberate`,
        ).toBeLessThanOrEqual(entry.ceiling);
        for (const marker of entry.absent) {
          expect(code, `${entry.name} bundle must not contain ${marker}`).not.toContain(marker);
        }
      },
      TIMEOUT,
    );
  }
});
