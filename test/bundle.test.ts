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
 * codec a caller did not ask for, no entropy pool behind a function that never
 * draws. `sideEffects: false` and the `@__PURE__` annotations
 * are what make that true, and nothing but a bundler can tell whether they
 * still do — a stray top-level call or an import moved to the wrong module
 * breaks it silently and only shows up in someone's shipped bytes.
 *
 * Each row bundles a single named import from `src` — not from `dist`, so the
 * test needs no prior build — minifies it, and asserts two things: the byte
 * size is within `TOLERANCE` of the row's `measured` value, and the markers
 * listed with it are absent.
 *
 * `measured` is the size when the row was last measured, and the bound is
 * two-sided: growth means something was pulled in, a drastic shrink means a
 * check or branch was shaken out. A deliberate change in either direction is a
 * one-line diff: re-measure and update `measured`. A change you cannot explain
 * is the test doing its job.
 */

const SRC = fileURLToPath(new URL("../src/", import.meta.url));

/** Relative slack around `measured`, in both directions. */
const TOLERANCE = 0.15;

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
  /** Minified bytes when the row was last measured; the test allows `TOLERANCE` either way. */
  measured: number;
  /** Strings that must not appear in the bundle. */
  absent: ReadonlyArray<string>;
}

const ENTRIES: ReadonlyArray<Entry> = [
  {
    name: "secureCompare",
    module: "compare.ts",
    measured: 1358,
    absent: [...CODECS, MARKERS.randomBuffer, MARKERS.randomBytes, MARKERS.importKey],
  },
  // fairness, not secrecy: the shared generator and its pool come along by design
  {
    name: "createDeck",
    module: "odds.ts",
    measured: 4875,
    absent: [...CODECS, MARKERS.importKey, MARKERS.digest],
  },
  // tiers bring their own chances, so no randomness of its own
  {
    name: "createCascade",
    module: "odds.ts",
    measured: 1342,
    absent: [...CODECS, MARKERS.randomBuffer, MARKERS.randomBytes, MARKERS.importKey],
  },
  // the only public function that throws nothing
  {
    name: "entropy",
    module: "entropy.ts",
    measured: 1554,
    absent: [...CODECS, MARKERS.randomBytes],
  },
  {
    name: "secureGenerate",
    module: "generate.ts",
    measured: 5004,
    absent: [...CODECS, MARKERS.importKey],
  },
  // hex and base64 come with `returnAs`, base32 does not
  {
    name: "hash",
    module: "hash.ts",
    measured: 4296,
    absent: [...BASE32, MARKERS.randomBuffer, MARKERS.randomBytes, MARKERS.importKey],
  },
  {
    name: "hkdf",
    module: "hkdf.ts",
    measured: 5534,
    absent: [...BASE32, MARKERS.randomBuffer, MARKERS.randomBytes, MARKERS.digest],
  },
  {
    name: "hmac",
    module: "hmac.ts",
    measured: 5585,
    absent: [
      ...BASE32,
      MARKERS.randomBuffer,
      MARKERS.randomBytes,
      MARKERS.digest,
      MARKERS.deriveBits,
      MARKERS.hkdf,
    ],
  },
  // base32 is here because OTP secrets are base32 text; the MAC is signed
  // directly, so the encodings behind `hmac()`'s `returnAs` stay out
  {
    name: "hotp",
    module: "otp.ts",
    measured: 7746,
    absent: [
      ...BASE64,
      ...HEX,
      MARKERS.randomBuffer,
      MARKERS.randomBytes,
      MARKERS.deriveBits,
      MARKERS.hkdf,
    ],
  },
  // a URI builder: base32 for the secret, no HMAC, no randomness
  {
    name: "otpauthURI",
    module: "otp.ts",
    measured: 7361,
    absent: [
      ...BASE64,
      ...HEX,
      MARKERS.randomBuffer,
      MARKERS.randomBytes,
      MARKERS.importKey,
      MARKERS.digest,
    ],
  },
  // the PHC fields are base64; the pool is behind the salt, and `digest` is BLAKE2b's own method
  {
    name: "argon2Verify",
    module: "argon2.ts",
    measured: 13916,
    absent: [...BASE32, ...HEX, MARKERS.importKey, MARKERS.deriveBits, MARKERS.hkdf],
  },
  // draws from the shared pool; the sampling generator over it stays behind
  {
    name: "secureRandomBytes",
    module: "random.ts",
    measured: 1913,
    absent: [...CODECS, MARKERS.importKey],
  },
  {
    name: "sanitizeObject",
    module: "sanitize.ts",
    measured: 761,
    absent: [...CODECS, MARKERS.randomBytes, MARKERS.importKey],
  },
  // no codec at all: a UUID is printed from its own hex table; the entropy pool comes along by design
  {
    name: "uuidv7",
    module: "uuid.ts",
    measured: 2721,
    absent: [...CODECS, MARKERS.importKey],
  },
  {
    name: "hexParse",
    module: "utils/index.ts",
    measured: 2932,
    absent: [...BASE32, ...BASE64, MARKERS.randomBytes],
  },
  // parse only, so even the encoder half stays behind
  {
    name: "base64Parse",
    module: "utils/index.ts",
    measured: 4348,
    absent: [...BASE32, ...HEX, MARKERS.base64Encode, MARKERS.randomBytes],
  },
  {
    name: "base32Parse",
    module: "utils/index.ts",
    measured: 4985,
    absent: [...BASE64, ...HEX, MARKERS.randomBytes],
  },
  // the error class on its own is a constructor and a field
  {
    name: "UnsecureError",
    module: "errors.ts",
    measured: 108,
    absent: [...CODECS, MARKERS.randomBytes, MARKERS.importKey],
  },
];

interface UnusedCall {
  /** The single name imported from the module. */
  name: string;
  /** The module, relative to `src`. */
  module: string;
  /** A call whose result is discarded. */
  call: string;
  /** Minified bytes that may survive once the call is dropped. */
  ceiling: number;
}

/**
 * A call whose result nobody reads must take its work with it. That is what
 * `@__NO_SIDE_EFFECTS__` promises on every value-returning function, and a
 * missing annotation shows up here as a whole module surviving.
 */
const UNUSED_CALLS: ReadonlyArray<UnusedCall> = [
  { name: "secureCompare", module: "compare.ts", call: 'secureCompare("a", "b")', ceiling: 0 },
  { name: "createDeck", module: "odds.ts", call: 'createDeck(["a"])', ceiling: 0 },
  { name: "hexParse", module: "utils/index.ts", call: 'hexParse("ab")', ceiling: 0 },
  { name: "sanitizeObjectCopy", module: "sanitize.ts", call: "sanitizeObjectCopy({})", ceiling: 0 },
  { name: "uuidv7", module: "uuid.ts", call: "uuidv7()", ceiling: 0 },
  { name: "hash", module: "hash.ts", call: 'hash("x")', ceiling: 0 },
  { name: "hotp", module: "otp.ts", call: 'hotp("JBSWY3DP", 0)', ceiling: 0 },
];

/** The id of the generated entry, `\0`-prefixed so nothing tries to read it. */
const VIRTUAL_ENTRY = "\0unsecure-bundle-entry";

/**
 * Bundle one named import and return the minified code. `console.log` is what
 * keeps the import alive: an unused one is exactly what tree-shaking removes,
 * which would measure nothing.
 */
async function bundleImport(entry: Entry): Promise<string> {
  return bundleSource(`import { ${entry.name} } from ${JSON.stringify(path.join(SRC, entry.module))};
console.log(${entry.name});
`);
}

/** Bundle an entry module given as source text and return the minified code. */
async function bundleSource(source: string): Promise<string> {
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
      `ships ${entry.name} within ${TOLERANCE * 100}% of ${entry.measured} bytes, and nothing else`,
      async () => {
        const code = await bundleImport(entry);
        const size = new TextEncoder().encode(code).length;
        expect(
          size,
          `${entry.name} bundles to ${size} bytes, over ${entry.measured}; re-measure and update the row if the growth is deliberate`,
        ).toBeLessThanOrEqual(Math.ceil(entry.measured * (1 + TOLERANCE)));
        expect(
          size,
          `${entry.name} bundles to ${size} bytes, under ${entry.measured}; a check or branch may have been shaken out — re-measure and update the row if the shrink is deliberate`,
        ).toBeGreaterThanOrEqual(Math.floor(entry.measured * (1 - TOLERANCE)));
        for (const marker of entry.absent) {
          expect(code, `${entry.name} bundle must not contain ${marker}`).not.toContain(marker);
        }
      },
      TIMEOUT,
    );
  }
});

describe("unused-call elimination", () => {
  for (const entry of UNUSED_CALLS) {
    it(
      `drops ${entry.call} entirely when its result is unused`,
      async () => {
        const code = await bundleSource(
          `import { ${entry.name} } from ${JSON.stringify(path.join(SRC, entry.module))};\n${entry.call};\n`,
        );
        const size = new TextEncoder().encode(code).length;
        expect(
          size,
          `${entry.call} leaves ${size} bytes behind; a value-returning function on its path is missing @__NO_SIDE_EFFECTS__`,
        ).toBeLessThanOrEqual(entry.ceiling);
      },
      TIMEOUT,
    );
  }
});

/**
 * The published layout is what a CDN consumer pays for: a subpath entry plus
 * every chunk it imports, whole. Chunks group modules by which entries reach
 * them, so the invariant is per entry: it must reach no codec it does not use.
 */
describe("chunk layout", () => {
  const BASE32_MARKER = [MARKERS.base32];
  const BASE64_MARKER = [MARKERS.base64Decode];
  const HEX_MARKER = [MARKERS.hexDecode];
  const DIGEST = [...BASE64_MARKER, ...HEX_MARKER];

  /** Every entry of `build.config.ts`, with the codecs it is allowed to reach. */
  const ENTRIES: ReadonlyArray<readonly [entry: string, allowed: ReadonlyArray<string>]> = [
    ["index", [...BASE32_MARKER, ...DIGEST]],
    ["argon2", DIGEST],
    ["compare", []],
    ["odds", []],
    ["entropy", []],
    ["errors", []],
    ["generate", []],
    ["hash", DIGEST],
    ["hkdf", DIGEST],
    ["hmac", DIGEST],
    ["otp", BASE32_MARKER],
    ["random", []],
    ["sanitize", []],
    ["uuid", []],
    ["utils/index", [...BASE32_MARKER, ...DIGEST]],
  ];
  const CODEC_MARKERS = [...BASE32_MARKER, ...DIGEST];

  it(
    "lets every entry reach only the codecs it uses",
    async () => {
      const build = await rolldown({
        input: Object.fromEntries(ENTRIES.map(([name]) => [name, path.join(SRC, `${name}.ts`)])),
        platform: "neutral",
        treeshake: true,
        logLevel: "silent",
      });
      try {
        const { output } = await build.generate({
          format: "esm",
          minify: true,
          entryFileNames: "[name].mjs",
          chunkFileNames: "_chunks/[name].mjs",
        });
        const chunks = output.filter((chunk) => chunk.type === "chunk");
        const codeOf = (fileName: string): string =>
          chunks.find((chunk) => chunk.fileName === fileName)!.code;
        for (const [entry, allowed] of ENTRIES) {
          const reached = new Set<string>();
          const queue = [`${entry}.mjs`];
          for (let next = queue.shift(); next !== undefined; next = queue.shift()) {
            if (reached.has(next)) continue;
            reached.add(next);
            queue.push(...chunks.find((chunk) => chunk.fileName === next)!.imports);
          }
          for (const name of reached) {
            for (const marker of CODEC_MARKERS) {
              if (allowed.includes(marker)) continue;
              expect(codeOf(name), `${entry} reaches ${name}, which holds ${marker}`).not.toContain(
                marker,
              );
            }
          }
        }
      } finally {
        await build.close();
      }
    },
    TIMEOUT,
  );
});
