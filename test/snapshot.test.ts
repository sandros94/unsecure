// A real Node startup snapshot, built and restored by a child process: the
// only way to see what the blob carries. Node-only by nature, and the bundler
// is what turns `src` into the one plain script `--build-snapshot` takes.
/// <reference types="node" />
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";
import { rolldown } from "rolldown";

const SRC = fileURLToPath(new URL("../src/", import.meta.url));
const dir = mkdtempSync(path.join(tmpdir(), "unsecure-snapshot-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

async function bundle(): Promise<string> {
  const entry = "\0snapshot-entry";
  const build = await rolldown({
    input: entry,
    platform: "node",
    treeshake: true,
    logLevel: "silent",
    plugins: [
      {
        name: "virtual-entry",
        resolveId: (id) => (id === entry ? id : null),
        load: (id) =>
          id === entry
            ? `export { uuidv4 } from ${JSON.stringify(path.join(SRC, "uuid.ts"))};
export { createSecureRandomGenerator, secureRandomBytes, secureRandomNumber } from ${JSON.stringify(path.join(SRC, "random.ts"))};`
            : null,
      },
    ],
  });
  try {
    const { output } = await build.generate({ format: "iife", name: "U", minify: true });
    return output.map((chunk) => (chunk.type === "chunk" ? chunk.code : "")).join("");
  } finally {
    await build.close();
  }
}

/** Build a blob from `script`, restore it twice, and return the two JSON outputs. */
function restoredTwice(script: string, name: string): [unknown, unknown] {
  const file = path.join(dir, `${name}.js`);
  const blob = path.join(dir, `${name}.blob`);
  writeFileSync(file, script);
  const env = { PATH: process.env.PATH, HOME: dir };
  execFileSync(process.execPath, ["--snapshot-blob", blob, "--build-snapshot", file], {
    env,
    cwd: dir,
  });
  const run = () =>
    JSON.parse(
      execFileSync(process.execPath, ["--snapshot-blob", blob], {
        env,
        cwd: dir,
        encoding: "utf8",
      }),
    ) as unknown;
  return [run(), run()];
}

describe("startup snapshot", () => {
  it("serves no pool byte captured while building, whatever registered a restore callback first", async () => {
    const lib = await bundle();
    const script = `
const v8 = require("node:v8");
const out = {};
// A consumer callback queued BEFORE the library is evaluated runs before any
// reset the library could register.
v8.startupSnapshot.addDeserializeCallback(() => {
  out.early = [U.uuidv4(), Buffer.from(U.secureRandomBytes(16)).toString("hex"), U.secureRandomNumber(2 ** 32), early.next(2 ** 32)];
});
${lib}
// Draw during the build so the pool, if it buffered, would hold bytes.
U.uuidv4(); U.secureRandomBytes(16); U.secureRandomNumber(1000);
const early = U.createSecureRandomGenerator(); early.next(10);
v8.startupSnapshot.setDeserializeMainFunction(() => {
  out.main = [U.uuidv4(), U.secureRandomNumber(2 ** 32)];
  console.log(JSON.stringify(out));
});
`;
    const [a, b] = restoredTwice(script, "order") as [
      Record<string, unknown[]>,
      Record<string, unknown[]>,
    ];
    expect(a.early).toHaveLength(4);
    for (let i = 0; i < 4; i++) expect(a.early![i]).not.toBe(b.early![i]);
    expect(a.main![0]).not.toBe(b.main![0]);
    expect(a.main![1]).not.toBe(b.main![1]);
  }, 60_000);
});
