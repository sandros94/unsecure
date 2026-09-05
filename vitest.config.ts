import { execFileSync } from "node:child_process";
import { type TestProjectConfiguration, defineConfig } from "vitest/config";

/**
 * V8 keeps the TC39 `Uint8Array` base64/hex methods behind a flag on some
 * builds. Probing by spawning is the only reliable check — the flag is a V8
 * option, so it never appears in `process.allowedNodeEnvironmentFlags` — and
 * an unknown flag makes Node exit before it runs anything.
 */
const NATIVE_FLAG = "--js-base-64";

function nativeFlagAccepted(): boolean {
  try {
    execFileSync(process.execPath, [NATIVE_FLAG, "-e", "0"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/**
 * The codec suite runs a second time with those methods enabled: which
 * backend decodes must never be observable, and only a run where a different
 * backend is available can prove it.
 */
const nativeProject: TestProjectConfiguration = {
  test: {
    name: "native-base64",
    pool: "forks",
    execArgv: [NATIVE_FLAG],
    include: ["test/codec*.test.ts", "test/utils.test.ts"],
    // Benchmarks measure strategies, not backends; running them twice buys
    // nothing but minutes.
    benchmark: { include: [] },
  },
};

export default defineConfig({
  test: {
    slowTestThreshold: 1000,
    projects: [{ test: { name: "default" } }, ...(nativeFlagAccepted() ? [nativeProject] : [])],
  },
});
