import { execFileSync } from "node:child_process";
import { type TestProjectConfiguration, defineConfig } from "vitest/config";

/**
 * V8 keeps the TC39 `Uint8Array` base64/hex methods behind a flag on some
 * builds. Probing by spawning is the only reliable check — the flag is a V8
 * option, so it never appears in `process.allowedNodeEnvironmentFlags` — and
 * an unknown flag makes Node exit before it runs anything.
 */
const NATIVE_FLAG = "--js-base-64";

/**
 * A runtime that already exposes the methods needs no flag: the default
 * project is the native run. Passing the flag anyway would break the day a
 * release ships them unconditionally and drops the option, since an unknown
 * flag makes Node exit before it runs anything.
 */
const NATIVE_METHODS_AVAILABLE =
  typeof (Uint8Array as unknown as { fromBase64?: unknown }).fromBase64 === "function";

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
    projects: [
      { test: { name: "default" } },
      ...(!NATIVE_METHODS_AVAILABLE && nativeFlagAccepted() ? [nativeProject] : []),
    ],
  },
});
