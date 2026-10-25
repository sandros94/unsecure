import { describe, expect, it, vi } from "vitest";
import { UnsecureError } from "unsecure/errors";
import { readJob, sanitizeBody, updateSettings } from "../../examples/safety/parse-json.ts";

function request(body: string): Request {
  return new Request("https://app.example.com/settings", { method: "PATCH", body });
}

function settingsStore() {
  return { update: vi.fn(async (_userId: string, patch: object) => ({ ...patch })) };
}

function codeOf(run: () => unknown): string | undefined {
  try {
    run();
  } catch (error) {
    if (error instanceof UnsecureError) return error.code;
    throw error;
  }
  return undefined;
}

describe("examples/safety/parse-json", () => {
  it("stores a patch with the pollution keys removed and pollutes nothing", async () => {
    const store = settingsStore();
    const body =
      '{"theme":"dark","__proto__":{"isAdmin":true},"prefs":{"constructor":{"prototype":{"x":1}}}}';
    const response = await updateSettings(request(body), "ada@example.com", store);

    expect(response.status).toBe(200);
    const patch = store.update.mock.calls[0]![1] as Record<string, unknown>;
    expect(Object.getOwnPropertyNames(patch)).toEqual(["theme", "prefs"]);
    expect(Object.getOwnPropertyNames(patch.prefs)).toEqual([]);
    expect(({} as Record<string, unknown>).isAdmin).toBeUndefined();
  });

  it("answers 400 for text that is not JSON", async () => {
    const store = settingsStore();
    const response = await updateSettings(request('{"theme":'), "ada@example.com", store);
    expect(response.status).toBe(400);
    expect(store.update).not.toHaveBeenCalled();
  });

  it("answers 422 for JSON that is not an object", async () => {
    for (const body of ["42", "null", '["dark"]', '"dark"']) {
      const response = await updateSettings(request(body), "ada@example.com", settingsStore());
      expect(response.status).toBe(422);
    }
  });

  it("middleware strips a parsed body in place and calls next", () => {
    const body = JSON.parse('{"name":"Ada","__proto__":{"isAdmin":true}}');
    const req = { body };
    const next = vi.fn();
    sanitizeBody(req, undefined, next);
    expect(req.body).toBe(body);
    expect(Object.getOwnPropertyNames(body)).toEqual(["name"]);
    expect(next).toHaveBeenCalledOnce();
  });

  it("middleware throws FROZEN when the key cannot be removed", () => {
    const body = Object.freeze(JSON.parse('{"__proto__":{"isAdmin":true}}'));
    expect(codeOf(() => sanitizeBody({ body }, undefined, () => {}))).toBe("FROZEN");
  });

  it("copies a job, keeps Dates by reference and leaves the message untouched", () => {
    const runAt = new Date("2026-11-01T09:00:00Z");
    const message = {
      id: "job_01",
      runAt,
      payload: JSON.parse('{"to":"ada@example.com","__proto__":{"isAdmin":true}}'),
    };
    const job = readJob(message);
    expect(job).not.toBe(message);
    expect(job.runAt).toBe(runAt);
    expect(Object.getOwnPropertyNames(job.payload)).toEqual(["to"]);
    expect(Object.getOwnPropertyNames(message.payload)).toEqual(["to", "__proto__"]);
  });

  it("refuses anything the allowlist does not name", () => {
    expect(codeOf(() => readJob({ id: "job_02", tags: new Set(["urgent"]) }))).toBe("INVALID_TYPE");
  });

  it("rebuilds plain objects from another realm, but its Date is not this realm's", async () => {
    const vm = await import("node:vm");
    const context = vm.createContext({});
    const foreign = vm.runInContext(
      `JSON.parse('{"id":"job_03","payload":{"__proto__":{"isAdmin":true}}}')`,
      context,
    );
    const job = readJob(foreign);
    expect(Object.getPrototypeOf(job)).toBe(Object.prototype);
    expect(Object.getOwnPropertyNames(job.payload)).toEqual([]);

    const runAt = vm.runInContext("new Date(0)", context);
    expect(codeOf(() => readJob({ id: "job_04", runAt }))).toBe("INVALID_TYPE");
  });
});
