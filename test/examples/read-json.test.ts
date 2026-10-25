import { describe, expect, it } from "vitest";
import { createComment } from "../../examples/getting-started/read-json.ts";

function post(body: string): Request {
  return new Request("https://api.example.com/posts/1347/comments", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
}

describe("examples/getting-started/read-json", () => {
  it("parses a comment and strips prototype-pollution keys", async () => {
    const response = await createComment(
      post('{"author":"ada@example.com","text":"Ship it.","__proto__":{"isAdmin":true}}'),
    );

    expect(response.status).toBe(201);
    const comment = await response.json();
    expect(comment).toEqual({ author: "ada@example.com", text: "Ship it." });
    expect(Object.hasOwn(comment, "__proto__")).toBe(false);
    expect(({} as { isAdmin?: boolean }).isAdmin).toBeUndefined();
  });

  it("answers 400 for a body that is not JSON", async () => {
    const response = await createComment(post('{"author":"ada@example.com",'));

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: "The body is not valid JSON." });
  });
});
