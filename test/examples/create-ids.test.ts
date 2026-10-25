import { describe, expect, it } from "vitest";
import { isUUIDv7, uuidv4, uuidv7Timestamp } from "unsecure/uuid";
import { createInvoice, invoiceIdFrom } from "../../examples/getting-started/create-ids.ts";

describe("examples/getting-started/create-ids", () => {
  it("gives each invoice a v7 id that sorts by creation time", async () => {
    const first = createInvoice("ada@example.com", 4200);
    await new Promise((resolve) => setTimeout(resolve, 2));
    const second = createInvoice("grace@example.com", 1999);

    expect(isUUIDv7(first.id)).toBe(true);
    expect(first.id < second.id).toBe(true);
    expect(uuidv7Timestamp(first.id)).toBeLessThanOrEqual(Date.now());
  });

  it("reads an id from the query string and refuses anything else", () => {
    const { id } = createInvoice("ada@example.com", 4200);
    const base = "https://billing.example.com/invoices";

    expect(invoiceIdFrom(new URL(`${base}?id=${id}`))).toBe(id);
    expect(invoiceIdFrom(new URL(base))).toBeNull();
    expect(invoiceIdFrom(new URL(`${base}?id=${uuidv4()}`))).toBeNull();
    expect(invoiceIdFrom(new URL(`${base}?id=1%20OR%201=1`))).toBeNull();
  });
});
