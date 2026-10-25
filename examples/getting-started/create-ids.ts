// #region docs
import { isUUIDv7, uuidv7 } from "unsecure/uuid";

interface Invoice {
  id: string;
  customer: string;
  total: number;
}

export function createInvoice(customer: string, total: number): Invoice {
  return { id: uuidv7(), customer, total };
}

/** The id from `/invoices?id=…`, or `null` when it is missing or malformed. */
export function invoiceIdFrom(url: URL): string | null {
  const id = url.searchParams.get("id");
  return isUUIDv7(id) ? id : null;
}
// #endregion
