import { createUUIDv7Generator, isUUIDv7, uuidv4, uuidv7Timestamp } from "unsecure/uuid";

// #region docs
/** One generator per process: its ids sort in the order they were made. */
const orderIds = createUUIDv7Generator();

export function newOrderId(): string {
  return orderIds.next();
}

/** User ids appear in profile URLs; a v4 keeps the sign-up time out of them. */
export function newUserId(): string {
  return uuidv4();
}

/** When an order was created, read from its id; `null` for anything not a v7. */
export function orderCreatedAt(id: unknown): Date | null {
  return isUUIDv7(id) ? new Date(uuidv7Timestamp(id)) : null;
}
// #endregion
