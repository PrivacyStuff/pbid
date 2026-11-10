export type ShieldedBid = {
  readonly bidder: string;
  readonly amount: bigint;
};

export type VisibleBid = {
  readonly bidder: string;
  readonly amount: bigint | null;
};

/** Amounts stay on the seller's client. Everyone else sees that a bid exists. */
export function bidsForViewer(viewer: string, seller: string, bids: readonly ShieldedBid[]): readonly VisibleBid[] {
  const show = viewer.length > 0 && viewer === seller;
  return bids.map((bid) => ({ bidder: bid.bidder, amount: show ? bid.amount : null }));
}

/**
 * Early accept needs the bid to clear the reserve the seller still holds.
 * After the public deadline any locked bid can be accepted.
 */
export function acceptEnabled(input: {
  readonly now: number;
  readonly deadline: number;
  readonly amount: bigint;
  readonly reserve: bigint;
}): boolean {
  if (input.now >= input.deadline) return true;
  if (input.amount < 0n || input.reserve < 0n) return false;
  return input.amount >= input.reserve;
}
