import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { acceptEnabled, bidsForViewer } from "./bid-desk.ts";

const SELLER = "seller";
const BIDDER = "bidder";

describe("private bids", () => {
  it("shows amounts only to the seller", () => {
    const bids = [{ bidder: BIDDER, amount: 5n }];
    assert.equal(bidsForViewer(SELLER, SELLER, bids)[0]?.amount, 5n);
    assert.equal(bidsForViewer(BIDDER, SELLER, bids)[0]?.amount, null);
    assert.equal(bidsForViewer("", SELLER, bids)[0]?.bidder, BIDDER);
  });

  it("accepts early only at the reserve, and any bid after the deadline", () => {
    assert.equal(acceptEnabled({ now: 10, deadline: 20, amount: 4n, reserve: 5n }), false);
    assert.equal(acceptEnabled({ now: 10, deadline: 20, amount: 5n, reserve: 5n }), true);
    assert.equal(acceptEnabled({ now: 20, deadline: 20, amount: 1n, reserve: 9n }), true);
  });
});
