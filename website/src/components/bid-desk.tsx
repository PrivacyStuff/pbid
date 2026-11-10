"use client";

import { useEffect, useState } from "react";
import { acceptEnabled, bidsForViewer, type ShieldedBid } from "@/lib/bid-desk";

const FIELD = "mt-2 w-full border border-line bg-transparent px-3 py-2";
const MIN_ACCOUNT_LENGTH = 32;
const MAX_ACCOUNT_LENGTH = 44;
const MAX_AMOUNT_DIGITS = 20;
const MAX_DEADLINE_UNIX = 4_102_444_800;
const BASE58_ACCOUNT = new RegExp(`^[1-9A-HJ-NP-Za-km-z]{${MIN_ACCOUNT_LENGTH},${MAX_ACCOUNT_LENGTH}}$`);
const DECIMAL_AMOUNT = new RegExp(`^\\d{1,${MAX_AMOUNT_DIGITS}}$`);
const SELLER = "this-browser";

type ListingDraft = {
  readonly asset: string;
  readonly reserve: bigint;
  readonly deadline: number;
};

export function BidDesk() {
  const [now, setNow] = useState<number | null>(null);
  const [asset, setAsset] = useState("");
  const [reserveText, setReserveText] = useState("");
  const [deadlineText, setDeadlineText] = useState("");
  const [bidder, setBidder] = useState("");
  const [amountText, setAmountText] = useState("");
  const [listing, setListing] = useState<ListingDraft | null>(null);
  const [bids, setBids] = useState<readonly ShieldedBid[]>([]);
  const [notice, setNotice] = useState<string | null>(null);
  const [preview, setPreview] = useState(false);

  useEffect(() => {
    // The clock is local. Filling this during render disagrees with the server HTML.
    // eslint-disable-next-line react-hooks/set-state-in-effect -- local clock after mount
    setNow(Math.floor(Date.now() / 1000));
  }, []);

  const viewer = preview ? "someone-else" : SELLER;
  const visible = bidsForViewer(viewer, SELLER, bids);

  function list(): void {
    const reserve = parseBase(reserveText);
    const deadline = Number(deadlineText);
    if (
      now === null ||
      !BASE58_ACCOUNT.test(asset.trim()) ||
      reserve === null ||
      !Number.isSafeInteger(deadline) ||
      deadline <= now ||
      deadline > MAX_DEADLINE_UNIX
    ) {
      setNotice("The NFT, the reserve, and a deadline after now are required.");
      return;
    }
    setListing({ asset: asset.trim(), reserve, deadline });
    setBids([]);
    setNotice(null);
  }

  function recordBid(): void {
    if (listing === null) return;
    const amount = parseBase(amountText);
    if (!BASE58_ACCOUNT.test(bidder.trim()) || amount === null) {
      setNotice("A bid needs a wallet and an amount you decrypted.");
      return;
    }
    setBids((current) => [...current, { bidder: bidder.trim(), amount }]);
    setAmountText("");
    setNotice(null);
  }

  return (
    <section className="mt-6">
      <p className="text-sm tracking-[0.18em] text-stamp uppercase">pbid</p>
      <h1 className="mt-4 font-serif text-5xl tracking-[-0.035em]">List the NFT. Keep the bids quiet.</h1>
      <p className="mt-3 max-w-2xl text-sm leading-6 text-muted">
        The NFT, the seller, and the deadline are public. The reserve stays in this browser. Bid amounts are shown only to the seller. This page does not submit a transaction. The listing program is separate from pescrow and is not deployed from here.
      </p>
      <label className="mt-6 block text-sm">
        Public NFT
        <input className={FIELD} value={asset} onChange={(event) => setAsset(event.target.value)} autoComplete="off" spellCheck={false} />
      </label>
      <label className="mt-4 block text-sm">
        Hidden reserve
        <input className={FIELD} value={reserveText} onChange={(event) => setReserveText(event.target.value)} inputMode="numeric" autoComplete="off" />
      </label>
      <label className="mt-4 block text-sm">
        Deadline (unix seconds)
        <input className={FIELD} value={deadlineText} onChange={(event) => setDeadlineText(event.target.value)} inputMode="numeric" autoComplete="off" />
      </label>
      <button type="button" className="mt-4 border border-foreground px-3 py-2 text-sm" onClick={list}>
        List NFT
      </button>
      {listing === null ? null : (
        <div className="mt-8">
          <p className="text-sm break-all">Public NFT {listing.asset}</p>
          <p className="mt-2 text-sm">Deadline {listing.deadline}. The reserve is not on the account.</p>
          <label className="mt-4 flex items-center gap-2 text-sm">
            <input type="checkbox" checked={preview} onChange={(event) => setPreview(event.target.checked)} />
            Preview as someone else
          </label>
          <label className="mt-6 block text-sm">
            Bidder
            <input className={FIELD} value={bidder} onChange={(event) => setBidder(event.target.value)} autoComplete="off" spellCheck={false} />
          </label>
          <label className="mt-4 block text-sm">
            Decrypted amount
            <input className={FIELD} value={amountText} onChange={(event) => setAmountText(event.target.value)} inputMode="numeric" autoComplete="off" />
          </label>
          <button type="button" className="mt-4 border border-foreground px-3 py-2 text-sm" onClick={recordBid}>
            Record decrypted bid
          </button>
          <ul className="mt-6 space-y-4">
            {visible.map((bid, index) => {
              const stored = bids[index];
              const sellerView = viewer === SELLER;
              const enabled =
                sellerView &&
                now !== null &&
                stored !== undefined &&
                acceptEnabled({
                  now,
                  deadline: listing.deadline,
                  amount: stored.amount,
                  reserve: listing.reserve,
                });
              return (
                <li key={`${bid.bidder}-${index}`} className="border border-line p-4">
                  <p className="text-sm break-all">{bid.bidder}</p>
                  <p className="mt-2 text-sm">{bid.amount === null ? "Amount hidden" : `Amount ${bid.amount.toString()}`}</p>
                  <button
                    type="button"
                    className="mt-3 border border-foreground px-3 py-2 text-sm disabled:border-line disabled:text-muted"
                    disabled={!enabled}
                    onClick={() => setNotice("Accept stays in this browser. The reserve was not sent, and no transaction was submitted.")}
                  >
                    Accept
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      )}
      {notice === null ? null : (
        <p className="mt-4 text-sm" role="status">
          {notice}
        </p>
      )}
    </section>
  );
}

function parseBase(text: string): bigint | null {
  if (!DECIMAL_AMOUNT.test(text)) return null;
  try {
    return BigInt(text);
  } catch {
    return null;
  }
}
