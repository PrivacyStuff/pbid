import { BidDesk } from "@/components/bid-desk";

export default function HomePage() {
  return (
    <div className="flex min-h-full flex-1 flex-col">
      <header className="flex items-center justify-between border-b border-line px-6 py-5 md:px-10">
        <p className="text-sm tracking-[0.22em] uppercase">pbid</p>
        <p className="text-sm tracking-[0.18em] text-muted uppercase">Open</p>
      </header>
      <main className="mx-auto flex w-full max-w-6xl flex-1 flex-col px-6 py-16 md:px-10 md:py-24">
        <BidDesk />
      </main>
      <footer className="border-t border-line px-6 py-6 text-sm text-muted md:px-10">
        Local preview. The reserve stays in this browser. No transaction is sent.
      </footer>
    </div>
  );
}
