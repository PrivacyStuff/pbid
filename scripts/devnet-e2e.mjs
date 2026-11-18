// Private auction against a deployed pbid program, then a privacy scan of
// everything an RPC node serves about it.
//
//   node scripts/devnet-e2e.mjs <program-id>
//
// RPC and payer come from the Solana CLI config. The RPC URL is never printed.
// Libraries are resolved from the website checkout (PBID_WEBSITE, default
// ../website/package.json). Proofs come from `cargo run --example bid_prove`.

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const PBID_DIR = path.resolve(here, "..");
const require = createRequire(process.env.PBID_WEBSITE ?? path.resolve(PBID_DIR, "../website/package.json"));
const web3 = require("@solana/web3.js");
const spl = require("@solana/spl-token");
const { PublicKey, Keypair, SystemProgram, Transaction, TransactionInstruction, ComputeBudgetProgram } = web3;

const CORE_PROGRAM = new PublicKey("CoREENxT6tW1HoK8ypY1SxRMZTcVPm7R94rH4PZNhX7d");
const RENT = web3.SYSVAR_RENT_PUBKEY;
const CLOCK = web3.SYSVAR_CLOCK_PUBKEY;

const IX_LIST = 0;
const IX_PLACE = 1;
const IX_ACCEPT = 4;
const IX_SHIELD = 5;
const IX_REFUND = 7;
const IX_UNSHIELD = 8;
const STANDARD_CORE = 1;
const CORE_CREATE_V1 = 0;
const CORE_DATA_ACCOUNT_STATE = 0;
const BORSH_NONE = 0;

const OFF_POOL_ROOT = 36;
const OFF_NOTE_SEAL = 136;
const SEAL_LEN = 132;
const SEAL_EPHEMERAL = 32;
const SEAL_NONCE = 12;
const POLY1305_TAG = 16;
const KIND_BID = 1;
const LISTING_STATUS_SOLD = 2;
const SHIELD_AMOUNT = [1, 9];
const SHIELD_INNER = [9, 41];
const SPEND_OUTPUT = [33, 65];
const SPEND_CHANGE = [65, 97];
const UNSHIELD_CHANGE = [33, 65];

const COMPUTE_LIMIT = 400_000;
const DECIMALS = 6;
const FUNDED = 50_000_000n;
const ALICE_SHIELD = 20_000_000n;
const ALICE_BID = 7_340_000n;
const BOB_SHIELD = 10_000_000n;
const BOB_BID = 4_210_000n;
const SELLER_EXIT = 5_000_000n;
const WALLET_LAMPORTS = 100_000_000;
const DEADLINE_SECONDS = 3_600n;
const SIGNATURE_PAGE = 1_000;

const X25519_PKCS8 = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI = Buffer.from("302a300506032b656e032100", "hex");

function solanaConfig() {
  const file = path.join(os.homedir(), ".config/solana/cli/config.yml");
  const text = fs.readFileSync(file, "utf8");
  const field = (name) => {
    const line = text.split("\n").find((row) => row.startsWith(`${name}:`));
    if (line === undefined) throw new Error(`The Solana config has no ${name}.`);
    return line.slice(name.length + 1).trim().replace(/^["']|["']$/g, "");
  };
  return { rpc: field("json_rpc_url"), keypair: field("keypair_path") };
}

function loadKeypair(file) {
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(file, "utf8"))));
}

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const unhex = (text) => Uint8Array.from(Buffer.from(text, "hex"));
const u64le = (value) => {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(BigInt(value));
  return out;
};
const i64le = (value) => {
  const out = Buffer.alloc(8);
  out.writeBigInt64LE(BigInt(value));
  return out;
};
const borshString = (text) => {
  const body = Buffer.from(text, "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32LE(body.length);
  return Buffer.concat([len, body]);
};

class Desk {
  constructor(connection, programId, payer) {
    this.connection = connection;
    this.programId = programId;
    this.payer = payer;
    this.log = [];
  }

  pda(seeds) {
    return PublicKey.findProgramAddressSync(seeds, this.programId)[0];
  }

  async send(label, instructions, signers) {
    const tx = new Transaction().add(ComputeBudgetProgram.setComputeUnitLimit({ units: COMPUTE_LIMIT }), ...instructions);
    try {
      const signature = await web3.sendAndConfirmTransaction(this.connection, tx, signers, { commitment: "confirmed" });
      const meta = await this.connection.getTransaction(signature, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
      const units = meta?.meta?.computeUnitsConsumed ?? 0;
      this.log.push({ label, signature, units });
      console.log(`  ${label.padEnd(22)} ${String(units).padStart(7)} CU  ${signature}`);
      return signature;
    } catch (error) {
      const logs = typeof error?.getLogs === "function" ? await error.getLogs(this.connection).catch(() => null) : error?.logs;
      throw new Error(`${label} failed: ${error?.message ?? error}\n${(logs ?? []).join("\n")}`);
    }
  }

  async fund(wallet) {
    await this.send(`fund ${wallet.publicKey.toBase58().slice(0, 6)}`, [
      SystemProgram.transfer({ fromPubkey: this.payer.publicKey, toPubkey: wallet.publicKey, lamports: WALLET_LAMPORTS }),
    ], [this.payer]);
  }

  /// Leaves rebuilt only from instruction data the program accepted.
  async leaves(mint) {
    const pool = this.pda([Buffer.from("pool"), mint.toBuffer()]);
    const signatures = [];
    let before;
    for (;;) {
      const page = await this.connection.getSignaturesForAddress(pool, { before, limit: SIGNATURE_PAGE }, "confirmed");
      signatures.push(...page);
      if (page.length < SIGNATURE_PAGE) break;
      before = page[page.length - 1].signature;
    }
    const leaves = [];
    for (const row of signatures.reverse()) {
      if (row.err !== null) continue;
      for (const data of await this.programData(row.signature)) {
        const slice = ([start, end]) => data.subarray(start, end);
        switch (data[0]) {
          case IX_SHIELD:
            leaves.push({ kind: "shield", amount: Buffer.from(slice(SHIELD_AMOUNT)).readBigUInt64LE().toString(), inner: hex(slice(SHIELD_INNER)) });
            break;
          case IX_PLACE:
          case IX_ACCEPT:
          case IX_REFUND:
            leaves.push({ kind: "commitment", commitment: hex(slice(SPEND_OUTPUT)) });
            leaves.push({ kind: "commitment", commitment: hex(slice(SPEND_CHANGE)) });
            break;
          case IX_UNSHIELD:
            leaves.push({ kind: "commitment", commitment: hex(slice(UNSHIELD_CHANGE)) });
            break;
          default:
            break;
        }
      }
    }
    return leaves;
  }

  async programData(signature) {
    const tx = await this.connection.getTransaction(signature, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
    if (tx === null) throw new Error(`Transaction ${signature} is not available yet.`);
    const keys = tx.transaction.message.staticAccountKeys;
    return tx.transaction.message.compiledInstructions
      .filter((ix) => keys[ix.programIdIndex].equals(this.programId))
      .map((ix) => Buffer.from(ix.data));
  }

  async root(mint) {
    const pool = await this.connection.getAccountInfo(this.pda([Buffer.from("pool"), mint.toBuffer()]), "confirmed");
    if (pool === null) return null;
    return hex(pool.data.subarray(OFF_POOL_ROOT, OFF_POOL_ROOT + 32));
  }
}

function prove(job) {
  const result = spawnSync("cargo", ["+1.97.1", "run", "--quiet", "--offline", "--release", "--example", "bid_prove"], {
    cwd: PBID_DIR,
    input: JSON.stringify(job),
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) throw new Error(`prover: ${result.stderr.trim()}`);
  return JSON.parse(result.stdout);
}

function viewKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("x25519");
  const secret = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const view = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return { secret: Buffer.from(secret), view: Buffer.from(view) };
}

/// The seller's side of the seal: X25519 with the ephemeral key, then ChaCha20-Poly1305.
function openSeal(secret, sealed) {
  if (sealed.length !== SEAL_LEN) throw new Error("The seal is the wrong length.");
  const ephemeral = sealed.subarray(0, SEAL_EPHEMERAL);
  const nonce = sealed.subarray(SEAL_EPHEMERAL, SEAL_EPHEMERAL + SEAL_NONCE);
  const body = sealed.subarray(SEAL_EPHEMERAL + SEAL_NONCE, SEAL_LEN - POLY1305_TAG);
  const tag = sealed.subarray(SEAL_LEN - POLY1305_TAG);
  const shared = crypto.diffieHellman({
    privateKey: crypto.createPrivateKey({ key: Buffer.concat([X25519_PKCS8, secret]), format: "der", type: "pkcs8" }),
    publicKey: crypto.createPublicKey({ key: Buffer.concat([X25519_SPKI, ephemeral]), format: "der", type: "spki" }),
  });
  const decipher = crypto.createDecipheriv("chacha20-poly1305", shared, nonce, { authTagLength: POLY1305_TAG });
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(body), decipher.final()]);
  return { amount: plain.readBigUInt64LE(0), blinding: hex(plain.subarray(8, 40)), secret: hex(plain.subarray(40, 72)) };
}

async function createCoreAsset(desk, owner) {
  const asset = Keypair.generate();
  const data = Buffer.concat([
    Buffer.from([CORE_CREATE_V1, CORE_DATA_ACCOUNT_STATE]),
    borshString("pbid devnet test"),
    borshString("https://example.com/pbid.json"),
    Buffer.from([BORSH_NONE]),
  ]);
  const optional = { pubkey: CORE_PROGRAM, isSigner: false, isWritable: false };
  const ix = new TransactionInstruction({
    programId: CORE_PROGRAM,
    keys: [
      { pubkey: asset.publicKey, isSigner: true, isWritable: true },
      optional,
      optional,
      { pubkey: owner.publicKey, isSigner: true, isWritable: true },
      optional,
      optional,
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      optional,
    ],
    data,
  });
  await desk.send("create Core asset", [ix], [owner, asset]);
  return asset.publicKey;
}

async function main() {
  const programArg = process.argv[2];
  if (programArg === undefined) throw new Error("Usage: node scripts/devnet-e2e.mjs <program-id>");
  const programId = new PublicKey(programArg);
  const config = solanaConfig();
  const connection = new web3.Connection(config.rpc, "confirmed");
  const seller = loadKeypair(config.keypair);
  const desk = new Desk(connection, programId, seller);
  const program = await connection.getAccountInfo(programId);
  if (program === null || !program.executable) throw new Error("The program id is not a deployed program on this cluster.");

  console.log(`program ${programId.toBase58()}`);
  console.log(`seller  ${seller.publicKey.toBase58()}`);
  const alice = Keypair.generate();
  const funder = Keypair.generate();
  const bob = Keypair.generate();
  console.log(`alice ${alice.publicKey.toBase58()}  funder ${funder.publicKey.toBase58()}  bob ${bob.publicKey.toBase58()}`);

  console.log("setup");
  for (const wallet of [alice, funder, bob]) await desk.fund(wallet);
  const mint = await spl.createMint(connection, seller, seller.publicKey, null, DECIMALS);
  console.log(`  mint ${mint.toBase58()}`);
  for (const wallet of [funder, bob]) {
    const account = await spl.getOrCreateAssociatedTokenAccount(connection, seller, mint, wallet.publicKey);
    await spl.mintTo(connection, seller, mint, account.address, seller, FUNDED);
  }
  const asset = await createCoreAsset(desk, seller);
  console.log(`  asset ${asset.toBase58()}`);

  const view = viewKeyPair();
  const listing = desk.pda([Buffer.from("listing"), asset.toBuffer()]);
  const now = BigInt(Math.floor(Date.now() / 1000));
  await desk.send("list", [new TransactionInstruction({
    programId,
    keys: [
      { pubkey: listing, isSigner: false, isWritable: true },
      { pubkey: seller.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: RENT, isSigner: false, isWritable: false },
      { pubkey: CLOCK, isSigner: false, isWritable: false },
      { pubkey: asset, isSigner: false, isWritable: true },
      { pubkey: CORE_PROGRAM, isSigner: false, isWritable: false },
      { pubkey: CORE_PROGRAM, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([Buffer.from([IX_LIST, STANDARD_CORE]), i64le(now + DEADLINE_SECONDS), view.view]),
  })], [seller]);

  const pool = desk.pda([Buffer.from("pool"), mint.toBuffer()]);
  const vault = spl.getAssociatedTokenAddressSync(mint, pool, true);
  const ata = (owner) => spl.getAssociatedTokenAddressSync(mint, owner, true);
  const nullPda = (nullifier) => desk.pda([Buffer.from("null"), Buffer.from(nullifier, "hex")]);
  const bidPda = (bidder) => desk.pda([Buffer.from("bid"), listing.toBuffer(), bidder.toBuffer()]);
  const meta = (pubkey, isWritable = false, isSigner = false) => ({ pubkey, isSigner, isWritable });
  const base = async (action) => ({
    action,
    mint: hex(mint.toBuffer()),
    root: await desk.root(mint),
    leaves: await desk.leaves(mint),
    listing: hex(listing.toBuffer()),
    seller: hex(seller.publicKey.toBuffer()),
    sellerView: hex(view.view),
  });
  const ix = (keys, data) => new TransactionInstruction({ programId, keys, data: Buffer.from(unhex(data)) });

  console.log("shield");
  const shields = {};
  for (const [label, payer, owner, amount] of [["alice (from funder)", funder, alice, ALICE_SHIELD], ["bob", bob, bob, BOB_SHIELD]]) {
    const job = { ...(await base("shield")), amount: amount.toString(), owner: hex(owner.publicKey.toBuffer()) };
    const result = prove(job);
    await desk.send(`shield ${label}`, [ix([
      meta(pool, true), meta(payer.publicKey, true, true), meta(mint), meta(ata(payer.publicKey), true), meta(vault, true),
      meta(spl.TOKEN_PROGRAM_ID), meta(spl.ASSOCIATED_TOKEN_PROGRAM_ID), meta(SystemProgram.programId), meta(RENT), meta(CLOCK),
    ], result.data)], [payer]);
    shields[owner.publicKey.toBase58()] = result.output;
  }

  console.log("place");
  const bids = {};
  for (const [label, bidder, amount] of [["alice", alice, ALICE_BID], ["bob", bob, BOB_BID]]) {
    const job = { ...(await base("place")), amount: amount.toString(), note: shields[bidder.publicKey.toBase58()] };
    const result = prove(job);
    await desk.send(`place ${label}`, [ix([
      meta(bidPda(bidder.publicKey), true), meta(bidder.publicKey, true, true), meta(listing), meta(pool, true),
      meta(nullPda(result.nullifier), true), meta(SystemProgram.programId), meta(RENT), meta(CLOCK),
    ], result.data)], [bidder]);
    bids[bidder.publicKey.toBase58()] = result;
  }

  console.log("seller opens the seals");
  const seen = {};
  for (const bidder of [alice, bob]) {
    const account = await connection.getAccountInfo(bidPda(bidder.publicKey), "confirmed");
    const opened = openSeal(view.secret, account.data.subarray(OFF_NOTE_SEAL, OFF_NOTE_SEAL + SEAL_LEN));
    const placed = bids[bidder.publicKey.toBase58()].output;
    if (opened.blinding !== placed.blinding || opened.secret !== placed.secret || opened.amount.toString() !== placed.amount) {
      throw new Error("The seal does not open to the note the bidder created.");
    }
    console.log(`  ${bidder === alice ? "alice" : "bob  "} bid ${opened.amount}`);
    seen[bidder.publicKey.toBase58()] = { ...placed, kind: KIND_BID };
  }

  console.log("accept alice, refund bob, seller exits part");
  const accept = prove({ ...(await base("accept")), note: seen[alice.publicKey.toBase58()] });
  await desk.send("accept alice", [ix([
    meta(listing, true), meta(seller.publicKey, true, true), meta(bidPda(alice.publicKey), true), meta(alice.publicKey),
    meta(SystemProgram.programId), meta(RENT), meta(CLOCK), meta(asset, true), meta(CORE_PROGRAM), meta(CORE_PROGRAM),
    meta(pool, true), meta(nullPda(accept.nullifier), true),
  ], accept.data)], [seller]);

  const refund = prove({ ...(await base("refund")), note: bids[bob.publicKey.toBase58()].output });
  await desk.send("refund bob", [ix([
    meta(bidPda(bob.publicKey), true), meta(bob.publicKey, true, true), meta(listing), meta(pool, true),
    meta(nullPda(refund.nullifier), true), meta(SystemProgram.programId), meta(RENT),
  ], refund.data)], [bob]);

  const exit = prove({ ...(await base("unshield")), amount: SELLER_EXIT.toString(), note: accept.output });
  await desk.send("unshield seller", [ix([
    meta(pool, true), meta(seller.publicKey, true, true), meta(nullPda(exit.nullifier), true), meta(mint), meta(vault, true),
    meta(ata(seller.publicKey), true), meta(spl.TOKEN_PROGRAM_ID), meta(spl.ASSOCIATED_TOKEN_PROGRAM_ID),
    meta(SystemProgram.programId), meta(RENT),
  ], exit.data)], [seller]);

  console.log("checks");
  const tokens = async (owner) => (await connection.getTokenAccountBalance(ata(owner), "confirmed")).value.amount;
  const assetAccount = await connection.getAccountInfo(asset, "confirmed");
  const assetOwner = new PublicKey(assetAccount.data.subarray(1, 33));
  const listingAccount = await connection.getAccountInfo(listing, "confirmed");
  const expect = (label, got, want) => {
    if (String(got) !== String(want)) throw new Error(`${label}: got ${got}, want ${want}`);
    console.log(`  ok  ${label} = ${got}`);
  };
  expect("asset owner is alice", assetOwner.toBase58(), alice.publicKey.toBase58());
  expect("listing status sold", listingAccount.data[1], LISTING_STATUS_SOLD);
  expect("vault", await tokens(pool), ALICE_SHIELD + BOB_SHIELD - SELLER_EXIT);
  expect("seller wallet", await tokens(seller.publicKey), SELLER_EXIT);
  expect("funder wallet", await tokens(funder.publicKey), FUNDED - ALICE_SHIELD);
  expect("bob wallet", await tokens(bob.publicKey), FUNDED - BOB_SHIELD);

  console.log("privacy scan of what the RPC serves");
  const publicBytes = [];
  for (const entry of desk.log) {
    const tx = await connection.getTransaction(entry.signature, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
    for (const compiled of tx.transaction.message.compiledInstructions) publicBytes.push(Buffer.from(compiled.data));
    publicBytes.push(Buffer.from((tx.meta.logMessages ?? []).join("\n")));
  }
  for (const { account } of await connection.getProgramAccounts(programId, "confirmed")) publicBytes.push(account.data);
  for (const owner of [alice.publicKey, bob.publicKey, funder.publicKey, seller.publicKey, pool]) {
    const account = await connection.getAccountInfo(ata(owner), "confirmed");
    if (account !== null) publicBytes.push(account.data);
  }
  const hidden = {
    "alice bid": ALICE_BID,
    "bob bid": BOB_BID,
    "alice change": ALICE_SHIELD - ALICE_BID,
    "bob change": BOB_SHIELD - BOB_BID,
    "seller kept shielded": ALICE_BID - SELLER_EXIT,
  };
  let leaks = 0;
  for (const [label, amount] of Object.entries(hidden)) {
    const le = u64le(amount);
    const be = Buffer.from(le).reverse();
    const text = Buffer.from(amount.toString());
    const hits = publicBytes.filter((bytes) => bytes.includes(le) || bytes.includes(be) || bytes.includes(text)).length;
    leaks += hits;
    console.log(`  ${hits === 0 ? "ok  " : "LEAK"} ${label} (${amount}) in ${hits} of ${publicBytes.length} public byte strings`);
  }
  if (leaks > 0) throw new Error("A hidden amount is readable on chain.");
  console.log("devnet private auction passed");
}

main().catch((error) => {
  console.error(error.message ?? error);
  process.exit(1);
});
