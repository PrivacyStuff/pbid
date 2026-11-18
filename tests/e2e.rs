//! The compiled program in LiteSVM: shield, bid, accept, refund, unshield.
//! The observer sees only what an RPC node serves: instruction data, account
//! keys, and account bytes. It never sees a witness or a seal key.
//!
//! Needs `target/deploy/pbid.so` (cargo-build-sbf --no-default-features
//! --features bpf-entrypoint) and the proving key from `cargo run --example gen_vk`.

use std::path::PathBuf;

use litesvm::LiteSVM;
use pbid::job::{hex, run as run_job, unhex, Action, Job, JobError, JobResult, Leaf, NoteJson};
use pbid::{
    note_commitment, open, prove, seal, view_key, Field, NoteTree, Opening, SpendWitness, KIND_BALANCE, KIND_BID,
    LISTING_LEN, LISTING_SEED, MODE_ACCEPT, MODE_BID, MODE_REFUND, MODE_UNSHIELD, NOTE_BID_LEN, OFF_NOTE_SEAL,
    OFF_POOL_ROOT, PLACE_IX_LEN, POOL_LEN, SHIELD_IX_LEN, SPEND_IX_LEN, STANDARD_LEGACY, STATUS_OPEN, STATUS_SOLD,
    TAG_LISTING, UNSHIELD_IX_LEN,
};
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_transaction::Transaction;

const PROGRAM_ID: &str = "tkGNtSKLidw6evDw86n2VUieoJYmExXDXa4RgLdhjJq";
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const COMPUTE_BUDGET: &str = "ComputeBudget111111111111111111111111111111";
const SYSVAR_RENT: &str = "SysvarRent111111111111111111111111111111111";
const SYSVAR_CLOCK: &str = "SysvarC1ock11111111111111111111111111111111";

const IX_SHIELD: u8 = 5;
const IX_PLACE: u8 = 1;
const IX_ACCEPT: u8 = 4;
const IX_REFUND: u8 = 7;
const IX_UNSHIELD: u8 = 8;

/// Instruction data offsets an indexer reads leaves from.
const SHIELD_AMOUNT: std::ops::Range<usize> = 1..9;
const SHIELD_INNER: std::ops::Range<usize> = 9..41;
const SPEND_OUTPUT: std::ops::Range<usize> = 33..65;
const SPEND_CHANGE: std::ops::Range<usize> = 65..97;
const UNSHIELD_CHANGE: std::ops::Range<usize> = 33..65;

const COMPUTE_LIMIT: u32 = 1_400_000;
/// Every note instruction has to leave most of the transaction budget free.
const COMPUTE_CEILING: u64 = 400_000;
const CB_LIMIT: u8 = 2;
const CUSTOM_NON_CANONICAL: u32 = 129;
const CUSTOM_NOTE_SPENT: u32 = 125;
const CUSTOM_BID_NOT_LOCKED: u32 = 123;

const MINT_LEN: usize = 82;
const TOKEN_ACCOUNT_LEN: usize = 165;
const TOKEN_AMOUNT_AT: usize = 64;
const TOKEN_STATE_AT: usize = 108;
const TOKEN_STATE_INITIALIZED: u8 = 1;
const MINT_SUPPLY_AT: usize = 36;
const MINT_DECIMALS_AT: usize = 44;
const MINT_INITIALIZED_AT: usize = 45;
const DECIMALS: u8 = 6;
const NFT_DECIMALS: u8 = 0;
const FUNDED: u64 = 50_000_000;
const SOL: u64 = 1_000_000_000;
const FAR_DEADLINE: i64 = i64::MAX / 2;

const ALICE_SHIELD: u64 = 20_000_000;
const ALICE_BID: u64 = 7_340_000;
const BOB_SHIELD: u64 = 10_000_000;
const BOB_BID: u64 = 4_210_000;
const SELLER_EXIT: u64 = 5_000_000;

/// BN254 scalar modulus, little-endian.
const MODULUS: Field = [
    0x01, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43, 0x91, 0x70, 0xb9, 0x79, 0x48, 0xe8, 0x33, 0x28,
    0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8, 0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
];

fn key(text: &str) -> Address {
    text.parse().expect("the constant is a valid base58 address")
}

fn program() -> Address {
    key(PROGRAM_ID)
}

fn ata(owner: &Address, mint: &Address) -> Address {
    Address::find_program_address(&[owner.as_ref(), key(TOKEN_PROGRAM).as_ref(), mint.as_ref()], &key(ATA_PROGRAM)).0
}

fn pda(seeds: &[&[u8]]) -> Address {
    Address::find_program_address(seeds, &program()).0
}

fn mint_bytes(decimals: u8, supply: u64) -> Vec<u8> {
    let mut data = vec![0u8; MINT_LEN];
    data[MINT_SUPPLY_AT..MINT_SUPPLY_AT + 8].copy_from_slice(&supply.to_le_bytes());
    data[MINT_DECIMALS_AT] = decimals;
    data[MINT_INITIALIZED_AT] = 1;
    data
}

fn token_account_bytes(mint: &Address, owner: &Address, amount: u64) -> Vec<u8> {
    let mut data = vec![0u8; TOKEN_ACCOUNT_LEN];
    data[..32].copy_from_slice(mint.as_ref());
    data[32..64].copy_from_slice(owner.as_ref());
    data[TOKEN_AMOUNT_AT..TOKEN_AMOUNT_AT + 8].copy_from_slice(&amount.to_le_bytes());
    data[TOKEN_STATE_AT] = TOKEN_STATE_INITIALIZED;
    data
}

fn compute_limit() -> Instruction {
    let mut data = vec![CB_LIMIT];
    data.extend_from_slice(&COMPUTE_LIMIT.to_le_bytes());
    Instruction { program_id: key(COMPUTE_BUDGET), accounts: vec![], data }
}

fn add_modulus(value: &Field) -> Field {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for index in 0..32 {
        let sum = u16::from(value[index]) + u16::from(MODULUS[index]) + carry;
        out[index] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "n + r still fits in 32 bytes");
    out
}

/// A note the holder can open. The chain only ever sees its commitment.
#[derive(Clone)]
struct Note {
    opening: Opening,
    index: u32,
}

/// Instruction data plus the notes it creates, before it is sent.
struct Prepared {
    ix: Instruction,
    output: Option<Opening>,
    change: Opening,
}

struct Desk {
    svm: LiteSVM,
    mint: Address,
    nft: Address,
    listing: Address,
    seller: Keypair,
    seller_secret: [u8; 32],
    tree: NoteTree,
    sent: Vec<Transaction>,
    compute: Vec<(u8, u64)>,
}

impl Desk {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        let so = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/deploy/pbid.so");
        svm.add_program_from_file(program(), &so)
            .expect("run cargo-build-sbf --no-default-features --features bpf-entrypoint first");
        let seller = Keypair::new();
        svm.airdrop(&seller.pubkey(), 10 * SOL).expect("airdrop");
        let mint = Address::new_unique();
        let nft = Address::new_unique();
        let rent = svm.minimum_balance_for_rent_exemption(MINT_LEN);
        for (address, decimals, supply) in [(mint, DECIMALS, FUNDED * 4), (nft, NFT_DECIMALS, 1)] {
            let account = Account { lamports: rent, data: mint_bytes(decimals, supply), owner: key(TOKEN_PROGRAM), executable: false, rent_epoch: 0 };
            svm.set_account(address, account).expect("mint");
        }
        let (listing, bump) = Address::find_program_address(&[LISTING_SEED, nft.as_ref()], &program());
        let seller_secret = pbid::random_field();
        let mut data = vec![0u8; LISTING_LEN];
        data[0] = TAG_LISTING;
        data[1] = STATUS_OPEN;
        data[2] = STANDARD_LEGACY;
        data[3] = bump;
        data[4..36].copy_from_slice(seller.pubkey().as_ref());
        data[36..68].copy_from_slice(nft.as_ref());
        data[68..76].copy_from_slice(&FAR_DEADLINE.to_le_bytes());
        data[76..108].copy_from_slice(&view_key(&seller_secret));
        let listing_rent = svm.minimum_balance_for_rent_exemption(LISTING_LEN);
        svm.set_account(listing, Account { lamports: listing_rent, data, owner: program(), executable: false, rent_epoch: 0 })
            .expect("listing");
        let mut desk = Self {
            svm,
            mint,
            nft,
            listing,
            seller,
            seller_secret,
            tree: NoteTree::new(),
            sent: Vec::new(),
            compute: Vec::new(),
        };
        desk.fund_token(&listing, &nft, 1);
        desk
    }

    fn fund_token(&mut self, owner: &Address, mint: &Address, amount: u64) {
        let rent = self.svm.minimum_balance_for_rent_exemption(TOKEN_ACCOUNT_LEN);
        let account = Account { lamports: rent, data: token_account_bytes(mint, owner, amount), owner: key(TOKEN_PROGRAM), executable: false, rent_epoch: 0 };
        self.svm.set_account(ata(owner, mint), account).expect("token account");
    }

    fn bidder(&mut self) -> Keypair {
        let bidder = Keypair::new();
        self.svm.airdrop(&bidder.pubkey(), 10 * SOL).expect("airdrop");
        let mint = self.mint;
        self.fund_token(&bidder.pubkey(), &mint, FUNDED);
        bidder
    }

    fn token_balance(&self, owner: &Address, mint: &Address) -> u64 {
        match self.svm.get_account(&ata(owner, mint)) {
            Some(account) if account.data.len() == TOKEN_ACCOUNT_LEN => {
                u64::from_le_bytes(account.data[TOKEN_AMOUNT_AT..TOKEN_AMOUNT_AT + 8].try_into().expect("8 bytes"))
            }
            _ => 0,
        }
    }

    fn pool(&self) -> Address {
        pda(&[b"pool", self.mint.as_ref()])
    }

    fn vault(&self) -> u64 {
        self.token_balance(&self.pool(), &self.mint)
    }

    fn bid_pda(&self, bidder: &Address) -> Address {
        pda(&[b"bid", self.listing.as_ref(), bidder.as_ref()])
    }

    fn pool_root(&self) -> Field {
        let account = self.svm.get_account(&self.pool()).expect("pool exists");
        assert_eq!(account.data.len(), POOL_LEN);
        account.data[OFF_POOL_ROOT..OFF_POOL_ROOT + 32].try_into().expect("32 bytes")
    }

    fn try_send(&mut self, signer: &Keypair, ix: Instruction) -> Result<(), (u32, String)> {
        let tag = ix.data[0];
        let payer = signer.pubkey();
        let tx = Transaction::new_signed_with_payer(&[compute_limit(), ix], Some(&payer), &[signer], self.svm.latest_blockhash());
        let result = self.svm.send_transaction(tx.clone());
        self.svm.expire_blockhash();
        match result {
            Ok(meta) => {
                self.compute.push((tag, meta.compute_units_consumed));
                self.sent.push(tx);
                Ok(())
            }
            Err(failed) => {
                let code = match failed.err {
                    solana_transaction_error::TransactionError::InstructionError(
                        _,
                        solana_instruction::error::InstructionError::Custom(code),
                    ) => code,
                    _ => u32::MAX,
                };
                Err((code, format!("{:?}\n{}", failed.err, failed.meta.logs.join("\n"))))
            }
        }
    }

    fn send(&mut self, signer: &Keypair, ix: Instruction) {
        if let Err((_, logs)) = self.try_send(signer, ix) {
            panic!("transaction failed: {logs}");
        }
    }

    /// Appends the notes a successful instruction created, in program order.
    fn record(&mut self, prepared: &Prepared) -> (Option<Note>, Note) {
        let output = prepared.output.as_ref().map(|opening| Note { index: self.push(opening), opening: opening.clone() });
        let change = Note { index: self.push(&prepared.change), opening: prepared.change.clone() };
        self.assert_tree_matches();
        (output, change)
    }

    fn append(&mut self, opening: &Opening) -> u32 {
        let index = self.push(opening);
        self.assert_tree_matches();
        index
    }

    fn push(&mut self, opening: &Opening) -> u32 {
        self.tree.append(opening.commitment().expect("commitment"))
    }

    fn assert_tree_matches(&self) {
        assert_eq!(self.tree.root().expect("root"), self.pool_root(), "client tree diverged from the pool");
    }

    fn shield(&mut self, funder: &Keypair, owner: &Address, amount: u64) -> Note {
        let opening = Opening::balance(amount, &owner.to_bytes(), &self.mint.to_bytes());
        let mut data = vec![IX_SHIELD];
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(&opening.inner().expect("inner"));
        assert_eq!(data.len(), SHIELD_IX_LEN);
        let ix = Instruction { program_id: program(), accounts: self.shield_metas(&funder.pubkey()), data };
        self.send(funder, ix);
        Note { index: self.append(&opening), opening }
    }

    fn witness(&self, input: &Note, output: &Opening, change: &Opening, mode: u8, bound: Field, pub_amount: u64) -> SpendWitness {
        let (siblings, bits) = self.tree.path(input.index).expect("path");
        let unshield = mode == MODE_UNSHIELD;
        SpendWitness {
            input: input.opening.clone(),
            output: output.clone(),
            change: change.clone(),
            seller: if unshield { [0u8; 32] } else { self.seller.pubkey().to_bytes() },
            siblings,
            bits,
            auction: if unshield { [0u8; 32] } else { self.listing.to_bytes() },
            mode,
            bound,
            pub_amount,
            old_root: self.tree.root().expect("root"),
        }
    }

    fn change_for(&self, input: &Note, amount: u64) -> Opening {
        Opening::balance(amount, &input.opening.owner, &self.mint.to_bytes())
    }

    fn prepare_place(&self, bidder: &Address, balance: &Note, amount: u64) -> Prepared {
        let output = Opening {
            amount,
            blinding: pbid::random_field(),
            secret: pbid::random_field(),
            owner: bidder.to_bytes(),
            listing: self.listing.to_bytes(),
            mint: self.mint.to_bytes(),
            kind: KIND_BID,
        };
        let change = self.change_for(balance, balance.opening.amount - amount);
        let (proof, instance) = prove(&self.witness(balance, &output, &change, MODE_BID, [0u8; 32], 0)).expect("bid proof");
        let sealed = seal(&view_key(&self.seller_secret), amount, &output.blinding, &output.secret, &pbid::random_field(), &[7u8; 12])
            .expect("seal");
        let mut data = vec![IX_PLACE];
        data.extend_from_slice(&instance.nullifier);
        data.extend_from_slice(&instance.output);
        data.extend_from_slice(&instance.change);
        data.extend_from_slice(&sealed);
        data.extend_from_slice(&proof);
        assert_eq!(data.len(), PLACE_IX_LEN);
        let ix = Instruction { program_id: program(), accounts: self.place_metas(bidder, &instance.nullifier), data };
        Prepared { ix, output: Some(output), change }
    }

    fn place(&mut self, bidder: &Keypair, balance: &Note, amount: u64) -> (Note, Note) {
        let prepared = self.prepare_place(&bidder.pubkey(), balance, amount);
        self.send(bidder, prepared.ix.clone());
        let (output, change) = self.record(&prepared);
        (output.expect("a bid has an output"), change)
    }

    /// The seller reads the amount from the seal on the bid account.
    fn seller_reads(&self, bidder: &Address) -> Note {
        let bid = self.svm.get_account(&self.bid_pda(bidder)).expect("bid account");
        assert_eq!(bid.data.len(), NOTE_BID_LEN);
        let (amount, blinding, secret) = open(&self.seller_secret, &bid.data[OFF_NOTE_SEAL..]).expect("seller opens");
        let opening = Opening { amount, blinding, secret, owner: bidder.to_bytes(), listing: self.listing.to_bytes(), mint: self.mint.to_bytes(), kind: KIND_BID };
        let index = self.tree.position(&opening.commitment().expect("commitment")).expect("the sealed note is in the tree");
        Note { opening, index }
    }

    fn settle_ix(&self, tag: u8, bid: &Note, output: &Opening, change: &Opening, mode: u8) -> (Vec<u8>, Field) {
        let bound = bid.opening.commitment().expect("commitment");
        let (proof, instance) = prove(&self.witness(bid, output, change, mode, bound, 0)).expect("settle proof");
        let mut data = vec![tag];
        data.extend_from_slice(&instance.nullifier);
        data.extend_from_slice(&instance.output);
        data.extend_from_slice(&instance.change);
        data.extend_from_slice(&proof);
        assert_eq!(data.len(), SPEND_IX_LEN);
        (data, instance.nullifier)
    }

    fn accept(&mut self, bidder: &Address, bid: &Note) -> Note {
        let output = Opening::balance(bid.opening.amount, &self.seller.pubkey().to_bytes(), &self.mint.to_bytes());
        let change = self.change_for(bid, 0);
        let (data, nullifier) = self.settle_ix(IX_ACCEPT, bid, &output, &change, MODE_ACCEPT);
        let ix = Instruction { program_id: program(), accounts: self.accept_metas(bidder, &nullifier), data };
        let seller = self.seller.insecure_clone();
        self.send(&seller, ix);
        let (note, _) = self.record(&Prepared { ix: Instruction { program_id: program(), accounts: vec![], data: vec![] }, output: Some(output), change });
        note.expect("an accept has an output")
    }

    fn refund_ix(&self, bidder: &Address, bid: &Note) -> Prepared {
        let output = Opening::balance(bid.opening.amount, &bidder.to_bytes(), &self.mint.to_bytes());
        let change = self.change_for(bid, 0);
        let (data, nullifier) = self.settle_ix(IX_REFUND, bid, &output, &change, MODE_REFUND);
        let ix = Instruction {
            program_id: program(),
            accounts: vec![
                AccountMeta::new(self.bid_pda(bidder), false),
                AccountMeta::new(*bidder, true),
                AccountMeta::new_readonly(self.listing, false),
                AccountMeta::new(self.pool(), false),
                AccountMeta::new(pda(&[b"null", &nullifier]), false),
                AccountMeta::new_readonly(Address::default(), false),
                AccountMeta::new_readonly(key(SYSVAR_RENT), false),
            ],
            data,
        };
        Prepared { ix, output: Some(output), change }
    }

    fn refund(&mut self, bidder: &Keypair, bid: &Note) -> Note {
        let prepared = self.refund_ix(&bidder.pubkey(), bid);
        self.send(bidder, prepared.ix.clone());
        self.record(&prepared).0.expect("a refund has an output")
    }

    fn unshield(&mut self, owner: &Keypair, note: &Note, amount: u64) -> Note {
        let change = self.change_for(note, note.opening.amount - amount);
        let (proof, instance) =
            prove(&self.witness(note, &Opening::empty(), &change, MODE_UNSHIELD, [0u8; 32], amount)).expect("unshield proof");
        let mut data = vec![IX_UNSHIELD];
        data.extend_from_slice(&instance.nullifier);
        data.extend_from_slice(&instance.change);
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(&proof);
        assert_eq!(data.len(), UNSHIELD_IX_LEN);
        let ix = Instruction { program_id: program(), accounts: self.unshield_metas(&owner.pubkey(), &instance.nullifier), data };
        self.send(owner, ix.clone());
        let prepared = Prepared { ix, output: None, change };
        self.record(&prepared).1
    }

    fn shield_metas(&self, funder: &Address) -> Vec<AccountMeta> {
        let pool = self.pool();
        vec![
            AccountMeta::new(pool, false),
            AccountMeta::new(*funder, true),
            AccountMeta::new_readonly(self.mint, false),
            AccountMeta::new(ata(funder, &self.mint), false),
            AccountMeta::new(ata(&pool, &self.mint), false),
            AccountMeta::new_readonly(key(TOKEN_PROGRAM), false),
            AccountMeta::new_readonly(key(ATA_PROGRAM), false),
            AccountMeta::new_readonly(Address::default(), false),
            AccountMeta::new_readonly(key(SYSVAR_RENT), false),
            AccountMeta::new_readonly(key(SYSVAR_CLOCK), false),
        ]
    }

    fn place_metas(&self, bidder: &Address, nullifier: &Field) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(self.bid_pda(bidder), false),
            AccountMeta::new(*bidder, true),
            AccountMeta::new_readonly(self.listing, false),
            AccountMeta::new(self.pool(), false),
            AccountMeta::new(pda(&[b"null", nullifier]), false),
            AccountMeta::new_readonly(Address::default(), false),
            AccountMeta::new_readonly(key(SYSVAR_RENT), false),
            AccountMeta::new_readonly(key(SYSVAR_CLOCK), false),
        ]
    }

    fn accept_metas(&self, bidder: &Address, nullifier: &Field) -> Vec<AccountMeta> {
        vec![
            AccountMeta::new(self.listing, false),
            AccountMeta::new(self.seller.pubkey(), true),
            AccountMeta::new(self.bid_pda(bidder), false),
            AccountMeta::new_readonly(*bidder, false),
            AccountMeta::new_readonly(Address::default(), false),
            AccountMeta::new_readonly(key(SYSVAR_RENT), false),
            AccountMeta::new_readonly(key(SYSVAR_CLOCK), false),
            AccountMeta::new_readonly(self.nft, false),
            AccountMeta::new(ata(&self.listing, &self.nft), false),
            AccountMeta::new(ata(bidder, &self.nft), false),
            AccountMeta::new_readonly(key(TOKEN_PROGRAM), false),
            AccountMeta::new_readonly(key(ATA_PROGRAM), false),
            AccountMeta::new(self.pool(), false),
            AccountMeta::new(pda(&[b"null", nullifier]), false),
        ]
    }

    fn unshield_metas(&self, owner: &Address, nullifier: &Field) -> Vec<AccountMeta> {
        let pool = self.pool();
        vec![
            AccountMeta::new(pool, false),
            AccountMeta::new(*owner, true),
            AccountMeta::new(pda(&[b"null", nullifier]), false),
            AccountMeta::new_readonly(self.mint, false),
            AccountMeta::new(ata(&pool, &self.mint), false),
            AccountMeta::new(ata(owner, &self.mint), false),
            AccountMeta::new_readonly(key(TOKEN_PROGRAM), false),
            AccountMeta::new_readonly(key(ATA_PROGRAM), false),
            AccountMeta::new_readonly(Address::default(), false),
            AccountMeta::new_readonly(key(SYSVAR_RENT), false),
        ]
    }

    /// Every account this auction touched, as an indexer would fetch them.
    fn public_accounts(&self, wallets: &[Address]) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = self.svm.get_program_accounts(&program()).into_iter().map(|(_, account)| account.data).collect();
        for wallet in wallets.iter().chain([self.pool(), self.listing, self.seller.pubkey()].iter()) {
            for mint in [self.mint, self.nft] {
                if let Some(account) = self.svm.get_account(&ata(wallet, &mint)) {
                    out.push(account.data);
                }
            }
        }
        out
    }
}

struct Auction {
    desk: Desk,
    alice: Keypair,
    bob: Keypair,
    bob_bid: Note,
}

/// Alice funds her note from a second wallet. Both bid less than they shielded.
fn auction() -> Auction {
    let mut desk = Desk::new();
    let alice = desk.bidder();
    let alice_funder = desk.bidder();
    let bob = desk.bidder();

    let alice_balance = desk.shield(&alice_funder, &alice.pubkey(), ALICE_SHIELD);
    let bob_balance = desk.shield(&bob, &bob.pubkey(), BOB_SHIELD);
    let shielded = desk.vault();
    assert_eq!(shielded, ALICE_SHIELD + BOB_SHIELD);

    let (_alice_bid, alice_change) = desk.place(&alice, &alice_balance, ALICE_BID);
    let (bob_bid, _bob_change) = desk.place(&bob, &bob_balance, BOB_BID);
    assert_eq!(desk.vault(), shielded, "a bid moved vault tokens");
    assert_eq!(alice_change.opening.amount, ALICE_SHIELD - ALICE_BID);

    let seen = desk.seller_reads(&alice.pubkey());
    assert_eq!(seen.opening.amount, ALICE_BID);
    assert_eq!(desk.seller_reads(&bob.pubkey()).opening.amount, BOB_BID);
    let seller_note = desk.accept(&alice.pubkey(), &seen);
    let listing = desk.svm.get_account(&desk.listing).expect("listing");
    assert_eq!(listing.data[1], STATUS_SOLD);
    assert_eq!(desk.token_balance(&alice.pubkey(), &desk.nft), 1, "the NFT went to the winner");
    assert_eq!(desk.token_balance(&desk.listing, &desk.nft), 0);
    assert_eq!(desk.vault(), shielded, "accept moved vault tokens");

    let bob_back = desk.refund(&bob, &bob_bid);
    assert_eq!(bob_back.opening.amount, BOB_BID);
    let seller = desk.seller.insecure_clone();
    let seller_rest = desk.unshield(&seller, &seller_note, SELLER_EXIT);
    assert_eq!(seller_rest.opening.amount, ALICE_BID - SELLER_EXIT);

    assert_eq!(desk.token_balance(&desk.seller.pubkey(), &desk.mint), SELLER_EXIT);
    assert_eq!(desk.token_balance(&alice_funder.pubkey(), &desk.mint), FUNDED - ALICE_SHIELD);
    assert_eq!(desk.token_balance(&bob.pubkey(), &desk.mint), FUNDED - BOB_SHIELD);
    assert_eq!(desk.vault(), shielded - SELLER_EXIT);
    Auction { desk, alice, bob, bob_bid }
}

#[test]
fn the_compiled_program_runs_a_full_private_auction() {
    let run = auction();
    for (tag, units) in &run.desk.compute {
        println!("instruction {tag}: {units} compute units");
        assert!(*units < COMPUTE_CEILING, "instruction {tag} used {units} compute units");
    }
    let _ = (run.alice, run.bob);
}

#[test]
fn no_bid_amount_appears_in_any_public_byte() {
    let run = auction();
    let wallets = [run.alice.pubkey(), run.bob.pubkey()];
    let mut public: Vec<Vec<u8>> = run.desk.sent.iter().flat_map(|tx| tx.message.instructions.iter().map(|ix| ix.data.clone())).collect();
    public.extend(run.desk.public_accounts(&wallets));
    // Bids, both change notes, and what the seller kept shielded. Shields and the
    // seller's exit are public by design, so they are not in this list.
    let hidden = [ALICE_BID, BOB_BID, ALICE_SHIELD - ALICE_BID, BOB_SHIELD - BOB_BID, ALICE_BID - SELLER_EXIT];
    for amount in hidden {
        for needle in [amount.to_le_bytes(), amount.to_be_bytes()] {
            let hits = public.iter().filter(|bytes| bytes.windows(needle.len()).any(|window| window == needle)).count();
            assert_eq!(hits, 0, "the hidden amount {amount} is readable in {hits} public byte strings");
        }
    }
}

#[test]
fn a_shield_publishes_no_note_secret() {
    let run = auction();
    for tx in &run.desk.sent {
        for ix in &tx.message.instructions {
            if ix.data.first() == Some(&IX_SHIELD) {
                assert_eq!(ix.data.len(), SHIELD_IX_LEN, "tag, amount, and one hash");
            }
        }
    }
    // The inner hash is a commitment to the blinding, secret, and owner. Without
    // the secret, nobody can compute the nullifier a later spend reveals.
    let owner = run.alice.pubkey().to_bytes();
    let probe = Opening::balance(ALICE_SHIELD, &owner, &run.desk.mint.to_bytes());
    let guess = note_commitment(probe.amount, &[0u8; 32], &[0u8; 32], &owner, &[0u8; 32], &probe.mint, KIND_BALANCE).expect("hash");
    assert_ne!(guess, probe.commitment().expect("hash"));
}

#[test]
fn a_nullifier_plus_the_modulus_is_refused() {
    let mut desk = Desk::new();
    let bidder = desk.bidder();
    let balance = desk.shield(&bidder, &bidder.pubkey(), BOB_SHIELD);
    let mut prepared = desk.prepare_place(&bidder.pubkey(), &balance, BOB_BID);
    let nullifier: Field = prepared.ix.data[1..33].try_into().expect("32 bytes");
    let shadow = add_modulus(&nullifier);
    prepared.ix.data[1..33].copy_from_slice(&shadow);
    prepared.ix.accounts[4] = AccountMeta::new(pda(&[b"null", &shadow]), false);
    let (code, logs) = desk.try_send(&bidder, prepared.ix).expect_err("n + r is the same proof input and has to be refused");
    assert_eq!(code, CUSTOM_NON_CANONICAL, "{logs}");
}

#[test]
fn a_spent_note_cannot_be_spent_twice() {
    let mut run = auction();
    let bob = run.bob.insecure_clone();
    let replay = run.desk.refund_ix(&bob.pubkey(), &run.bob_bid);
    let (code, logs) = run.desk.try_send(&bob, replay.ix).expect_err("a second refund of one bid");
    assert!(code == CUSTOM_BID_NOT_LOCKED || code == CUSTOM_NOTE_SPENT, "{logs}");
}

#[test]
fn a_stranger_cannot_refund_someone_elses_bid() {
    let mut desk = Desk::new();
    let bidder = desk.bidder();
    let stranger = desk.bidder();
    let balance = desk.shield(&bidder, &bidder.pubkey(), BOB_SHIELD);
    let (bid, _) = desk.place(&bidder, &balance, BOB_BID);
    let mut stolen = desk.refund_ix(&bidder.pubkey(), &bid);
    stolen.ix.accounts[1] = AccountMeta::new(stranger.pubkey(), true);
    assert!(desk.try_send(&stranger, stolen.ix).is_err());
}

/// Leaves as a public indexer rebuilds them: only from instruction data the
/// program accepted. Shields publish an amount and an inner hash, spends
/// publish commitments.
fn replay_leaves(desk: &Desk) -> Vec<Leaf> {
    let commitment = |bytes: &[u8]| Leaf::Commitment { commitment: hex(bytes) };
    let mut leaves = Vec::new();
    for tx in &desk.sent {
        for ix in &tx.message.instructions {
            let data = &ix.data;
            match data.first().copied() {
                Some(IX_SHIELD) => leaves.push(Leaf::Shield {
                    amount: u64::from_le_bytes(data[SHIELD_AMOUNT].try_into().expect("8 bytes")).to_string(),
                    inner: hex(&data[SHIELD_INNER]),
                }),
                Some(IX_PLACE | IX_ACCEPT | IX_REFUND) => {
                    leaves.push(commitment(&data[SPEND_OUTPUT]));
                    leaves.push(commitment(&data[SPEND_CHANGE]));
                }
                Some(IX_UNSHIELD) => leaves.push(commitment(&data[UNSHIELD_CHANGE])),
                _ => {}
            }
        }
    }
    leaves
}

fn job_for(desk: &Desk, action: Action) -> Job {
    let root = desk.svm.get_account(&desk.pool()).map(|account| hex(&account.data[OFF_POOL_ROOT..OFF_POOL_ROOT + 32]));
    Job {
        action,
        mint: hex(desk.mint.as_ref()),
        root,
        leaves: replay_leaves(desk),
        amount: None,
        owner: None,
        note: None,
        listing: Some(hex(desk.listing.as_ref())),
        seller: Some(hex(desk.seller.pubkey().as_ref())),
        seller_view: Some(hex(&view_key(&desk.seller_secret))),
    }
}

fn job_data(result: &JobResult) -> (Vec<u8>, Field) {
    let data = unhex(&result.data).expect("hex");
    let nullifier = result.nullifier.as_deref().map(|value| unhex(value).expect("hex").try_into().expect("32 bytes")).unwrap_or([0u8; 32]);
    (data, nullifier)
}

#[test]
fn prover_jobs_run_on_the_compiled_program() {
    let mut desk = Desk::new();
    let alice = desk.bidder();
    let funder = desk.bidder();
    let seller = desk.seller.insecure_clone();

    let mut shield = job_for(&desk, Action::Shield);
    shield.amount = Some(ALICE_SHIELD.to_string());
    shield.owner = Some(hex(alice.pubkey().as_ref()));
    let shielded = run_job(&shield).expect("shield job");
    let (data, _) = job_data(&shielded);
    let ix = Instruction { program_id: program(), accounts: desk.shield_metas(&funder.pubkey()), data };
    desk.send(&funder, ix);

    let mut place = job_for(&desk, Action::Place);
    place.amount = Some(ALICE_BID.to_string());
    place.note = shielded.output.clone();
    let placed = run_job(&place).expect("place job");
    let (data, nullifier) = job_data(&placed);
    let ix = Instruction { program_id: program(), accounts: desk.place_metas(&alice.pubkey(), &nullifier), data };
    desk.send(&alice, ix);
    let change = placed.change.clone().expect("a bid leaves change");
    assert_eq!(change.amount, (ALICE_SHIELD - ALICE_BID).to_string());

    // The seller rebuilds the bid note from the seal alone.
    let bid = desk.svm.get_account(&desk.bid_pda(&alice.pubkey())).expect("bid account");
    let (amount, blinding, secret) = open(&desk.seller_secret, &bid.data[OFF_NOTE_SEAL..]).expect("seller opens");
    assert_eq!(amount, ALICE_BID);
    let opening = Opening { amount, blinding, secret, owner: alice.pubkey().to_bytes(), listing: desk.listing.to_bytes(), mint: desk.mint.to_bytes(), kind: KIND_BID };
    let seen = NoteJson {
        amount: amount.to_string(),
        blinding: hex(&blinding),
        secret: hex(&secret),
        owner: hex(&opening.owner),
        listing: hex(&opening.listing),
        mint: hex(&opening.mint),
        kind: KIND_BID,
        commitment: hex(&opening.commitment().expect("commitment")),
    };
    assert_eq!(Some(&seen), placed.output.as_ref(), "the seal opens to the note the bidder created");

    let mut accept = job_for(&desk, Action::Accept);
    accept.note = Some(seen);
    let accepted = run_job(&accept).expect("accept job");
    let (data, nullifier) = job_data(&accepted);
    let ix = Instruction { program_id: program(), accounts: desk.accept_metas(&alice.pubkey(), &nullifier), data };
    desk.send(&seller, ix);
    assert_eq!(desk.token_balance(&alice.pubkey(), &desk.nft), 1);

    let mut exit = job_for(&desk, Action::Unshield);
    exit.amount = Some(SELLER_EXIT.to_string());
    exit.note = accepted.output.clone();
    let exited = run_job(&exit).expect("unshield job");
    let (data, nullifier) = job_data(&exited);
    let ix = Instruction { program_id: program(), accounts: desk.unshield_metas(&seller.pubkey(), &nullifier), data };
    desk.send(&seller, ix);
    assert_eq!(desk.token_balance(&seller.pubkey(), &desk.mint), SELLER_EXIT);
    assert_eq!(desk.vault(), ALICE_SHIELD - SELLER_EXIT);

    // Past the root check, a spend with no note stops at the missing field.
    let rebuilt = run_job(&job_for(&desk, Action::Unshield)).map(|_| ()).unwrap_err();
    assert_eq!(rebuilt, JobError::MissingField, "the replayed leaves still match the pool root");
}
