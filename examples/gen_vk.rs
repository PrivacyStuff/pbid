//! Creates the join-split keys from OS entropy. Writes the proving key to
//! `keys/pbid_pk.bin` (or `$PBID_PROVING_KEY`) and the verifying key the
//! program includes to `src/vk.bin`. The setup randomness lives only in this
//! process. Rebuild and redeploy the program after running this.
//! `cargo +1.97.1 run --release --example gen_vk`

use rand_core::OsRng;

fn main() {
    if let Err(message) = run() {
        eprintln!("{message}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let (pk, vk) = pbid::setup(&mut OsRng).map_err(|err| format!("setup failed: {err:?}"))?;
    let pk_path = pbid::proving_key_path();
    if let Some(parent) = pk_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| format!("{}: {err}", parent.display()))?;
    }
    std::fs::write(&pk_path, &pk).map_err(|err| format!("{}: {err}", pk_path.display()))?;
    let vk_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/vk.bin");
    std::fs::write(&vk_path, &vk).map_err(|err| format!("{}: {err}", vk_path.display()))?;
    println!("proving key {} bytes -> {}", pk.len(), pk_path.display());
    println!("verifying key {} bytes -> {}", vk.len(), vk_path.display());
    Ok(())
}
