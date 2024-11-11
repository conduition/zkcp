use risc0_zkvm::guest::env;
use risc0_zkvm::guest::sha;
use risc0_zkvm::guest::sha::Sha256;

use common::secp256k1;

fn main() {
    let mut secret_key = [0u8; 32];
    let mut secret_nonce = [0u8; 32];
    let mut challenge = [0u8; 32];

    env::read_slice(&mut secret_key);
    env::read_slice(&mut secret_nonce);
    env::read_slice(&mut challenge);

    let sig = secp256k1::schnorr_signature(secret_key, secret_nonce, challenge);

    env::commit_slice(&challenge);
    env::commit_slice(&sig);

    // Compute SHA256 hash, and write it to the journal as a public output
    let digest = sha::Impl::hash_bytes(&secret_key);
    env::commit_slice(digest.as_bytes());
}
