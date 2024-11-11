use std::time::Instant;
use zkcp::proofs::dlog_secp256k1_sha256::Secp256k1DlogSha256Proof;

fn main() {
    let secret_key = secp::Scalar::reduce_from(&[3u8; 32]);

    let prove_start_time = Instant::now();
    println!("proving execution...");

    let proof = Secp256k1DlogSha256Proof::new(secret_key).unwrap();

    println!(
        "proof generated in {} seconds",
        prove_start_time.elapsed().as_secs()
    );

    println!("receipt journal output:");
    println!("  hash:      {}", hex::encode(proof.hash()));
    println!("  challenge: {:x}", proof.challenge().unwrap());
    println!("  signature: {:x}", proof.signature().unwrap());

    println!("verifying dlog-secp256k1-sha256 proof...");
    proof.verify().unwrap();
    println!("ok!");

    println!("proof is valid; discrete log of {:x}", proof.public_key);
    println!("...is also the preimage of {}", hex::encode(proof.hash()));

    let proof_serialized = borsh::to_vec(&proof).unwrap();
    println!("Receipt is {} bytes long", proof_serialized.len());
}
