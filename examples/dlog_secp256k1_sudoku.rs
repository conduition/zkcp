use std::time::Instant;
use zkcp::proofs::dlog_secp256k1_sudoku::Secp256k1DlogSudokuProof;
use zkcp::sudoku::is_valid_sudoku_solution;

fn main() {
    let secret_key = secp::Scalar::reduce_from(&[3u8; 32]);

    let solution = [
        6, 1, 4, /**/ 3, 8, 9, /**/ 2, 5, 7, //
        5, 8, 3, /**/ 6, 7, 2, /**/ 4, 1, 9, //
        9, 7, 2, /**/ 5, 4, 1, /**/ 8, 6, 3, //
        /***********************************/
        1, 3, 9, /**/ 8, 5, 4, /**/ 6, 7, 2, //
        2, 5, 8, /**/ 1, 6, 7, /**/ 9, 3, 4, //
        7, 4, 6, /**/ 2, 9, 3, /**/ 5, 8, 1, //
        /***********************************/
        8, 2, 7, /**/ 9, 1, 5, /**/ 3, 4, 6, //
        4, 9, 5, /**/ 7, 3, 6, /**/ 1, 2, 8, //
        3, 6, 1, /**/ 4, 2, 8, /**/ 7, 9, 5, //
    ];
    let mask = [
        1, 1, 1, /**/ 1, 1, 1, /**/ 1, 1, 0, //
        1, 0, 0, /**/ 1, 0, 0, /**/ 1, 0, 0, //
        0, 0, 0, /**/ 1, 0, 0, /**/ 0, 1, 1, //
        /***********************************/
        1, 1, 0, /**/ 1, 0, 0, /**/ 1, 1, 0, //
        1, 0, 1, /**/ 1, 1, 0, /**/ 1, 0, 1, //
        0, 1, 0, /**/ 1, 0, 1, /**/ 1, 0, 1, //
        /***********************************/
        0, 1, 0, /**/ 1, 0, 0, /**/ 1, 0, 0, //
        1, 0, 1, /**/ 1, 0, 1, /**/ 1, 0, 0, //
        1, 1, 0, /**/ 1, 1, 0, /**/ 1, 0, 1, //
    ];

    let prove_start_time = Instant::now();
    println!("proving execution...");

    let proof = Secp256k1DlogSudokuProof::new(secret_key, &solution, &mask).unwrap();

    println!(
        "proof generated in {} seconds",
        prove_start_time.elapsed().as_secs()
    );

    println!("receipt journal output:");
    println!("  challenge: {:x}", proof.challenge().unwrap());
    println!("  signature: {:x}", proof.signature().unwrap());

    println!("verifying dlog-secp256k1-sudoku proof...");
    proof.verify().unwrap();
    println!("ok!");

    println!("proof is valid; discrete log of {:x}", proof.public_key);
    println!(
        "...is also the decryption key to a solution for the sudoku puzzle:\n{:?}",
        proof.puzzle()
    );

    let proof_serialized = borsh::to_vec(&proof).unwrap();
    println!("Receipt is {} bytes long", proof_serialized.len());

    let solution = proof.decrypt_solution(secret_key).unwrap();
    assert!(is_valid_sudoku_solution(&solution));
}
