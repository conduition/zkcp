use std::time::Instant;
use zkcp::proofs::sha256_sudoku::Sha256SudokuProof;
use zkcp::sudoku::is_valid_sudoku_solution;

fn main() {
    let preimage = [3u8; 32];

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

    let proof = Sha256SudokuProof::new(preimage, &solution, &mask).unwrap();

    assert_eq!(
        proof.puzzle(),
        [
            6, 1, 4, /**/ 3, 8, 9, /**/ 2, 5, 0, //
            5, 0, 0, /**/ 6, 0, 0, /**/ 4, 0, 0, //
            0, 0, 0, /**/ 5, 0, 0, /**/ 0, 6, 3, //
            /***********************************/
            1, 3, 0, /**/ 8, 0, 0, /**/ 6, 7, 0, //
            2, 0, 8, /**/ 1, 6, 0, /**/ 9, 0, 4, //
            0, 4, 0, /**/ 2, 0, 3, /**/ 5, 0, 1, //
            /***********************************/
            0, 2, 0, /**/ 9, 0, 0, /**/ 3, 0, 0, //
            4, 0, 5, /**/ 7, 0, 6, /**/ 1, 0, 0, //
            3, 6, 0, /**/ 4, 2, 0, /**/ 7, 0, 5, //
        ]
    );

    println!(
        "proof generated in {} seconds",
        prove_start_time.elapsed().as_secs()
    );

    println!("receipt journal output:");
    println!("  hash:               {}", hex::encode(proof.hash()));
    println!(
        "  encrypted solution: {}",
        hex::encode(&proof.journal()[32 + 12 + 81..])
    );

    println!("verifying sha256-sudoku proof...");
    proof.verify().unwrap();
    println!("ok!");

    println!("proof is valid; preimage of {}", hex::encode(proof.hash()));
    println!(
        "...is also the decryption key to a solution for the sudoku puzzle:\n{:?}",
        proof.puzzle()
    );

    let proof_serialized = borsh::to_vec(&proof).unwrap();
    println!("Receipt is {} bytes long", proof_serialized.len());

    let solution = proof.decrypt_solution(preimage).unwrap();
    assert!(is_valid_sudoku_solution(&solution));
}
