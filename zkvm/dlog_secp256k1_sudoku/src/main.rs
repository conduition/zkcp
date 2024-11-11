use common::{secp256k1, sudoku};

use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use risc0_zkvm::guest::env;

fn main() {
    let mut secret_key = [0u8; 32];
    let mut secret_nonce = [0u8; 32];
    let mut challenge = [0u8; 32];
    let mut chacha_nonce = [0u8; 12];
    let mut sudoku_puzzle_mask = [0u8; 81];
    let mut sudoku_solution = [0u8; 81];

    env::read_slice(&mut secret_key);
    env::read_slice(&mut secret_nonce);
    env::read_slice(&mut challenge);
    env::read_slice(&mut chacha_nonce);
    env::read_slice(&mut sudoku_puzzle_mask);
    env::read_slice(&mut sudoku_solution);

    let sig = secp256k1::schnorr_signature(secret_key, secret_nonce, challenge);

    assert!(sudoku::is_valid_sudoku_solution(&sudoku_solution));
    let sudoku_puzzle_bytes = sudoku::mask_sudoku_solution(&sudoku_solution, &sudoku_puzzle_mask);

    let mut compact_solution = sudoku::compress_board(&sudoku_solution);
    let mut cipher = ChaCha20::new(&secret_key.into(), &chacha_nonce.into());
    cipher.apply_keystream(&mut compact_solution);

    env::commit_slice(&challenge);
    env::commit_slice(&sig);
    env::commit_slice(&chacha_nonce);
    env::commit_slice(&sudoku_puzzle_bytes);
    env::commit_slice(&compact_solution); // encrypted with chacha20
}
