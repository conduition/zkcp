use common::sudoku;

use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use risc0_zkvm::guest::env;
use risc0_zkvm::guest::sha;

use risc0_zkvm::guest::sha::Sha256;

fn main() {
    let mut preimage = [0u8; 32];
    let mut chacha_nonce = [0u8; 12];
    let mut sudoku_puzzle_mask = [0u8; 81];
    let mut sudoku_solution = [0u8; 81];

    env::read_slice(&mut preimage);
    env::read_slice(&mut chacha_nonce);
    env::read_slice(&mut sudoku_puzzle_mask);
    env::read_slice(&mut sudoku_solution);

    let digest = sha::Impl::hash_bytes(&preimage);

    assert!(sudoku::is_valid_sudoku_solution(&sudoku_solution));
    let sudoku_puzzle_bytes = sudoku::mask_sudoku_solution(&sudoku_solution, &sudoku_puzzle_mask);

    let mut compact_solution = sudoku::compress_board(&sudoku_solution);
    let mut cipher = ChaCha20::new(&preimage.into(), &chacha_nonce.into());
    cipher.apply_keystream(&mut compact_solution);

    env::commit_slice(digest.as_bytes());
    env::commit_slice(&chacha_nonce);
    env::commit_slice(&sudoku_puzzle_bytes);
    env::commit_slice(&compact_solution);
}
