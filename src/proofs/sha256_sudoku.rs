// These constants represent the RISC-V ELF and the image ID generated by risc0-build.
// The ELF is used for proving and the ID is used for verification.
use crate::methods::{SHA256_SUDOKU_ELF, SHA256_SUDOKU_ID};

use anyhow::bail;
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use risc0_zkvm::sha::rust_crypto::{Digest as _, Sha256};
use risc0_zkvm::sha::Digest;

use super::sha256_generic::Sha256Proof;
use crate::program::Program;
use common::sudoku::{self, CompactSudokuBoard, SudokuBoard};

/// This program takes in the following secret inputs:
///
/// - `preimage` (32 bytes)
/// - `chacha_nonce` (12 bytes)
/// - `mask` (81 bytes)
/// - `sudoku_solution` (81 bytes)
///
/// It asserts that `sudoku_solution` is a valid sudoku board, and then
/// produces the following public outputs:
///
/// - `hash = sha256(preimage)` (32 bytes)
/// - `chacha_nonce` (12 bytes)
/// - `sudoku_puzzle = mask_sudoku_solution(sudoku_solution, mask)` (81 bytes)
/// - `compact_encrypted_solution = chacha_cipher(preimage).encrypt(compress_board(sudoku_solution))` (36 bytes)
///
/// This program is used to instantiate [`Sha256SudokuProof`].
#[derive(Copy, Debug, Clone, Eq, PartialEq, Hash)]
pub struct Sha256SudokuProgram;

impl Program for Sha256SudokuProgram {
    fn id() -> [u32; 8] {
        SHA256_SUDOKU_ID
    }
    fn elf() -> &'static [u8] {
        SHA256_SUDOKU_ELF
    }

    /// chacha nonce (12 bytes)
    /// mask         (81 bytes)
    /// solution     (81 bytes)
    fn aux_input_len() -> usize {
        12 + 81 + 81
    }

    /// Journal:
    /// - Hash: 32 bytes
    /// - chacha nonce: 12 bytes
    /// - puzzle: 81 bytes
    /// - encrypted compact solution: 36 bytes
    fn appendix_len() -> usize {
        12 + 81 + 36 // sha256 hash of secret key
    }
}

/// A proof that the preimage of a SHA256 hash is also the decryption key to a valid
/// sudoku solution.
pub type Sha256SudokuProof = Sha256Proof<Sha256SudokuProgram>;

impl Sha256SudokuProof {
    pub fn new(
        preimage: [u8; 32],
        solution: &SudokuBoard,
        puzzle_mask: &SudokuBoard,
    ) -> Result<Self, anyhow::Error> {
        let chacha_nonce_hash = Sha256::new()
            .chain_update(Digest::from(SHA256_SUDOKU_ID))
            .chain_update(preimage)
            .chain_update(solution)
            .chain_update(puzzle_mask)
            .chain_update(b"chacha_nonce")
            .finalize();

        let mut aux_input = [0u8; 12 + 81 + 81];
        aux_input[..12].copy_from_slice(&chacha_nonce_hash[..12]);
        aux_input[12..][..81].copy_from_slice(puzzle_mask.as_ref());
        aux_input[12..][81..].copy_from_slice(solution.as_ref());

        Sha256SudokuProof::prove_custom(preimage, &aux_input)
    }

    pub fn puzzle(&self) -> SudokuBoard {
        SudokuBoard::try_from(&self.journal()[32..][12..][..81])
            .expect("journal length already checked in constructor")
    }

    pub fn decrypt_solution(&self, preimage: [u8; 32]) -> Result<SudokuBoard, anyhow::Error> {
        let hash: [u8; 32] = Sha256::new().chain_update(preimage).finalize().into();
        if hash != self.hash() {
            bail!("preimage does not match hash in proof journal");
        }

        let chacha_nonce =
            <[u8; 12]>::try_from(&self.journal()[32..][..12]).expect("always correct length");
        let mut compact_solution = CompactSudokuBoard::try_from(&self.journal()[32..][12..][81..])
            .expect("always correct length");

        let mut cipher = ChaCha20::new(&preimage.into(), &chacha_nonce.into());
        cipher.apply_keystream(&mut compact_solution);
        let solution = sudoku::decompress_board(&compact_solution)?;

        if !sudoku::is_valid_sudoku_solution(&solution) {
            bail!(
                "decrypted solution is not valid. This should never happen; \
                   did you forget to verify the proof?"
            );
        } else if !sudoku::solves_sudoku_puzzle(&solution, &self.puzzle()) {
            bail!(
                "decrypted solution is for the wrong puzzle. This should never happen; \
                   did you forget to verify the proof?"
            );
        }
        Ok(solution)
    }
}
