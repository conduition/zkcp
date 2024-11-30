use std::io;
use std::marker::PhantomData;

use anyhow::bail;
use risc0_zkvm::{ExecutorEnv, LocalProver, Prover, ProverOpts, Receipt};

use crate::program::Program;

/// A generic proof that a SHA256 preimage exhibits some custom properties.
///
/// Generally this type is used to instantiate more application-specific proofs.
#[derive(
    Clone,
    Debug,
    Eq,
    PartialEq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
pub struct Sha256Proof<P: Program> {
    pub receipt: Receipt,
    phantom: PhantomData<P>,
}

impl<P: Program> Sha256Proof<P> {
    /// Create a zk-STARK proof that a SHA256 preimage exhibits some arbitrary properties
    /// determined by the RISCV program `P`.
    pub fn prove_custom(preimage: [u8; 32], aux_input: &[u8]) -> Result<Self, anyhow::Error> {
        let env = ExecutorEnv::builder()
            .write_slice(&preimage)
            .write_slice(aux_input)
            .build()?;

        // This call takes a while.
        let prove_info =
            LocalProver::new("local").prove_with_opts(env, P::elf(), &ProverOpts::fast())?;

        let proof = Sha256Proof {
            receipt: prove_info.receipt,
            phantom: PhantomData,
        };

        proof.check_journal_length()?;

        Ok(proof)
    }

    /// Return a reference the bytes of the RISC0 guest program output (AKA the journal).
    pub fn journal(&self) -> &[u8] {
        &self.receipt.journal.bytes
    }

    /// Journal:
    /// - hash:     32 bytes
    /// - Appendix: P::appendix_len() bytes
    fn check_journal_length(&self) -> Result<(), anyhow::Error> {
        if self.journal().len() != 32 + P::appendix_len() {
            bail!(
                "journal is incorrect length {}; expected {}",
                self.journal().len(),
                32 + P::appendix_len()
            );
        }
        Ok(())
    }

    /// Return the SHA256 hash the proof is about. The preimage of this hash is a
    /// secret input to the program `P`.
    pub fn hash(&self) -> [u8; 32] {
        <[u8; 32]>::try_from(&self.journal()[..32]).unwrap()
    }

    /// Serialize the proof to a compact vector of bytes. "Compact" is a relative term though,
    /// as zk-STARK proofs will generally be several hundred kilobytes.
    ///
    /// We use [`borsh`](https://github.com/near/borsh-rs) for binary serialization.
    pub fn to_vec(&self) -> io::Result<Vec<u8>> {
        borsh::to_vec(self)
    }

    /// Deserialize a proof from a vector of bytes.
    ///
    /// We use [`borsh`](https://github.com/near/borsh-rs) for binary serialization.
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        borsh::from_slice(bytes)
    }

    /// Verify the zk-STARK proof of computational integrity. Returns `Ok` if the program `P`
    /// was executed correctly.
    pub fn verify(&self) -> Result<(), anyhow::Error> {
        self.receipt.verify(P::id())?;
        Ok(())
    }
}
