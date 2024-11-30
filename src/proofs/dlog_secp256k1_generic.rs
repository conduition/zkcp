use std::io;
use std::marker::PhantomData;

use anyhow::bail;
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::sha::rust_crypto::{Digest as _, Sha256};
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{ExecutorEnv, LocalProver, Prover, ProverOpts, Receipt};
use secp::{MaybeScalar, Point, Scalar, G};

use crate::program::Program;

fn compute_challenge(id: [u32; 8], public_nonce: Point, public_key: Point) -> MaybeScalar {
    MaybeScalar::reduce_from(
        &Sha256::new()
            .chain_update(public_nonce.serialize())
            .chain_update(public_key.serialize())
            .chain_update(Digest::from(id))
            .finalize()
            .into(),
    )
}

/// A generic proof that a secp256k1 discrete log (secret key) exhibits some custom properties.
///
/// Generally this type is used to instantiate more application-specific proofs.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Secp256k1DlogProof<P: Program> {
    pub public_key: Point,
    pub public_nonce: Point,
    pub receipt: Receipt,

    phantom: PhantomData<P>,
}

impl<P: Program> BorshSerialize for Secp256k1DlogProof<P> {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        BorshSerialize::serialize(&self.public_key.serialize(), writer)?;
        BorshSerialize::serialize(&self.public_nonce.serialize(), writer)?;
        BorshSerialize::serialize(&self.receipt, writer)?;
        Ok(())
    }
}

impl<P: Program> BorshDeserialize for Secp256k1DlogProof<P> {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let public_key_bytes: [u8; 33] = BorshDeserialize::deserialize_reader(reader)?;
        let public_key = Point::try_from(public_key_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let public_nonce_bytes: [u8; 33] = BorshDeserialize::deserialize_reader(reader)?;
        let public_nonce = Point::try_from(public_nonce_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let receipt: Receipt = BorshDeserialize::deserialize_reader(reader)?;

        let proof = Secp256k1DlogProof {
            public_key,
            public_nonce,
            receipt,
            phantom: PhantomData,
        };
        Ok(proof)
    }
}

impl<P: Program> Secp256k1DlogProof<P> {
    /// Create a zk-STARK proof that a secp256k1 secret key exhibits some arbitrary properties
    /// determined by the RISCV program `P`.
    pub fn prove_custom(secret_key: Scalar, aux_input: &[u8]) -> Result<Self, anyhow::Error> {
        if aux_input.len() != P::aux_input_len() {
            bail!(
                "expected aux_input to prover of len {}; got {}",
                P::aux_input_len(),
                aux_input.len()
            );
        }

        let secret_key_bytes = secret_key.serialize();

        let secret_nonce = Scalar::reduce_from(
            &Sha256::new()
                .chain_update(Digest::from(P::id()))
                .chain_update(secret_key_bytes)
                .chain_update(aux_input)
                .chain_update(b"secp256k1_nonce")
                .finalize()
                .into(),
        );
        let secret_nonce_bytes = secret_nonce.serialize();

        let public_key = secret_key * G;
        let public_nonce = secret_nonce * G;

        let challenge = compute_challenge(P::id(), public_nonce, public_key);

        let env = ExecutorEnv::builder()
            .write_slice(&secret_key_bytes)
            .write_slice(&secret_nonce_bytes)
            .write_slice(&challenge.serialize())
            .write_slice(aux_input)
            .build()?;

        // This call takes a while.
        let prove_info =
            LocalProver::new("local").prove_with_opts(env, P::elf(), &ProverOpts::fast())?;

        let proof = Secp256k1DlogProof {
            receipt: prove_info.receipt,
            public_key,
            public_nonce,
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
    /// - Schnorr challenge: 32 bytes
    /// - Schnorr sig:       32 bytes
    /// - Appendix:          P::appendix_len() bytes
    fn check_journal_length(&self) -> Result<(), anyhow::Error> {
        if self.journal().len() != 64 + P::appendix_len() {
            bail!(
                "journal is incorrect length {}; expected {}",
                self.journal().len(),
                64 + P::appendix_len()
            );
        }
        Ok(())
    }

    /// Parse and return the challenge scalar used to create the Schnorr signature,
    /// from the guest output journal.
    pub fn challenge(&self) -> Result<MaybeScalar, anyhow::Error> {
        Ok(MaybeScalar::try_from(&self.journal()[0..32])?)
    }

    /// Parse and return the Schnorr signature scalar `s` from the
    /// guest output journal.
    pub fn signature(&self) -> Result<MaybeScalar, anyhow::Error> {
        Ok(MaybeScalar::try_from(&self.journal()[32..64])?)
    }

    /// Return a reference to the _appendix,_ which refers to any journal output
    /// from the guest _after_ the first 64 bytes needed for the secp256k1
    /// signature proof.
    ///
    /// The appendix is used by application-specific proofs to append additional public
    /// output data to the zk-STARK proof.
    pub fn appendix(&self) -> &[u8] {
        &self.journal()[64..]
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

    /// Verify the Schnorr signature, and then the zk-STARK proof of computational integrity.
    /// Returns `Ok` if the program `P` was executed correctly AND the secp256k1 Schnorr
    /// signature is valid.
    pub fn verify(&self) -> Result<(), anyhow::Error> {
        let challenge = compute_challenge(P::id(), self.public_nonce, self.public_key);
        if challenge != self.challenge()? {
            bail!("journal challenge does not match computed challenge");
        }

        let s = self.signature()?;
        if s * G != self.public_nonce + self.public_key * challenge {
            bail!("schnorr signature is invalid");
        }

        self.receipt.verify(P::id())?;

        Ok(())
    }
}
